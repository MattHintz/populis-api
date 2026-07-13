"""Solslot API — FastAPI application.

Endpoints:
  GET  /health
  GET  /protocol
  POST /auth/challenge
  POST /vault/register/evm
  POST /vault/register/chia
  GET  /vault/{launcher_id}
  GET  /zkpassport/validator

Removed endpoints:
  GET  /vault/by-evm/{address}  --  POP-CANON-014: removed in this brick.
      The endpoint enumerated the EVM ↔ vault_launcher_id binding and
      its on-chain state for any caller knowing the EVM address, turning
      the registry into a global doxxing oracle for member identities
      and amplifying unauthenticated coinset.org queries.  The portal's
      ``findVaultByEvmAddress`` consumer was already removed in Phase
      9-Hermes-D (vault discovery moved client-side via
      ``VaultDiscoveryService`` / CHIP-22 hint scan), so removal is
      consumer-safe.  ``VaultRegistry.get_by_evm`` remains as an
      internal helper used by ``register_evm_vault`` to reject
      duplicate registrations — it is no longer exposed over HTTP.
"""
from __future__ import annotations

import base64
import logging
import time
from contextlib import asynccontextmanager
from typing import Annotated, Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator

from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32

from .admin import router as admin_router
from .admin_bootstrap import router as admin_bootstrap_router
from .admin_auth import (
    router as admin_auth_router,
    validate_admin_config_at_startup,
)
try:
    from .admin_roster_update import router as admin_roster_update_router
except ModuleNotFoundError as e:
    if e.name != "solslot_api.admin_roster_update":
        raise
    admin_roster_update_router = None
from .mint_endpoints import router as mint_endpoints_router
from .protocol_artifacts import router as protocol_artifacts_router
from .zkpassport_validator import router as zkpassport_validator_router
from .zkpassport_relay import router as zkpassport_relay_router
from .zkpassport_enrollments import router as zkpassport_enrollments_router
from .challenges import (
    ChallengeStore,
    ChallengeStoreFullError,
    RateLimitedError,
    get_store as get_challenge_store,
)
from .coinset_client import CoinsetClient
from .config import (
    Settings,
    get_settings,
    validate_runtime_environment_namespace,
    validate_secret_env_file_permissions,
    validate_server_hardening_at_startup,
)
from .credential_auth import require_alpha_writes
from .deployment_manifest import load_deployment_manifest
from .protocol_config import build_snapshot as build_protocol_config_snapshot
from .release_metadata import ReleaseMetadata, load_release_metadata
from .singletons import build_singletons_snapshot
from .cors import cors_middleware_options
from .evm_auth import (
    eip712_domain,
    normalize_evm_address,
    recover_evm_signer,
    registration_bls_message,
    registration_bls_signing_digest,
    registration_typed_data,
    VAULT_SPEND_TYPEHASH_STRING,
)
from .faucet import Faucet
from .state import VaultRecord, VaultRegistry, get_registry
from .server_hardening import ServerHardeningMiddleware, documentation_urls
from .vault_launcher import AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1, build_and_sign_launch
from .vault_version_registry import (
    VaultVersionRegistrySnapshot,
    build_vault_version_registry_snapshot,
)
from solslot_puzzles.vault_driver import (
    VAULT_INNER_MOD,
    puzzle_for_p2_vault,
)

logger = logging.getLogger(__name__)

# Precompute at import time to sidestep pyo3's "LazyNode is unsendable" panic
# when FastAPI dispatches sync endpoints via anyio's thread pool.
VAULT_INNER_MOD_HASH_HEX: str = "0x" + VAULT_INNER_MOD.get_tree_hash().hex()

# Warm up chia puzzle templates on the import thread so their internal
# `chia_protocol::lazy_node::LazyNode` is bound to the main thread.
# Without this, when Starlette's lifespan runs on the anyio worker thread
# and the faucet calls `puzzle_for_pk(wallet_pk).get_tree_hash()`, the
# LazyNode (created lazily during the *first* access on whatever thread)
# panics with "LazyNode is unsendable, but sent to another thread".
#
# The fix is to force-touch each puzzle template here, on the import
# thread, so the LazyNode is materialised once and the resulting bytes
# are cached on the Program — making subsequent cross-thread access
# safe.  This mirrors the precomputation above for VAULT_INNER_MOD and
# closes the four chia_rs LazyNode errors in tests/test_smoke.py.
def _warm_chia_puzzle_templates() -> None:
    # p2_delegated_puzzle_or_hidden_puzzle.MOD — used by Faucet to
    # derive the wallet puzzle hash via puzzle_for_pk.
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD as P2_MOD
    bytes(P2_MOD)               # force serialize → caches Program._bytes
    P2_MOD.get_tree_hash()      # force tree-hash compute too

    # Eagerly import chia.wallet.trading.offer (and therefore
    # chia.wallet.util.puzzle_compression) here, on the main thread.
    # That module's body contains a top-level
    # ``bytes(standard_puzzle.MOD) + bytes(LEGACY_CAT_MOD)``
    # which walks two more LazyNodes; without this warm-up those walks
    # would happen on the first request thread (the /protocol endpoint
    # lazy-imports protocol_deployment, which transitively pulls in
    # chia.wallet.trading.offer) and panic with the same
    # "LazyNode is unsendable" assertion failure.
    import chia.wallet.trading.offer  # noqa: F401 — import for side-effect
    import chia.wallet.util.puzzle_compression  # noqa: F401

    # solslot_puzzles A.1, A.2, A.3, A.4, A.5 inner mods — same threading
    # hazard.  Touching them here on the import thread caches each
    # mod's serialised bytes + tree hash so cross-thread access in
    # request handlers is safe.  Without this, /protocol's call to
    # build_singletons_snapshot or build_vault_version_registry_snapshot
    # panics on the second hit.
    from solslot_puzzles.admin_authority_v2_driver import admin_authority_v2_inner_mod
    from solslot_puzzles.mint_proposal_v2_driver import mint_proposal_inner_v2_mod
    from solslot_puzzles.property_registry_driver import (
        property_registry_inner_mod,
    )
    from solslot_puzzles.protocol_config_driver import protocol_config_inner_mod
    from solslot_puzzles.vault_version_registry_driver import (
        vault_version_registry_inner_mod,
    )
    for mod in (
        admin_authority_v2_inner_mod(),
        mint_proposal_inner_v2_mod(),
        property_registry_inner_mod(),
        protocol_config_inner_mod(),
        vault_version_registry_inner_mod(),
    ):
        bytes(mod)
        mod.get_tree_hash()

    # Phase 2.5: Eip712Member puzzle is loaded by admin_records.py (when
    # leaf_hash is omitted from the JSON) and by the
    # /admin/auth/eip712/compute_leaf_hash endpoint.  Warm it on the
    # import thread for the same LazyNode-threading reason as above.
    # ``_eip712_member_mod_hash()`` populates the module-level bytes32
    # cache so per-request curry computations can use pure-bytes math
    # without ever touching a LazyNode again.
    from solslot_puzzles.eip712_helpers import (
        _eip712_member_mod_hash,
        _eip712_member_puzzle,
    )
    _eip712_mod = _eip712_member_puzzle()
    bytes(_eip712_mod)
    _eip712_mod.get_tree_hash()
    _eip712_member_mod_hash()  # populate the bytes32 cache


_warm_chia_puzzle_templates()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


# ─── App lifecycle ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_runtime_environment_namespace()
    validate_secret_env_file_permissions()
    settings = get_settings()
    validate_server_hardening_at_startup(settings)

    # POP-CANON-016: fail fast at boot if the admin desk is enabled but
    # SOLSLOT_ADMIN_JWT_SECRET is unset.  This complements the runtime
    # guard inside ``get_jwt_secret``; with both, an operator gets the
    # clear error during deployment rather than at the first admin
    # request hours later.
    validate_admin_config_at_startup(settings)

    app.state.settings = settings
    app.state.coinset = CoinsetClient(settings.coinset_base_url)

    if settings.faucet_master_sk_hex:
        app.state.faucet = Faucet.from_master_private_key_hex(
            settings.faucet_master_sk_hex, settings.network
        )
    elif settings.faucet_seed_hex:
        app.state.faucet = Faucet.from_seed_hex(settings.faucet_seed_hex, settings.network)
    elif settings.faucet_mnemonic:
        app.state.faucet = Faucet.from_mnemonic(settings.faucet_mnemonic, settings.network)
    else:
        app.state.faucet = None
        logger.warning(
            "Faucet not configured — vault registration endpoints will return 503. "
            "Set SOLSLOT_FAUCET_MASTER_SK_HEX, SOLSLOT_FAUCET_SEED_HEX, or SOLSLOT_FAUCET_MNEMONIC."
        )

    if app.state.faucet is not None:
        logger.info(
            "Faucet ready: %s  (puzhash %s)",
            app.state.faucet.bech32_address(),
            app.state.faucet.address_hex,
        )

    # POP-CANON-008: faucet UTXO consolidation worker.  Opt-in via
    # SOLSLOT_FAUCET_CONSOLIDATION_ENABLED=true.  Started here so the
    # task is owned by the FastAPI event loop and properly cancelled on
    # shutdown.
    app.state.faucet_worker = None
    if app.state.faucet is not None and settings.faucet_consolidation_enabled:
        from .faucet_worker import (
            FaucetConsolidationConfig,
            FaucetConsolidationWorker,
        )

        worker_config = FaucetConsolidationConfig(
            enabled=True,
            threshold=settings.faucet_consolidation_threshold,
            interval_seconds=settings.faucet_consolidation_interval_seconds,
            fee=settings.faucet_consolidation_fee,
            max_inputs_per_run=settings.faucet_consolidation_max_inputs,
        )
        worker = FaucetConsolidationWorker(
            faucet=app.state.faucet,
            coinset=app.state.coinset,
            config=worker_config,
        )
        await worker.start()
        app.state.faucet_worker = worker

    try:
        yield
    finally:
        if app.state.faucet_worker is not None:
            await app.state.faucet_worker.stop()
        await app.state.coinset.close()


_server_settings = get_settings()

app = FastAPI(
    title="Solslot API",
    version="0.1.0",
    description="Solslot Protocol members-portal API (testnet)",
    lifespan=lifespan,
    **documentation_urls(_server_settings),
)


# Localhost matching is available only in development/test. Staging and
# production accept exact HTTPS origins from SOLSLOT_CORS_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    **cors_middleware_options(_server_settings),
)
app.add_middleware(
    ServerHardeningMiddleware,
    settings=_server_settings,
)

# Run-once ceremony routes use the bootstrap operator token.
app.include_router(admin_router)
app.include_router(admin_bootstrap_router)

# Post-genesis admin desk: wallet-signed JWT auth backed only by verified
# records committed by the current admin-authority singleton.
app.include_router(admin_auth_router)
if admin_roster_update_router is not None:
    app.include_router(admin_roster_update_router)
app.include_router(mint_endpoints_router)
app.include_router(protocol_artifacts_router)

# Read-only zkPassport validator public-key metadata.
app.include_router(zkpassport_validator_router)

# zkPassport vault bridge enrollment index (public receipt material only).
app.include_router(zkpassport_enrollments_router)

# zkPassport gasless relayer (ERC-2771 meta-tx; 503 when relayer key is unset).
app.include_router(zkpassport_relay_router)


# ─── Dependency injectors ───────────────────────────────────────────────

async def get_coinset() -> CoinsetClient:
    # async to keep the dependency on the event loop thread (FastAPI dispatches
    # sync deps to a worker pool, which would touch chia_rs LazyNodes that were
    # bound to the lifespan thread → pyo3 panic).
    return app.state.coinset  # type: ignore[attr-defined]


async def get_faucet() -> Faucet:
    f: Optional[Faucet] = app.state.faucet  # type: ignore[attr-defined]
    if f is None:
        raise HTTPException(
            status_code=503,
            detail="Faucet is not configured on this server — vault registration is disabled. "
            "Set SOLSLOT_FAUCET_SEED_HEX or SOLSLOT_FAUCET_MNEMONIC.",
        )
    return f


# ─── Schemas ────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    ok: bool
    service: str = "Solslot API"
    protocol_version: str = "solslot-v2"
    network: str
    peak_height: Optional[int]
    api_commit: Optional[str] = None
    protocol_commit: Optional[str] = None


class ReleaseResponse(BaseModel):
    available: bool
    release: Optional[ReleaseMetadata] = None


class ProtocolInfo(BaseModel):
    network: str
    pool_launcher_id: Optional[str]
    governance_launcher_id: Optional[str]
    vault_inner_mod_hash: str
    eip712_domain: dict[str, Any]
    eip712_typehash_string: str
    faucet_address: Optional[str]
    faucet_balance_mojos: Optional[int]
    deployed: bool = False
    deployment_manifest: Optional[dict[str, Any]] = None
    # ── A.3 protocol-config singleton fields ──────────────────────────
    # Deterministic hash of (pool_launcher_id, governance_launcher_id,
    # network, protocol_config_version).  When the operator has launched
    # the on-chain singleton, the CREATE_PUZZLE_ANNOUNCEMENT it emits on
    # every update spend carries this exact same hash — frontends can
    # therefore independently verify the operator's published config
    # against on-chain state by walking the singleton lineage on
    # coinset.org and comparing.  Returned as ``None`` until both pool +
    # governance launchers are configured (without them, the singleton
    # has nothing meaningful to publish).  See SECURITY.md §A.3.
    protocol_config_hash: Optional[str] = None
    # Launcher coin id of the on-chain protocol-config singleton, when
    # the operator has set ``SOLSLOT_PROTOCOL_CONFIG_LAUNCHER_ID``.
    # Until Phase 1.5 lands the singleton-lineage indexer, this field
    # is informational: clients can use it to locate the singleton on
    # coinset.org and verify the published content_hash themselves.
    protocol_config_launcher_id: Optional[str] = None
    # Monotonically increasing version stamped into the singleton's
    # curried state.  Bumped by the operator on every config update.
    protocol_config_version: int = 1
    # ── A.4 property-registry singleton fields ────────────────────────
    # Launcher coin id of the on-chain property-registry singleton, when
    # the operator has set ``SOLSLOT_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID``.
    # Off-chain consumers walk this singleton's lineage on coinset.org
    # to discover registered property ids (each registration spend
    # emits a CREATE_PUZZLE_ANNOUNCEMENT carrying the canonical id).
    # Returned as ``None`` until the operator opts in.  See SECURITY.md §A.4.
    property_registry_launcher_id: Optional[str] = None
    # Tree hash of the uncurried ``property_registry_inner.clsp`` mod
    # — clients use this to verify they're reading the canonical
    # puzzle on-chain (rather than a malicious lookalike).
    property_registry_mod_hash: Optional[str] = None
    # ── A.1 mint-proposal singleton fields ────────────────────────────
    # Tree hash of the uncurried ``mint_proposal_inner.clsp`` mod;
    # exposed so clients can identify mint-proposal singletons on
    # coinset.org by uncurrying their inner reveal and comparing this
    # value.  Each individual proposal has its own launcher_id (not
    # exposed here — that's per-proposal, not protocol-level).
    # See SECURITY.md §A.1.
    mint_proposal_mod_hash: Optional[str] = None
    # ── A.5 vault-version registry singleton fields ───────────────────
    # Launcher coin id of the on-chain vault-version registry singleton,
    # when the operator has set ``SOLSLOT_VAULT_VERSION_REGISTRY_LAUNCHER_ID``.
    # Off-chain consumers walk this singleton's lineage on coinset.org to
    # discover the current canonical vault descriptor (vault inner mod hash,
    # canonical params hash, version).  Returned as ``None`` until the
    # registry is deployed.  See SECURITY.md §A.5.
    vault_version_registry_launcher_id: Optional[str] = None
    # Tree hash of the uncurried ``vault_version_registry_inner.clsp`` mod;
    # clients use this to verify they found the canonical registry puzzle.
    vault_version_registry_mod_hash: Optional[str] = None
    # Monotonic vault descriptor version.  Default 1 = initial deployment.
    vault_version: int = 1
    # ``sha256tree`` of the protocol-wide vault params (pool singleton mod,
    # pool launcher id, pool launcher puzzle hash, zkPassport bridge policy
    # hash).  ``None`` when pool launcher is not configured.
    vault_canonical_params_hash: Optional[str] = None
    # ``sha256tree`` of ``[vault_inner_mod_hash, canonical_params_hash, vault_version]``.
    # The on-chain registry publishes this exact value via its announcement.
    vault_version_registry_content_hash: Optional[str] = None


class ChallengeRequest(BaseModel):
    address: str = Field(
        ..., min_length=1, max_length=1024, description="EVM address or Chia BLS pubkey hex"
    )
    auth_type: str = Field(..., pattern="^(evm|chia_bls|passkey)$")

    @model_validator(mode="after")
    def validate_address_for_auth_type(self):
        if self.auth_type == "evm":
            self.address = normalize_evm_address(self.address, "address")
        elif self.auth_type == "chia_bls":
            raw = self.address[2:] if self.address.startswith("0x") else self.address
            try:
                pk_bytes = bytes.fromhex(raw)
            except ValueError as e:
                raise ValueError("BLS pubkey must be hex") from e
            if len(pk_bytes) != 48:
                raise ValueError("BLS pubkey must be 48 bytes")
        return self


class ChallengeResponse(BaseModel):
    nonce: str
    expires_at: float
    typed_data: Optional[dict[str, Any]] = None
    message_hex: Optional[str] = None


class RegisterEvmVaultRequest(BaseModel):
    address: str
    nonce: str
    signature: str


class RegisterChiaVaultRequest(BaseModel):
    bls_pubkey: str
    nonce: str
    signature: str


class VaultCreationResponse(BaseModel):
    vault_launcher_id: str
    vault_full_puzhash: str
    p2_vault_puzhash: str
    spend_bundle_id: str
    pushed_at: float
    auth_type: str
    # POP-CANON-004 fix: surface the actual coinset.org acceptance status
    # to the frontend.  When False, the spend was NOT accepted by the
    # mempool; the frontend should show a hard error and avoid persisting
    # the launcher id.  ``push_status`` carries the raw error/status string.
    accepted: bool = True
    push_status: Optional[str] = None


class VaultStateResponse(BaseModel):
    vault_launcher_id: str
    vault_full_puzhash: str
    p2_vault_puzhash: str
    auth_type: str
    owner_address: Optional[str]
    owner_pubkey: str
    confirmed: bool
    confirmed_block_index: Optional[int]
    current_coin_id: Optional[str]
    balance: dict[str, Any]


# ─── Endpoints ──────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health(
    settings: Annotated[Settings, Depends(get_settings)],
    coinset: Annotated[CoinsetClient, Depends(get_coinset)],
) -> HealthResponse:
    release = load_release_metadata(settings.release_metadata_path)
    try:
        state = await coinset.get_blockchain_state()
        peak = state.get("blockchain_state", {}).get("peak") or {}
        return HealthResponse(
            ok=True,
            network=settings.network,
            peak_height=peak.get("height"),
            api_commit=release.apiCommit if release else None,
            protocol_commit=release.protocolCommit if release else None,
        )
    except Exception as e:
        logger.warning("coinset unreachable: %s", e)
        return HealthResponse(
            ok=False,
            network=settings.network,
            peak_height=None,
            api_commit=release.apiCommit if release else None,
            protocol_commit=release.protocolCommit if release else None,
        )


@app.get("/release", response_model=ReleaseResponse)
async def release(
    settings: Annotated[Settings, Depends(get_settings)],
) -> ReleaseResponse:
    metadata = load_release_metadata(settings.release_metadata_path)
    return ReleaseResponse(available=metadata is not None, release=metadata)


@app.get("/protocol", response_model=ProtocolInfo)
async def protocol(
    settings: Annotated[Settings, Depends(get_settings)],
    coinset: Annotated[CoinsetClient, Depends(get_coinset)],
) -> ProtocolInfo:
    faucet: Optional[Faucet] = app.state.faucet  # type: ignore[attr-defined]
    faucet_balance = None
    if faucet is not None:
        try:
            coins = await coinset.get_coin_records_by_puzzle_hash(
                "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
            )
            faucet_balance = sum(
                int((c.get("coin") or c)["amount"])
                for c in coins
                if c.get("spent_block_index") in (0, None)
            )
        except Exception as e:
            logger.warning("faucet balance lookup failed: %s", e)
    # Auto-discover the deployment manifest if present (dict-only, no CLVM
    # Program instantiation on the request thread).
    deployed = False
    deployment_manifest: Optional[dict[str, Any]] = None
    pool_launcher_from_manifest: Optional[str] = settings.pool_launcher_id
    gov_launcher_from_manifest: Optional[str] = settings.governance_launcher_id
    try:
        from pathlib import Path

        manifest_path = Path(settings.deployment_manifest_path)
        if manifest_path.exists():
            deployment_manifest = load_deployment_manifest(manifest_path)
            deployed = True
            pool_launcher_from_manifest = deployment_manifest["pool_launcher_id"]
            gov_launcher_from_manifest = deployment_manifest["tracker_launcher_id"]
    except Exception as e:
        logger.warning("Failed to read deployment manifest: %s", e)

    # POP-CANON-A3: compute the protocol_config_hash from whichever
    # source (manifest > env) the API is currently trusting.  Frontends
    # use this hash when binding the EIP-712 envelope; auditors can
    # recompute it from on-chain singleton state and refuse to sign
    # when the two diverge.
    protocol_snapshot = build_protocol_config_snapshot(
        settings,
        pool_launcher_id_hex=pool_launcher_from_manifest,
        governance_launcher_id_hex=gov_launcher_from_manifest,
    )

    # POP-CANON-A1 + A.4: surface the on-chain mint-proposal +
    # property-registry singleton handles.  Mod-hashes are static
    # across the deployment; launcher_id is operator-configurable
    # (None until the property-registry is launched on-chain).
    singletons_snapshot = build_singletons_snapshot(settings)

    # POP-CANON-A.5: surface the on-chain vault-version registry singleton
    # descriptor.  Mod-hash and current vault code are static across the
    # deployment; launcher_id, canonical params hash and content hash are
    # computable only when the pool launcher is configured (the params hash
    # binds the pool launcher id).
    vault_registry_snapshot = build_vault_version_registry_snapshot(
        settings,
        pool_launcher_id_hex=pool_launcher_from_manifest,
    )

    return ProtocolInfo(
        network=settings.network,
        pool_launcher_id=pool_launcher_from_manifest,
        governance_launcher_id=gov_launcher_from_manifest,
        vault_inner_mod_hash=VAULT_INNER_MOD_HASH_HEX,
        eip712_domain=eip712_domain(),
        eip712_typehash_string=VAULT_SPEND_TYPEHASH_STRING,
        faucet_address=faucet.bech32_address() if faucet else None,
        faucet_balance_mojos=faucet_balance,
        deployed=deployed,
        deployment_manifest=deployment_manifest,
        protocol_config_hash=protocol_snapshot.content_hash_hex,
        protocol_config_launcher_id=protocol_snapshot.protocol_config_launcher_id_hex,
        protocol_config_version=protocol_snapshot.config_version,
        property_registry_launcher_id=singletons_snapshot.property_registry_launcher_id_hex,
        property_registry_mod_hash=singletons_snapshot.property_registry_mod_hash_hex,
        mint_proposal_mod_hash=singletons_snapshot.mint_proposal_mod_hash_hex,
        vault_version_registry_launcher_id=vault_registry_snapshot.vault_version_registry_launcher_id_hex,
        vault_version_registry_mod_hash=vault_registry_snapshot.vault_version_registry_mod_hash_hex,
        vault_version=vault_registry_snapshot.vault_version,
        vault_canonical_params_hash=vault_registry_snapshot.canonical_params_hash_hex,
        vault_version_registry_content_hash=vault_registry_snapshot.content_hash_hex,
    )


@app.post("/auth/challenge", response_model=ChallengeResponse)
async def request_challenge(
    body: ChallengeRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[ChallengeStore, Depends(get_challenge_store)],
) -> ChallengeResponse:
    """Issue a fresh registration challenge.

    Snapshots the current pool/network into the Challenge so that subsequent
    /vault/register/evm calls verify against THESE values, not whatever
    settings happen to be live at registration time (POP-CANON-002).

    Per-IP rate limited and capped at ``challenge_store_max_pending`` to
    bound memory under DoS load (POP-CANON-003).
    """
    require_alpha_writes(settings)
    pool_id_hex = _require_vault_protocol_ready(settings)
    network = settings.network
    source_ip = _client_ip(request)
    try:
        ch = store.issue(
            body.address,
            body.auth_type,
            pool_launcher_id_hex=pool_id_hex,
            chia_network=network,
            source_ip=source_ip,
        )
    except RateLimitedError as e:
        raise HTTPException(status_code=429, detail=str(e)) from e
    except ChallengeStoreFullError as e:
        raise HTTPException(status_code=429, detail=str(e)) from e

    typed_data: Optional[dict[str, Any]] = None
    message_hex: Optional[str] = None
    if body.auth_type == "evm":
        typed_data = registration_typed_data(
            body.address,
            ch.nonce,
            pool_launcher_id_hex=pool_id_hex,
            auth_type="secp256k1",
            chia_network=network,
        )
    elif body.auth_type == "chia_bls":
        message_hex = "0x" + registration_bls_message(
            ch.nonce,
            ch.pool_launcher_id_hex,
            ch.auth_type,
            ch.chia_network,
        ).hex()
    return ChallengeResponse(
        nonce=ch.nonce,
        expires_at=ch.expires_at,
        typed_data=typed_data,
        message_hex=message_hex,
    )


@app.post("/vault/register/evm", response_model=VaultCreationResponse)
async def register_evm_vault(
    body: RegisterEvmVaultRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    coinset: Annotated[CoinsetClient, Depends(get_coinset)],
    faucet: Annotated[Faucet, Depends(get_faucet)],
    store: Annotated[ChallengeStore, Depends(get_challenge_store)],
    registry: Annotated[VaultRegistry, Depends(get_registry)],
) -> VaultCreationResponse:
    require_alpha_writes(settings)
    current_pool_id_hex = _require_vault_protocol_ready(settings)
    ch = store.pop(body.nonce, body.address, "evm")
    if ch is None:
        raise HTTPException(
            status_code=400,
            detail="Challenge is missing, expired, or does not match this address/auth_type.",
        )
    if ch.pool_launcher_id_hex.lower() != current_pool_id_hex.lower():
        raise HTTPException(
            status_code=409,
            detail="Challenge no longer matches the active A.3 protocol config. Request a new challenge.",
        )

    # POP-CANON-002 fix: rebuild the typed_data using the SNAPSHOT recorded
    # at challenge issuance time, not current settings.  This means that
    # even if an operator changes ``pool_launcher_id`` or ``network``
    # between /auth/challenge and /vault/register/evm, the digest matches
    # only the pool/network the user actually saw and signed off on.
    typed_data = registration_typed_data(
        body.address,
        ch.nonce,
        pool_launcher_id_hex=ch.pool_launcher_id_hex,
        auth_type="secp256k1",
        chia_network=ch.chia_network,
    )
    try:
        recovery = recover_evm_signer(typed_data, body.signature)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    if recovery.address.lower() != body.address.lower():
        raise HTTPException(
            status_code=400,
            detail=(
                f"Signature is valid but recovered address {recovery.address} "
                f"does not match claimed {body.address}."
            ),
        )

    if registry.get_by_evm(recovery.address) is not None:
        raise HTTPException(
            status_code=409, detail="EVM address is already registered."
        )

    # Look up an unspent faucet coin
    coins = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
    )
    fee = 0
    min_amount = 1 + fee
    # POP-CANON-009 fix: enforce the documented per-spend cap.  Mirrors
    # Chia's CoinSelectionConfig.max_coin_amount filter.
    selected = faucet.select_coin(
        coins,
        min_amount=min_amount,
        max_amount=settings.faucet_max_spend_mojos,
    )
    if selected is None:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Faucet has no coins ≥ {min_amount} mojo at {faucet.bech32_address()}. "
                f"Please fund the faucet from a testnet11 faucet before registering new vaults."
            ),
        )

    # POP-CANON-002 fix: build the vault using the SNAPSHOTTED pool launcher
    # id (from the challenge), not the current settings.  This guarantees
    # the on-chain singleton is bound to the same pool the user saw in
    # their wallet at sign time.
    pool_launcher_id = bytes32.fromhex(_strip0x(ch.pool_launcher_id_hex))

    launched = build_and_sign_launch(
        faucet=faucet,
        faucet_coin_json={
            "parent_coin_info": "0x" + selected.parent_coin_info.hex(),
            "puzzle_hash": "0x" + selected.puzzle_hash.hex(),
            "amount": str(selected.amount),
        },
        owner_pubkey=recovery.compressed_pubkey,
        auth_type=AUTH_TYPE_SECP256K1,
        pool_launcher_id=pool_launcher_id,
        zkpassport_bridge_policy_hash=bytes32.fromhex(
            _strip0x(settings.zkpassport_bridge_policy_hash)
        ),
        fee=fee,
    )

    # POP-CANON-004 fix: hard-fail on push_tx rejection so the frontend
    # cannot silently believe a vault was registered when the spend was
    # never accepted into the mempool.
    accepted, push_status = await _push_or_fail(coinset, launched.spend_bundle)
    if not accepted:
        raise HTTPException(
            status_code=502,
            detail=f"coinset.org rejected the spend: {push_status}",
        )

    now = time.time()
    p2 = puzzle_for_p2_vault(launched.vault_launcher_id)
    p2_hash = bytes32(p2.get_tree_hash())

    record = VaultRecord(
        launcher_id=launched.vault_launcher_id,
        full_puzhash=launched.vault_full_puzhash,
        p2_vault_puzhash=p2_hash,
        auth_type=AUTH_TYPE_SECP256K1,
        owner_pubkey=recovery.compressed_pubkey,
        owner_evm_address=recovery.address,
        spend_bundle_id=launched.spend_bundle_id,
        pushed_at=now,
    )
    registry.record(record)

    return VaultCreationResponse(
        vault_launcher_id="0x" + launched.vault_launcher_id.hex(),
        vault_full_puzhash="0x" + launched.vault_full_puzhash.hex(),
        p2_vault_puzhash="0x" + p2_hash.hex(),
        spend_bundle_id=launched.spend_bundle_id,
        pushed_at=now,
        auth_type="evm",
        accepted=accepted,
        push_status=push_status,
    )


@app.post("/vault/register/chia", response_model=VaultCreationResponse)
async def register_chia_vault(
    body: RegisterChiaVaultRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    coinset: Annotated[CoinsetClient, Depends(get_coinset)],
    faucet: Annotated[Faucet, Depends(get_faucet)],
    store: Annotated[ChallengeStore, Depends(get_challenge_store)],
    registry: Annotated[VaultRegistry, Depends(get_registry)],
) -> VaultCreationResponse:
    require_alpha_writes(settings)
    pk_hex = body.bls_pubkey
    current_pool_id_hex = _require_vault_protocol_ready(settings)
    ch = store.pop(body.nonce, pk_hex, "chia_bls")
    if ch is None:
        raise HTTPException(
            status_code=400,
            detail="Challenge is missing, expired, or does not match this pubkey.",
        )
    if ch.pool_launcher_id_hex.lower() != current_pool_id_hex.lower():
        raise HTTPException(
            status_code=409,
            detail="Challenge no longer matches the active A.3 protocol config. Request a new challenge.",
        )

    pk_bytes = bytes.fromhex(pk_hex[2:] if pk_hex.startswith("0x") else pk_hex)
    if len(pk_bytes) != 48:
        raise HTTPException(status_code=400, detail="BLS pubkey must be 48 bytes")
    sig_bytes = bytes.fromhex(
        body.signature[2:] if body.signature.startswith("0x") else body.signature
    )
    if len(sig_bytes) != 96:
        raise HTTPException(status_code=400, detail="BLS signature must be 96 bytes")

    try:
        pk = G1Element.from_bytes(pk_bytes)
        sig = G2Element.from_bytes(sig_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"BLS key/sig invalid: {e}") from e

    signing_digest = registration_bls_signing_digest(
        ch.nonce,
        ch.pool_launcher_id_hex,
        ch.auth_type,
        ch.chia_network,
    )
    if not AugSchemeMPL.verify(pk, signing_digest, sig):
        raise HTTPException(status_code=400, detail="BLS signature does not verify")

    coins = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
    )
    fee = 0
    # POP-CANON-009 fix: enforce the documented per-spend cap.
    selected = faucet.select_coin(
        coins,
        min_amount=1 + fee,
        max_amount=settings.faucet_max_spend_mojos,
    )
    if selected is None:
        raise HTTPException(status_code=503, detail="Faucet has no spendable coins")

    # POP-CANON-002 parity: use the snapshotted pool_launcher_id_hex from
    # the challenge, not live settings. The CHIP-0002 signature commits to
    # this pool, auth path, and network. Without this parity, an operator
    # who changes pool_launcher_id between /auth/challenge and
    # /vault/register/chia would silently launch a BLS vault bound to a
    # different pool than the one snapshotted at challenge issuance.
    pool_launcher_id = bytes32.fromhex(_strip0x(ch.pool_launcher_id_hex))
    launched = build_and_sign_launch(
        faucet=faucet,
        faucet_coin_json={
            "parent_coin_info": "0x" + selected.parent_coin_info.hex(),
            "puzzle_hash": "0x" + selected.puzzle_hash.hex(),
            "amount": str(selected.amount),
        },
        owner_pubkey=pk_bytes,
        auth_type=AUTH_TYPE_BLS,
        pool_launcher_id=pool_launcher_id,
        zkpassport_bridge_policy_hash=bytes32.fromhex(
            _strip0x(settings.zkpassport_bridge_policy_hash)
        ),
        fee=fee,
    )

    # POP-CANON-004 fix: hard-fail on push_tx rejection.
    accepted, push_status = await _push_or_fail(coinset, launched.spend_bundle)
    if not accepted:
        raise HTTPException(
            status_code=502,
            detail=f"coinset.org rejected the spend: {push_status}",
        )

    now = time.time()
    p2 = puzzle_for_p2_vault(launched.vault_launcher_id)
    p2_hash = bytes32(p2.get_tree_hash())

    record = VaultRecord(
        launcher_id=launched.vault_launcher_id,
        full_puzhash=launched.vault_full_puzhash,
        p2_vault_puzhash=p2_hash,
        auth_type=AUTH_TYPE_BLS,
        owner_pubkey=pk_bytes,
        owner_evm_address=None,
        spend_bundle_id=launched.spend_bundle_id,
        pushed_at=now,
    )
    registry.record(record)

    return VaultCreationResponse(
        vault_launcher_id="0x" + launched.vault_launcher_id.hex(),
        vault_full_puzhash="0x" + launched.vault_full_puzhash.hex(),
        p2_vault_puzhash="0x" + p2_hash.hex(),
        spend_bundle_id=launched.spend_bundle_id,
        pushed_at=now,
        auth_type="chia_bls",
        accepted=accepted,
        push_status=push_status,
    )


@app.get("/vault/{launcher_id}", response_model=VaultStateResponse)
async def get_vault(
    launcher_id: str,
    coinset: Annotated[CoinsetClient, Depends(get_coinset)],
    registry: Annotated[VaultRegistry, Depends(get_registry)],
) -> VaultStateResponse:
    lid = _parse_bytes32(launcher_id, "launcher_id")
    record = registry.get(lid)
    if record is None:
        raise HTTPException(status_code=404, detail="Vault not registered on this server")

    confirmed_block_index: Optional[int] = None
    current_coin_id: Optional[str] = None
    confirmed = False

    coins = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + record.full_puzhash.hex(), include_spent=False
    )
    for rec in coins:
        if rec.get("spent_block_index") in (0, None):
            cjson = rec.get("coin") or rec
            from chia.types.blockchain_format.coin import Coin
            coin = Coin(
                parent_coin_info=bytes32.fromhex(cjson["parent_coin_info"].removeprefix("0x")),
                puzzle_hash=bytes32.fromhex(cjson["puzzle_hash"].removeprefix("0x")),
                amount=int(cjson["amount"]),
            )
            current_coin_id = "0x" + bytes(coin.name()).hex()
            confirmed_block_index = rec.get("confirmed_block_index")
            confirmed = True
            break

    auth_label = "evm" if record.auth_type == AUTH_TYPE_SECP256K1 else "chia_bls"
    return VaultStateResponse(
        vault_launcher_id="0x" + record.launcher_id.hex(),
        vault_full_puzhash="0x" + record.full_puzhash.hex(),
        p2_vault_puzhash="0x" + record.p2_vault_puzhash.hex(),
        auth_type=auth_label,
        owner_address=record.owner_evm_address,
        owner_pubkey="0x" + record.owner_pubkey.hex(),
        confirmed=confirmed,
        confirmed_block_index=confirmed_block_index,
        current_coin_id=current_coin_id,
        balance={"xch_mojos": 0, "deeds": []},  # TODO: aggregate p2_vault holdings
    )


# POP-CANON-014: /vault/by-evm/{address} removed.  See module docstring.
# ``VaultRegistry.get_by_evm`` remains an internal-only helper.


# ─── Helpers ─────────────────────────────────────────────────────────────────────

def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def _pool_launcher_id_or_zero(settings: Settings) -> bytes32:
    """Return the configured pool launcher id, or a 32-zero placeholder on
    testnet while the pool has not been deployed yet.

    A zero pool id is acceptable for Phase-0 smoke testing: the vault still
    launches, but pool-mediated flows will fail until a real pool is pinned.

    POP-CANON-011 fix (2026-04-26): prefer the deployment manifest over the
    cached env-based ``settings.pool_launcher_id``.  The manifest is the
    source of truth post-deploy; the env value is the bootstrap default.
    Reading fresh from disk on each call mirrors Chia's "no @lru_cache on
    Service config" pattern and eliminates stale-pool drift after an
    admin redeploy without process restart.

    Resolution order:
      1. ``deployment_manifest.pool_launcher_id`` if the manifest exists.
      2. ``settings.pool_launcher_id`` (env / .env fallback).
      3. 32-zero placeholder (Phase-0 smoke testing).
    """
    pool_id = _read_pool_launcher_from_manifest(settings.deployment_manifest_path)
    if pool_id is not None:
        return bytes32.fromhex(_strip0x(pool_id))
    if settings.pool_launcher_id:
        return bytes32.fromhex(_strip0x(settings.pool_launcher_id))
    return bytes32(b"\x00" * 32)


def _read_pool_launcher_from_manifest(manifest_path: str) -> Optional[str]:
    """Read ``pool_launcher_id`` from the deployment manifest if it exists.

    Returns the post-deploy pool_launcher_id, or None on any error
    (file missing, malformed JSON, missing key).  Callers MUST fall back
    to ``settings.pool_launcher_id`` and then to the zero placeholder.

    Errors are swallowed because the manifest may be momentarily malformed
    during a partial admin write; this function must never raise.

    POP-CANON-011 fix.

    Note: this deliberately uses plain ``json.loads`` rather than
    ``solslot_puzzles.protocol_deployment.load_manifest_dict``.  The latter
    enforces a strict schema (all 18 required fields) which is the right
    contract for the ``/admin/deployment`` introspection endpoint, but
    overkill — and a stability liability — for the hot path that just
    needs one well-known field.  An admin manifest with an evolving schema
    must not break new-challenge issuance.
    """
    try:
        import json
        from pathlib import Path

        p = Path(manifest_path)
        if not p.exists():
            return None
        raw = json.loads(p.read_text())
        pool_id = raw.get("pool_launcher_id")
        if pool_id and not pool_id.startswith("0x"):
            pool_id = "0x" + pool_id
        return pool_id
    except Exception:
        return None


def _pool_launcher_id_hex(settings: Settings) -> str:
    """Hex form of the pool launcher id, snapshotted into challenges."""
    return "0x" + _pool_launcher_id_or_zero(settings).hex()


def _require_vault_protocol_ready(settings: Settings) -> str:
    if not settings.zkpassport_bridge_policy_hash:
        raise HTTPException(
            status_code=409,
            detail="Vault registration is disabled until the fresh V2 bridge policy is pinned.",
        )
    _require_nonzero_bytes32_hex(
        settings.zkpassport_bridge_policy_hash,
        "SOLSLOT_ZKPASSPORT_BRIDGE_POLICY_HASH",
    )
    protocol_config_launcher_id = getattr(settings, "protocol_config_launcher_id", None)
    if not protocol_config_launcher_id:
        raise HTTPException(
            status_code=409,
            detail="Vault registration is disabled until the A.3 protocol-config singleton is launched.",
        )
    _require_nonzero_bytes32_hex(
        protocol_config_launcher_id,
        "SOLSLOT_PROTOCOL_CONFIG_LAUNCHER_ID",
    )

    try:
        from pathlib import Path

        manifest = load_deployment_manifest(Path(settings.deployment_manifest_path))
    except Exception as e:
        raise HTTPException(
            status_code=409,
            detail="Vault registration is disabled until protocol genesis has a valid deployment manifest.",
        ) from e

    pool_id_hex = _require_nonzero_bytes32_hex(
        manifest.get("pool_launcher_id"),
        "deployment_manifest.pool_launcher_id",
    )
    governance_id_hex = _require_nonzero_bytes32_hex(
        manifest.get("tracker_launcher_id"),
        "deployment_manifest.tracker_launcher_id",
    )

    snapshot = build_protocol_config_snapshot(
        settings,
        pool_launcher_id_hex=pool_id_hex,
        governance_launcher_id_hex=governance_id_hex,
    )
    if snapshot.content_hash_hex is None:
        raise HTTPException(
            status_code=409,
            detail="Vault registration is disabled until A.3 commits to pool, governance, network, and version.",
        )
    return pool_id_hex


def _require_nonzero_bytes32_hex(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=409, detail=f"{field_name} is required.")
    clean = _strip0x(value.strip())
    if len(clean) != 64:
        raise HTTPException(status_code=409, detail=f"{field_name} must be 32 bytes.")
    try:
        parsed = bytes32.fromhex(clean)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=f"{field_name} is not valid hex.") from e
    if parsed == bytes32(b"\x00" * 32):
        raise HTTPException(status_code=409, detail=f"{field_name} cannot be zero.")
    return "0x" + parsed.hex()


def _client_ip(request: Request) -> str:
    """Extract the client IP for per-IP rate limiting.

    Uses the immediate peer address rather than trusting client-supplied
    forwarding headers.
    """
    if request.client is not None:
        return request.client.host
    return "unknown"


async def _push_or_fail(coinset: CoinsetClient, spend_bundle: Any) -> tuple[bool, Optional[str]]:
    """Broadcast a spend bundle to coinset.org and surface the result.

    Returns:
        (accepted, status_string).  ``accepted`` is True iff coinset's
        ``push_tx`` returned ``success: true``.  When False, the caller
        should still return a response (so the client can render the
        error) but ``status_string`` carries the diagnostic.

    POP-CANON-004 fix: previously this only logged a warning and returned
    success regardless of the actual mempool acceptance status.
    """
    try:
        push_result = await coinset.push_tx(_spend_bundle_to_json(spend_bundle))
    except Exception as e:
        logger.exception("coinset push_tx failed: %s", e)
        raise HTTPException(
            status_code=502, detail=f"coinset.org rejected the spend: {e}"
        ) from e

    if push_result.get("success"):
        return True, None

    status = push_result.get("status") or push_result.get("error") or str(push_result)
    logger.warning("push_tx returned non-success: %s", status)
    return False, str(status)


def _parse_bytes32(h: str, field_name: str) -> bytes32:
    clean = h[2:] if h.startswith("0x") else h
    if len(clean) != 64:
        raise HTTPException(status_code=400, detail=f"{field_name} must be 32 bytes")
    try:
        return bytes32.fromhex(clean)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"{field_name} is not valid hex: {e}") from e


def _spend_bundle_to_json(bundle) -> dict[str, Any]:
    """Serialise a chia_rs.SpendBundle into coinset.org's expected JSON shape."""
    # chia_rs.SpendBundle has to_json_dict() that returns the exact shape
    # that Chia full-node `push_tx` accepts.
    if hasattr(bundle, "to_json_dict"):
        return bundle.to_json_dict()  # type: ignore[no-any-return]
    # Fallback: manually serialise
    return {
        "coin_spends": [
            {
                "coin": {
                    "parent_coin_info": "0x" + bytes(cs.coin.parent_coin_info).hex(),
                    "puzzle_hash": "0x" + bytes(cs.coin.puzzle_hash).hex(),
                    "amount": cs.coin.amount,
                },
                "puzzle_reveal": "0x" + bytes(cs.puzzle_reveal).hex(),
                "solution": "0x" + bytes(cs.solution).hex(),
            }
            for cs in bundle.coin_spends
        ],
        "aggregated_signature": "0x" + bytes(bundle.aggregated_signature).hex(),
    }


__all__ = ["app"]
