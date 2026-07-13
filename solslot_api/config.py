"""Runtime configuration for the Solslot API.

Values are loaded from environment variables (optionally via .env) by
pydantic-settings.  Secrets — the faucet key and the challenge secret —
are the two values that MUST be set in production.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


SECRET_ENV_FILE_KEYS = frozenset(
    {
        "SOLSLOT_ADMIN_JWT_SECRET",
        "SOLSLOT_ADMIN_TOKEN",
        "SOLSLOT_FAUCET_MASTER_SK_HEX",
        "SOLSLOT_FAUCET_SEED_HEX",
        "SOLSLOT_FAUCET_MNEMONIC",
        "SOLSLOT_CHALLENGE_SECRET",
        "SOLSLOT_BOOTSTRAP_SESSION_SECRET",
        "SOLSLOT_ZKPASSPORT_VALIDATOR_SEED_HEX",
        "SOLSLOT_ZKPASSPORT_RELAYER_PRIVATE_KEY_HEX",
        "SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN",
    }
)

_RETIRED_NAMESPACE_DIGEST = (
    "4b61ef4fda96729ef3703e602087708f3fa1ebfc2d809e0be3398086f8ec6706"
)
_RETIRED_NAMESPACE_LENGTH = 7


def validate_runtime_environment_namespace() -> None:
    """Reject environment keys from the abandoned runtime namespace."""
    offenders: list[str] = []
    for key in os.environ:
        lowered = key.lower().encode("utf-8")
        for index in range(len(lowered) - _RETIRED_NAMESPACE_LENGTH + 1):
            token = lowered[index : index + _RETIRED_NAMESPACE_LENGTH]
            if hashlib.sha256(token).hexdigest() == _RETIRED_NAMESPACE_DIGEST:
                offenders.append(key)
                break
    if offenders:
        raise RuntimeError(
            "Retired runtime namespace detected in environment keys: "
            + ", ".join(sorted(offenders))
            + ". Configure SOLSLOT_* variables only."
        )


def validate_secret_env_file_permissions(env_file: Path | None = None) -> None:
    path = env_file or Path(str(Settings.model_config.get("env_file", ".env")))
    if not path.exists() or not path.is_file():
        return
    secret_keys = _secret_keys_present_in_env_file(path)
    if not secret_keys:
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        keys = ", ".join(sorted(secret_keys))
        raise RuntimeError(
            f"{path} contains secret env vars ({keys}) but is readable or writable "
            f"by group/other (mode {mode:03o}). Run `chmod 600 {path}` or move "
            "secrets into a secret store before starting the API."
        )


def validate_server_hardening_at_startup(settings: "Settings") -> None:
    """Reject unsafe staging/production HTTP posture before serving traffic."""

    if settings.runtime_environment not in {"staging", "production"}:
        return
    if not settings.bootstrap_cookie_secure:
        raise RuntimeError(
            "SOLSLOT_BOOTSTRAP_COOKIE_SECURE must be true in staging/production."
        )
    if settings.api_docs_enabled:
        raise RuntimeError(
            "SOLSLOT_API_DOCS_ENABLED must be false in staging/production."
        )
    if not settings.security_headers_enabled or not settings.hsts_enabled:
        raise RuntimeError(
            "Security headers and HSTS must be enabled in staging/production."
        )
    if (
        settings.runtime_environment == "production"
        and settings.network == "mainnet"
        and settings.zkpassport_validator_threshold < 2
    ):
        raise RuntimeError(
            "Mainnet production requires SOLSLOT_ZKPASSPORT_VALIDATOR_THRESHOLD "
            "of at least 2."
        )

    insecure_origins: list[str] = []
    for origin in settings.allowed_origins():
        lowered = origin.lower()
        if (
            origin == "*"
            or lowered.startswith("http://")
            or "localhost" in lowered
            or "127.0.0.1" in lowered
            or "0.0.0.0" in lowered
        ):
            insecure_origins.append(origin)
    if insecure_origins:
        raise RuntimeError(
            "Staging/production CORS origins must be exact HTTPS origins; rejected: "
            + ", ".join(sorted(insecure_origins))
        )


def _secret_keys_present_in_env_file(path: Path) -> set[str]:
    keys: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return keys
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if key in SECRET_ENV_FILE_KEYS and value.strip().strip("\"'"):
            keys.add(key)
    return keys


class Settings(BaseSettings):
    """Solslot API runtime settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SOLSLOT_",
        extra="ignore",
    )

    # ── Empty-string → None coercion for optional-string fields ──────────
    # Setting an env var to "" (e.g. by the test conftest's ``.env``-mask
    # shim) must read back as ``None`` rather than ``""`` so callers'
    # ``is None`` checks behave the same as when the var is genuinely
    # unset.  Applied to every ``Optional[str]`` field where ``None`` is
    # the meaningful "absent" sentinel.
    @field_validator(
        "protocol_admin_authority_v2_launcher_id",
        "protocol_admin_authority_v2_mips_root_hash",
        "protocol_admin_authority_v2_admins_hash",
        "protocol_admin_authority_v2_pending_ops_hash",
        "pool_launcher_id",
        "governance_launcher_id",
        "protocol_config_launcher_id",
        "protocol_property_registry_launcher_id",
        "vault_version_registry_launcher_id",
        "admin_records_path",
        "zkpassport_validator_seed_hex",
        "zkpassport_relayer_private_key_hex",
        "zkpassport_bridge_policy_hash",
        "zkpassport_forwarder_address",
        "zkpassport_emitter_address",
        "protocol_artifact_api_token",
        mode="before",
    )
    @classmethod
    def _empty_string_is_none(cls, v: object) -> object:
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    # ── Server posture ───────────────────────────────────────────────────
    # Secure-by-default: local development must opt in explicitly.  This
    # prevents a missing environment variable on a newly provisioned host
    # from silently enabling development CORS or API documentation.
    runtime_environment: Literal[
        "development", "test", "staging", "production"
    ] = "production"
    api_docs_enabled: bool = False
    security_headers_enabled: bool = True
    hsts_enabled: bool = True
    max_request_body_bytes: int = Field(4 * 1024 * 1024, ge=1, le=16 * 1024 * 1024)
    request_timeout_seconds: float = Field(30.0, gt=0, le=120.0)

    # ── Network ───────────────────────────────────────────────────────────
    network: Literal["testnet11", "mainnet"] = "testnet11"
    coinset_base_url: str = "https://testnet11.api.coinset.org"

    # High-risk protocol writes remain locked until the frozen V2 artifact
    # bundle has passed ceremony preflight. Read-only health, protocol, vault,
    # and credential receipt recovery remain available while this is false.
    alpha_writes_enabled: bool = False
    minting_enabled: bool = False
    release_metadata_path: str = "./release.json"

    # ── Auth / challenges ────────────────────────────────────────────────
    challenge_ttl_seconds: int = 300
    # 32-byte hex string.  If empty a random one is generated per-process.
    challenge_secret: str = ""

    # ── Faucet (launcher payer) ──────────────────────────────────────────
    # ONE of these three must be set; without any the backend refuses to
    # register new vaults.
    #   * faucet_mnemonic           — 12/24-word BIP-39 mnemonic
    #   * faucet_seed_hex           — 32-byte hex entropy for AugSchemeMPL.key_gen
    #   * faucet_master_sk_hex      — 32-byte hex of a serialised BLS master PrivateKey
    #                                 (e.g. pulled directly out of Chia's keychain)
    faucet_mnemonic: Optional[str] = None
    faucet_seed_hex: Optional[str] = None
    faucet_master_sk_hex: Optional[str] = None
    # Maximum amount (mojos) a single faucet-funded launcher may consume.
    # Launchers themselves cost 1 mojo; the rest is fee headroom.
    faucet_max_spend_mojos: int = 10_000_000  # 0.01 XCH per registration

    # ── Protocol deployment ───────────────────────────────────────────────
    # Once the pool singleton, governance singleton and DID are launched on
    # testnet they are pinned here.  Vaults must reference the same pool.
    pool_launcher_id: Optional[str] = None
    governance_launcher_id: Optional[str] = None
    # Path to the persisted deployment manifest (JSON).  When set and present,
    # the API loads the plan on startup so it can serve /admin/deployment and
    # the protocol-aware vault flows without re-deploying.
    deployment_manifest_path: str = "./state/deployment_manifest_v2.json"
    bootstrap_manifest_path: str = "./state/bootstrap_manifest_v2.json"
    bootstrap_session_secret: str = ""
    bootstrap_session_ttl_seconds: int = Field(900, ge=1)
    bootstrap_cookie_secure: bool = True

    # ── Protocol-config singleton (A.3) ───────────────────────────────────
    # On-chain replacement for the three trust-root env vars
    # ``pool_launcher_id`` / ``governance_launcher_id`` / ``network``.
    # When the operator has launched a ``protocol_config_inner.clsp``
    # singleton, set this to its 32-byte launcher coin id (0x-prefixed
    # hex).  The API then surfaces a deterministic ``protocol_config_hash``
    # on ``/protocol`` so frontends can independently verify the
    # operator's published config matches the on-chain singleton state.
    #
    # The value must come from the signed V2 ceremony artifact.
    protocol_config_launcher_id: Optional[str] = None
    # Monotonically increasing version stamped into the singleton's
    # curried state.  Bumped by the operator on every config update;
    # the puzzle enforces ``new_version > old_version`` (replay
    # protection).  Default 1 = "initial deployment".
    protocol_config_version: int = 1

    # ── Solslot V2 admin-authority singleton ──────────────────────────────
    # CHIP-0043 MIPS composition replaces flat key allowlists.
    # composition. Each admin slot holds a OneOfN of personal auth methods
    # (BLS, EIP-712 / MetaMask, passkey, ...) under a protocol-level MofN
    # quorum. Lets admins mix signing methods and add backup keys over time
    # without going through SGT governance.
    #
    # The API exposes these values publicly and accepts admin JWTs only from
    # a records file whose launcher and admins hash match this authority.
    #
    protocol_admin_authority_v2_launcher_id: Optional[str] = None
    # 0x-prefixed 32-byte sha256-tree hash of the MIPS m_of_n quorum tree.
    # Computed off-chain via chia-wallet-sdk MIPS bindings; published here
    # so the snapshot endpoint can return the same value the on-chain
    # puzzle has curried.
    protocol_admin_authority_v2_mips_root_hash: Optional[str] = None
    # 0x-prefixed sha256-tree hash of the admins list (each entry is
    # ``(admin_idx, leaves_list, m_within)``). Computed via
    # ``solslot_puzzles.admin_authority_v2_driver.compute_admins_hash``.
    protocol_admin_authority_v2_admins_hash: Optional[str] = None
    # 0x-prefixed sha256-tree hash of the pending-ops list. Defaults to
    # the empty-list hash when omitted; bumped whenever a KEY_ADD_PROPOSE
    # / KEY_REMOVE_EMERGENCY adds an entry, or KEY_ADD_ACTIVATE / VETO
    # / KEY_ADD_REMOVE_ACTIVATE removes one.
    protocol_admin_authority_v2_pending_ops_hash: Optional[str] = None
    # Monotonic uint64 stamped into the v2 singleton's curried state.
    # Strictly increases across all 6 spend tags. Defaults to 1; operators
    # The clean V2 ceremony starts this counter at 1.
    protocol_admin_authority_v2_version: int = 1

    # ── Property-registry singleton (A.4) ─────────────────────────────────
    # On-chain replacement for the off-chain property-uniqueness role
    # of ``MintProposalStore`` (POP-CANON-014).  When the operator has
    # launched a ``property_registry_inner.clsp`` singleton, set this
    # to its launcher coin id; the API surfaces it on the ``/protocol``
    # endpoint so clients can walk the singleton's lineage on
    # coinset.org to enumerate registered properties.
    #
    # Minting remains locked until this singleton can be verified on-chain.
    protocol_property_registry_launcher_id: Optional[str] = None

    # ── Vault-version registry singleton (vault upgrade / Brick 4d) ────────
    # On-chain ``vault_version_registry_inner.clsp`` singleton that publishes
    # the canonical current vault descriptor (vault inner mod hash, canonical
    # params hash, vault version).  Backend-free clients walk its lineage on
    # coinset.org to detect outdated vaults and offer a decentralized upgrade.
    # When the operator has launched the registry, set this to its 32-byte
    # launcher coin id (0x-prefixed hex); the API then surfaces a deterministic
    # ``vault_version_registry_content_hash`` clients can independently verify
    # against the singleton's on-chain ``CREATE_PUZZLE_ANNOUNCEMENT``.  ``None``
    # until the registry is deployed (clients treat the protocol as
    # "registry-less" and skip the upgrade banner).
    vault_version_registry_launcher_id: Optional[str] = None
    # Monotonically increasing vault descriptor version stamped into the
    # registry's curried state.  Bumped by the authorizer on every publish
    # spend; default 1 = "initial deployment".
    vault_version_registry_version: int = 1

    # ── zkPassport validator node ─────────────────────────────────────────
    # 32-byte hex seed for the BLS validator keypair that countersigns
    # VaultAttestationVerified EVM events.  Generate with:
    #   python3 -c "import secrets; print(secrets.token_bytes(32).hex())"
    # Store as SOLSLOT_ZKPASSPORT_VALIDATOR_SEED_HEX in .env (mode 0600).
    # This key is used only by the internal enrollment state machine after an
    # indexed EVM event and reserved Chia bridge coin have both been verified.
    # There is intentionally no public validator-signing endpoint.
    zkpassport_validator_seed_hex: Optional[str] = None
    # Alpha may use one validator explicitly. A mainnet production process
    # refuses to start below 2; the fresh bridge policy must commit to the
    # same threshold and independent validator set.
    zkpassport_validator_threshold: int = Field(1, ge=1, le=16)

    # ── zkPassport vault bridge policy hash ───────────────────────────
    # Canonical validator-set commitment curried into every vault at mint so
    # the on-chain spend_update_identity ('z') can assert the validator bridge
    # coin announcement.  MUST equal the deployed emitter's bridgePolicyHash and
    # the portal's environment.zkPassport bridgePolicyHash.  Vaults minted before
    # this was wired (the old zero default) are NOT enrollable and must be
    # re-registered.
    zkpassport_bridge_policy_hash: Optional[str] = None
    zkpassport_bridge_amount: int = 1
    # Enrollment discovers confirmed unspent coins at the current bridge
    # policy hash. Public enrollment requests never spend the faucet. A
    # chain-verified admin replenishes the pool through the protected route.
    # Persistent public receipt/index and anti-replay ledger. Chia vault state
    # remains final authority. A fresh database is required for every V2
    # ceremony; retired JSON enrollment stores are never imported.
    zkpassport_ledger_db_path: str = "./state/zkpassport_v2.db"
    zkpassport_policy_version: int = Field(2, ge=2)
    zkpassport_owner_challenge_ttl_seconds: int = Field(300, ge=30, le=900)

    # ── zkPassport gasless relayer (ERC-2771 meta-transactions) ────────
    # The relayer submits forwarder.execute() on behalf of users so alpha
    # testers never need Sepolia ETH.  Users still sign an EIP-712
    # ForwardRequest in their wallet (gasless); this key only pays gas.
    #
    # SECRET — 0x-prefixed 32-byte key of a funded EOA.  When unset, POST
    # /zkpassport/relay returns 503.  Store in .env (mode 0600); on testnet you
    # may reuse the EVM deployer key.
    zkpassport_relayer_private_key_hex: Optional[str] = None

    # ── Sols Lot protocol artifact server-to-server guard ────────────────
    # Optional bearer token for endpoints that *build* or *finalize*
    # protocol purchase artifacts.  Public verification remains open so
    # wallets, portals, and auditors can recompute artifact hashes without
    # holding any service credential.
    protocol_artifact_api_token: Optional[str] = None
    # JSON-RPC endpoint the relayer uses (defaults to a public Sepolia node).
    zkpassport_evm_rpc_url: str = "https://ethereum-sepolia-rpc.publicnode.com"
    # EIP-155 chain id the relayer signs for (11155111 = Eth Sepolia).
    zkpassport_evm_chain_id: int = 11155111
    # Fresh V2 addresses are intentionally unset until the EVM ceremony.
    zkpassport_forwarder_address: Optional[str] = None
    zkpassport_emitter_address: Optional[str] = None
    zkpassport_evm_min_confirmations: int = Field(2, ge=1)

    # Persistent relay limits. Each axis is enforced independently so one
    # account, vault, source, or bridge coin cannot drain the sponsored key.
    zkpassport_relay_per_ip_per_minute: int = Field(12, ge=1)
    zkpassport_relay_per_owner_per_minute: int = Field(6, ge=1)
    zkpassport_relay_per_vault_per_hour: int = Field(2, ge=1)
    zkpassport_relay_global_gas_per_day: int = Field(20_000_000, ge=1)
    zkpassport_relay_circuit_failure_threshold: int = Field(5, ge=1)
    zkpassport_relay_circuit_cooldown_seconds: int = Field(900, ge=60)

    # ── Admin auth ────────────────────────────────────────────────────────
    # Bearer token required by `/admin/deploy/*` and other one-shot operator
    # commands.  When unset, those routes are disabled (return 503) — the
    # safest default for a public endpoint without an explicit operator
    # opt-in.  Generate with `openssl rand -hex 32`.
    admin_token: Optional[str] = None

    # ── Admin Desk (interactive operator UI) ──────────────────────────────
    # The Admin Desk uses chain-bound records + a short-lived JWT instead
    # of the ceremony token. See
    # `docs/ADMIN_DESK_DESIGN.md` §3 for the full rationale.

    # Path to a JSON file containing the OPERATOR-EXPANDED admin records
    # When set, the API:
    #   1. Loads the records at boot.
    #   2. Recomputes ``admins_hash`` from them via the protocol's
    #      canonical hash function and asserts it matches the on-chain
    #      singleton's ``admins_hash`` (sourced from
    #      ``protocol_admin_authority_v2_admins_hash`` ceremony coordinate).
    #   3. Builds the EVM-address set from the JSON's EIP-712 leaf metadata.
    #
    # The file is ENVIRONMENT-LOCAL — it contains only data that's already
    # public (pubkeys, EVM addresses, hashes); no secrets.  But it MUST
    # match the on-chain state or the API refuses to boot, so treat it
    # as part of the deployment artefact.
    #
    # See ``solslot_api.admin_records.AdminRecordsConfig`` for the JSON
    # schema; ``GENESIS_README.md`` shows how to generate this file from
    # a launch wizard run.
    admin_records_path: Optional[str] = None

    def effective_admin_records_path(self) -> Optional[str]:
        if self.admin_records_path:
            return self.admin_records_path
        path = Path(self.bootstrap_manifest_path).with_name("admin_records_v2.json")
        return str(path) if path.exists() else None

    def _finalized_admin_authority_v2(self) -> dict[str, object]:
        path = Path(self.bootstrap_manifest_path).with_name("portal_runtime_config_v2.json")
        if not path.exists():
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, dict):
            return {}
        authority = raw.get("admin_authority_v2")
        return authority if isinstance(authority, dict) else {}

    def effective_protocol_admin_authority_v2_launcher_id(self) -> Optional[str]:
        if self.protocol_admin_authority_v2_launcher_id:
            return self.protocol_admin_authority_v2_launcher_id
        value = self._finalized_admin_authority_v2().get("launcher_id")
        return value if isinstance(value, str) and value.strip() else None

    def effective_protocol_admin_authority_v2_mips_root_hash(self) -> Optional[str]:
        if self.protocol_admin_authority_v2_mips_root_hash:
            return self.protocol_admin_authority_v2_mips_root_hash
        value = self._finalized_admin_authority_v2().get("mips_root")
        return value if isinstance(value, str) and value.strip() else None

    def effective_protocol_admin_authority_v2_admins_hash(self) -> Optional[str]:
        if self.protocol_admin_authority_v2_admins_hash:
            return self.protocol_admin_authority_v2_admins_hash
        value = self._finalized_admin_authority_v2().get("admins_hash")
        return value if isinstance(value, str) and value.strip() else None

    def effective_protocol_admin_authority_v2_version(self) -> int:
        authority = self._finalized_admin_authority_v2()
        value = authority.get("authority_version")
        if (
            self.protocol_admin_authority_v2_version != 1
            or not isinstance(value, int)
        ):
            return self.protocol_admin_authority_v2_version
        return value

    # HS256 secret used to sign admin-desk JWTs.  Generate with
    # `openssl rand -hex 32`.  When empty, a random per-process secret is
    # generated; that's fine for local dev but means tokens don't survive
    # restart.  In production, set this explicitly.
    admin_jwt_secret: str = ""

    # Lifetime (seconds) of an admin JWT.  Default 15 minutes.  Refresh via
    # /admin/auth/refresh while the session is active.
    admin_jwt_ttl_seconds: int = 900

    # Rate limit on /admin/auth/challenge per source IP per minute.
    admin_login_per_ip_per_minute: int = 6

    # Default voting window (seconds) for newly-published mint proposals.
    # The operator can override per-proposal within
    # [voting_window_min, voting_window_max].  Default 24h.
    voting_window_seconds_default: int = 86400
    voting_window_seconds_min: int = 3600       # 1h floor
    voting_window_seconds_max: int = 604800     # 7d ceiling

    # Filesystem path to the admin desk SQLite database (mint proposals,
    # property metadata).  Distinct from the vault registry path so the
    # operator can back them up independently.
    admin_db_path: str = "./state/admin_desk_v2.db"

    # ── CORS ──────────────────────────────────────────────────────────────
    # Same-origin deployments need no CORS entries. Local development opts
    # in with SOLSLOT_RUNTIME_ENVIRONMENT=development; only then is the
    # localhost regex accepted by cors_middleware_options().
    cors_origins: str = ""

    # ── EIP-712 domain ────────────────────────────────────────────────────
    eip712_name: str = "Solslot Protocol"
    # V2 binds pool, auth type, and network. Other versions are rejected.
    eip712_version: str = "2"
    # MUST match EIP712_DOMAIN_CHAIN_ID in solslot_puzzles/vault_driver.py.
    eip712_chain_id: int = 1

    # ── DoS hardening (POP-CANON-003 / Strategy 7) ────────────────────────
    # Maximum number of pending challenges in memory at any time.  When the
    # cap is reached, /auth/challenge returns 429 to back off load.
    challenge_store_max_pending: int = 50_000
    # Maximum challenges issued per source IP per minute.
    challenge_per_ip_per_minute: int = 60
    # Shared SQLite-WAL store makes challenge quotas and nonce consumption
    # process-safe. Tests opt into the in-memory implementation explicitly.
    challenge_store_path: str = "./state/challenges_v2.db"

    # ── Faucet UTXO consolidation worker (POP-CANON-008) ──────────────────
    # Background task that periodically merges fragmented faucet change UTXOs
    # back into a single coin.  Disabled by default — operators must opt in
    # after verifying behaviour against their own faucet.
    faucet_consolidation_enabled: bool = False
    # When the unspent UTXO count exceeds this, the worker triggers a merge.
    faucet_consolidation_threshold: int = 50
    # Polling interval in seconds (default 10 min).
    faucet_consolidation_interval_seconds: float = 600.0
    # Fee paid by the consolidating spend bundle (mojos).  Default 0 — testnet
    # mempools accept zero-fee bundles when block space is available.
    faucet_consolidation_fee: int = 0
    # Cap on inputs per consolidation run (well below MAX_SPENDS_PER_BLOCK).
    faucet_consolidation_max_inputs: int = 500

    def allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def effective_admin_allowlist_set(self) -> set[str]:
        """Return EVM admins derived only from hash-verified V2 records."""
        if self.effective_admin_records_path():
            from .admin_records import get_admin_records_for_settings
            records = get_admin_records_for_settings(self)
            if records is None:
                return set()  # path set but load failed validation already
            return records.eip712_evm_address_set()
        return set()

@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
