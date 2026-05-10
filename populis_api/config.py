"""Runtime configuration for the Populis API.

Values are loaded from environment variables (optionally via .env) by
pydantic-settings.  Secrets — the faucet key and the challenge secret —
are the two values that MUST be set in production.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Populis API runtime settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="POPULIS_",
        extra="ignore",
    )

    # ── Empty-string → None coercion for optional-string fields ──────────
    # Setting an env var to "" (e.g. by the test conftest's ``.env``-mask
    # shim) must read back as ``None`` rather than ``""`` so callers'
    # ``is None`` checks behave the same as when the var is genuinely
    # unset.  Applied to every ``Optional[str]`` field where ``None`` is
    # the meaningful "absent" sentinel.
    @field_validator(
        "protocol_admin_authority_launcher_id",
        "protocol_admin_authority_v2_launcher_id",
        "protocol_admin_authority_v2_mips_root_hash",
        "protocol_admin_authority_v2_admins_hash",
        "protocol_admin_authority_v2_pending_ops_hash",
        "pool_launcher_id",
        "governance_launcher_id",
        "protocol_config_launcher_id",
        "protocol_property_registry_launcher_id",
        "admin_records_path",
        mode="before",
    )
    @classmethod
    def _empty_string_is_none(cls, v: object) -> object:
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    # ── Network ───────────────────────────────────────────────────────────
    network: Literal["testnet11", "mainnet"] = "testnet11"
    coinset_base_url: str = "https://testnet11.api.coinset.org"

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
    deployment_manifest_path: str = "./deployment_manifest.json"
    bootstrap_manifest_path: str = "./bootstrap_manifest.json"
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
    # Phase 1 (this commit): the API computes content_hash from the
    # *settings* values; the operator is responsible for keeping settings
    # and on-chain state aligned.  Phase 1.5 adds a coinset.org indexer
    # that walks the singleton lineage and parses the curried state
    # directly, removing the operator-trust step.
    protocol_config_launcher_id: Optional[str] = None
    # Monotonically increasing version stamped into the singleton's
    # curried state.  Bumped by the operator on every config update;
    # the puzzle enforces ``new_version > old_version`` (replay
    # protection).  Default 1 = "initial deployment".
    protocol_config_version: int = 1

    # ── Admin-authority singleton (A.2) ────────────────────────────────────
    # On-chain replacement for ``POPULIS_ADMIN_PUBKEY_ALLOWLIST`` +
    # ``POPULIS_ADMIN_JWT_SECRET`` trust roots.  When the operator has
    # launched an ``admin_authority_inner.clsp`` singleton, set this
    # to its launcher coin id; the API will surface a deterministic
    # ``state_hash`` on ``/admin/auth/authority`` so admins (and
    # external auditors) can independently verify the on-chain
    # quorum-signed authority state.
    #
    # Phase 2 (this commit): the singleton's state is informational
    # only — the API still gates the admin desk via
    # ``admin_pubkey_allowlist`` env var.  Phase 2.5 wires the
    # singleton state into ``require_admin_jwt`` so live revocation
    # becomes a chain event rather than an env push.
    protocol_admin_authority_launcher_id: Optional[str] = None
    # Comma-separated BLS G1 pubkey hex strings (96 hex chars each)
    # making up the m-of-n rotation quorum that controls the singleton.
    # These are the operator team's COLD keys; distinct from the EVM
    # addresses that drive the admin desk login flow.
    protocol_admin_authority_pubkeys: str = ""
    # Quorum threshold M for rotation spends; 1 ≤ M ≤ |pubkeys|.
    # Defaults to 1 (single-key authority — fine for dev/test).
    protocol_admin_authority_quorum_m: int = 1
    # Monotonic version stamped into the singleton's curried state.
    # Bumped by the operator on every rotation; the puzzle enforces
    # ``new_version > old_version`` (replay protection).
    protocol_admin_authority_version: int = 1

    # ── Admin-authority v2 singleton (Phase 9-Hermes-C) ───────────────────
    # On-chain replacement for the v1 BLS allowlist using CHIP-0043 MIPS
    # composition. Each admin slot holds a OneOfN of personal auth methods
    # (BLS, EIP-712 / MetaMask, passkey, ...) under a protocol-level MofN
    # quorum. Lets admins mix signing methods and add backup keys over time
    # without going through PGT governance.
    #
    # Phase 2-informational-only (current): when the operator launches a
    # v2 singleton and publishes its launcher id + state hashes, the API
    # surfaces them on ``/admin/auth/authority_v2`` so admins and external
    # auditors can independently verify operator config matches on-chain
    # state. Admin desk gating still uses the v1 BLS allowlist.
    #
    # Phase 4-gating-source (future): require_admin_jwt walks the v2
    # singleton lineage at every request and authenticates via the MIPS
    # quorum. EIP-712 / MetaMask admins authenticate without ever issuing
    # a BLS signature.
    #
    # Migration playbook: research/POPULIS_ADMIN_AUTHORITY_V2_DESIGN.md §7.
    protocol_admin_authority_v2_launcher_id: Optional[str] = None
    # 0x-prefixed 32-byte sha256-tree hash of the MIPS m_of_n quorum tree.
    # Computed off-chain via chia-wallet-sdk MIPS bindings; published here
    # so the snapshot endpoint can return the same value the on-chain
    # puzzle has curried.
    protocol_admin_authority_v2_mips_root_hash: Optional[str] = None
    # 0x-prefixed sha256-tree hash of the admins list (each entry is
    # ``(admin_idx, leaves_list, m_within)``). Computed via
    # ``populis_puzzles.admin_authority_v2_driver.compute_admins_hash``.
    protocol_admin_authority_v2_admins_hash: Optional[str] = None
    # 0x-prefixed sha256-tree hash of the pending-ops list. Defaults to
    # the empty-list hash when omitted; bumped whenever a KEY_ADD_PROPOSE
    # / KEY_REMOVE_EMERGENCY adds an entry, or KEY_ADD_ACTIVATE / VETO
    # / KEY_ADD_REMOVE_ACTIVATE removes one.
    protocol_admin_authority_v2_pending_ops_hash: Optional[str] = None
    # Monotonic uint64 stamped into the v2 singleton's curried state.
    # Strictly increases across all 6 spend tags. Defaults to 1; operators
    # migrating from v1 typically set this to v1's authority_version + 1.
    protocol_admin_authority_v2_version: int = 1

    # ── Property-registry singleton (A.4) ─────────────────────────────────
    # On-chain replacement for the off-chain property-uniqueness role
    # of ``MintProposalStore`` (POP-CANON-014).  When the operator has
    # launched a ``property_registry_inner.clsp`` singleton, set this
    # to its launcher coin id; the API surfaces it on the ``/protocol``
    # endpoint so clients can walk the singleton's lineage on
    # coinset.org to enumerate registered properties.
    #
    # Phase 3 (this commit): the singleton is informational; off-chain
    # ``MintProposalStore.create()`` continues to enforce uniqueness.
    # Phase 3.5 (deferred): extend the puzzle's curried state with a
    # sorted-Merkle-tree root and require non-membership proofs at
    # registration time — making duplicate property registrations
    # consensus-impossible.
    protocol_property_registry_launcher_id: Optional[str] = None

    # ── Admin auth ────────────────────────────────────────────────────────
    # Bearer token required by `/admin/deploy/*` and other one-shot operator
    # commands.  When unset, those routes are disabled (return 503) — the
    # safest default for a public endpoint without an explicit operator
    # opt-in.  Generate with `openssl rand -hex 32`.
    admin_token: Optional[str] = None

    # ── Admin Desk (interactive operator UI) ──────────────────────────────
    # The Admin Desk uses a wallet-pubkey allowlist + short-lived JWT
    # instead of the static `admin_token` model.  See
    # `docs/ADMIN_DESK_DESIGN.md` §3 for the full rationale.

    # Comma-separated list of 0x-prefixed pubkeys (or BLS G1 hex) allowed to
    # log in to the admin desk.  When empty, the admin desk routes return
    # 503.  Examples:
    #   POPULIS_ADMIN_PUBKEY_ALLOWLIST=0xabc...,0x123...
    #
    # Phase 2.5: ``admin_records_path`` (below) takes precedence when set.
    # The env var becomes a fallback / break-glass for when the on-chain
    # gating source is unreachable; an operator-facing deprecation timeline
    # lands after the testnet11 dry-run validates the JSON-config path.
    admin_pubkey_allowlist: str = ""

    # Path to a JSON file containing the OPERATOR-EXPANDED admin records
    # (Phase 2.5b-1).  When set, the API:
    #   1. Loads the records at boot.
    #   2. Recomputes ``admins_hash`` from them via the protocol's
    #      canonical hash function and asserts it matches the on-chain
    #      singleton's ``admins_hash`` (sourced from
    #      ``protocol_admin_authority_v2_admins_hash`` env until
    #      Phase 2.5b-2 wires direct coinset.org lookups).
    #   3. Builds the EVM-address allowlist from the JSON's eip712 leaf
    #      metadata; this REPLACES ``admin_pubkey_allowlist`` as the
    #      gating source for ``/admin/*`` routes.
    #
    # The file is ENVIRONMENT-LOCAL — it contains only data that's already
    # public (pubkeys, EVM addresses, hashes); no secrets.  But it MUST
    # match the on-chain state or the API refuses to boot, so treat it
    # as part of the deployment artefact.
    #
    # See ``populis_api.admin_records.AdminRecordsConfig`` for the JSON
    # schema; ``GENESIS_README.md`` shows how to generate this file from
    # a launch wizard run.
    admin_records_path: Optional[str] = None

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
    admin_db_path: str = "./admin_desk.db"

    # ── CORS ──────────────────────────────────────────────────────────────
    cors_origins: str = "http://localhost:4200,http://localhost:5173"

    # ── EIP-712 domain ────────────────────────────────────────────────────
    eip712_name: str = "Populis Protocol"
    # v2 = post POP-CANON-002 audit fix (envelope now binds pool, auth_type,
    # network).  v1 signatures are intentionally NOT accepted.
    eip712_version: str = "2"
    # MUST match EIP712_DOMAIN_CHAIN_ID in populis_puzzles/vault_driver.py.
    eip712_chain_id: int = 1

    # ── DoS hardening (POP-CANON-003 / Strategy 7) ────────────────────────
    # Maximum number of pending challenges in memory at any time.  When the
    # cap is reached, /auth/challenge returns 429 to back off load.
    challenge_store_max_pending: int = 50_000
    # Maximum challenges issued per source IP per minute.
    challenge_per_ip_per_minute: int = 60

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

    def admin_pubkey_allowlist_set(self) -> set[str]:
        """Return the lowercase, normalized set of allowlisted admin pubkeys.

        Hex prefix ``0x`` is preserved if present so callers can match on
        whichever convention they prefer; comparisons should also normalize
        to lower-case.  An empty allowlist disables the admin desk
        (callers handle the 503 path).

        **Phase 2.5 note:** prefer ``effective_admin_allowlist_set`` for
        per-request gating; this method is the legacy/env-var-only path
        retained for the boot validator and as a break-glass fallback.
        """
        raw = (self.admin_pubkey_allowlist or "").strip()
        if not raw:
            return set()
        return {p.strip().lower() for p in raw.split(",") if p.strip()}

    def effective_admin_allowlist_set(self) -> set[str]:
        """Live admin EVM-address allowlist, combining all gating sources.

        Phase 2.5b-1 promotes the on-chain-derived JSON records above
        the env-var legacy path:

        1. **Records JSON (preferred)**: when ``admin_records_path`` is
           set, load + verify against on-chain ``admins_hash`` and
           extract EVM addresses from leaf metadata.  Drift causes a
           ``RuntimeError`` so the operator notices immediately.
        2. **Env var (fallback)**: when the JSON path is unset, fall
           back to ``admin_pubkey_allowlist`` (Phase 2 behaviour).
        3. **Empty**: when neither is set, the admin desk is disabled
           (callers handle 503).

        Note that we INTENTIONALLY do not union the two sets — that
        would let a misconfigured env var smuggle an extra admin past
        the on-chain check.  When records JSON is configured it is the
        SOLE gating source.

        Lazy-loaded + cached by file mtime; an operator who edits the
        JSON file sees the new allowlist on the next request without
        restart (subject to ``get_settings`` cache clearing in tests).
        """
        if self.admin_records_path:
            from .admin_records import get_admin_records_for_settings
            records = get_admin_records_for_settings(self)
            if records is None:
                return set()  # path set but load failed validation already
            return records.eip712_evm_address_set()
        return self.admin_pubkey_allowlist_set()

    def admin_authority_pubkeys_list(self) -> list[bytes]:
        """Return the parsed ordered list of A.2 admin-authority BLS pubkeys.

        Each pubkey is a 48-byte BLS G1 element.  Order matters — the
        on-chain singleton's ``signer_indices`` solution param indexes
        into this list, so any reordering would invalidate every
        rotation signature.

        Returns an empty list when the operator has not configured the
        singleton (callers treat that as "A.2 disabled").

        Raises ValueError if any entry is not 48 bytes after hex decode.
        """
        raw = (self.protocol_admin_authority_pubkeys or "").strip()
        if not raw:
            return []
        out: list[bytes] = []
        for i, hex_str in enumerate(p.strip() for p in raw.split(",") if p.strip()):
            if hex_str.startswith("0x") or hex_str.startswith("0X"):
                hex_str = hex_str[2:]
            try:
                pk = bytes.fromhex(hex_str)
            except ValueError as e:
                raise ValueError(
                    f"protocol_admin_authority_pubkeys[{i}] is not valid hex: {e}"
                )
            if len(pk) != 48:
                raise ValueError(
                    f"protocol_admin_authority_pubkeys[{i}] must be 48 bytes "
                    f"(BLS G1), got {len(pk)}"
                )
            out.append(pk)
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
