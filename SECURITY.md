# Security · Populis API

This document describes the threat model, the audit trail, and the
operator-facing security checklist for `populis_api`.

The API is the trust boundary between user wallets, the coinset.org
chain RPC, and (in admin-desk paths) the operator team's
allowlisted EVM keys.  Anything here that says **"do this in
production"** has a corresponding regression test in `tests/`.

## Threat model

| Asset | Risk | Mitigation |
|---|---|---|
| User vault launcher payment | Faucet drain via spurious registration | `/auth/challenge` rate limited per IP; nonce popped atomically on success (POP-CANON-006) |
| EIP-712 registration envelope | Pool/network/auth_type drift — user wallet display diverges from server intent | Envelope binds `poolLauncherId`, `chiaNetwork`, `authType` (POP-CANON-002 fix) |
| Vault registry memory | Unbounded growth, in-memory append-only | Bounded via TTL + capacity (POP-CANON-007 fix) |
| Faucet UTXO set | Fragmentation grows with `O(N log N)` lookup | Optional consolidation worker, threshold-driven (POP-CANON-008 fix) |
| Faucet spend amount | Documented `faucet_max_spend_mojos` was unenforced | Enforced before signing every spend (POP-CANON-009 fix) |
| Settings cache | Stale `pool_launcher_id` after `/admin/deploy/protocol` redeploy | Manifest write invalidates `get_settings()` cache (POP-CANON-011 fix) |
| Admin desk JWT | Stolen / leaked token | 15-min TTL + memory-only frontend storage; live allowlist re-check on every request (POP-CANON-012 fix) |
| Admin desk allowlist rotation | Revoked admin keeps authority via refresh chain | `require_admin_jwt` re-checks live allowlist; revocation effective on next request (POP-CANON-012 fix) |
| Committee endpoints | Spec/impl drift — over-restrictive auth | `/admin/committee/*` un-gated; PGT-VOTE signature inside the bundle is the authority (POP-CANON-013 fix) |
| `property_id` uniqueness | Case + whitespace bypass to mint two deeds for the same property | `MintProposalStore.create()` canonicalises via `strip().upper()` (POP-CANON-014 fix) |
| Admin login envelope | Future scope-confusion replay | EIP-712 envelope binds `authType` + `scope` (POP-CANON-015 fix) |
| Multi-worker JWT secret | Per-process random secrets cause intermittent 403s | `get_jwt_secret` refuses to start under non-empty allowlist + missing secret; lifespan-time validator (POP-CANON-016 fix) |

Out-of-scope risks (not directly mitigated here):

* Compromise of the coinset.org control plane.  We treat its
  `push_tx`/get_coin_record responses as untrusted "control plane"
  data (POP-CANON-004).  Production deployments should run an
  independent `chia` full node and dual-source confirmation.
* Compromise of a user's wallet.  The user is the root of trust for
  their vault — we cryptographically bind their pubkey to their
  vault but do not protect against client-side signing tools.
* DDoS at the network layer.  Mitigated by upstream CDN / WAF
  (Cloudflare or similar), out of scope for this codebase.

## Audit trail

Three independent canon audits have been run against this codebase.
Each finding is referenced in code comments at the fix site and has
at least one regression test under `tests/`.

| ID | Severity | Class | Status | Where to find the fix |
|---|---:|---|---|---|
| POP-CANON-002 | Med | SIGCOV-1 / Strategy 2 | **fixed** | `evm_auth.py:registration_typed_data` |
| POP-CANON-003 | Med | Strategy 7 | **fixed** | `challenges.py:ChallengeStore` rate limit |
| POP-CANON-004 | Low-Med | TRUTH-1 | acknowledged | Out-of-scope mitigation; see threat model |
| POP-CANON-005 | Low | SIGN-1 | **fixed** | EIP-712 envelope expansion (paired with -002) |
| POP-CANON-006 | Low | LD-1 | **fixed** | `challenges.py:ChallengeStore.pop` |
| POP-CANON-007 | Med | SP-2 / CL-1 | **fixed** | `state.py:VaultRegistry` (TTL + capacity) |
| POP-CANON-008 | Med | CL-1 | **fixed** | `faucet_worker.py:FaucetConsolidationWorker` |
| POP-CANON-009 | Low-Med | Documentation drift | **fixed** | `faucet.py:select_coin` enforces `faucet_max_spend_mojos` |
| POP-CANON-010 | Low | LD-2 | **fixed** | `coinset_client.py:get_coin_records_by_puzzle_hash` `limit` |
| POP-CANON-011 | Low-Med | SN-3 | **fixed** | `admin.py:deploy_protocol` invalidates `get_settings()` cache |
| POP-CANON-012 | **High** | AUTHZ / TRUTH-1 | **fixed** | `admin_auth.py:require_admin_jwt` re-checks allowlist |
| POP-CANON-013 | Med | AUTHZ spec drift | **fixed** | `mint_endpoints.py:/admin/committee/*` un-gated |
| POP-CANON-014 | Med | SP-2 / Data integrity | **fixed** | `mint_proposals.py:MintProposalStore.create` canonicalises |
| POP-CANON-015 | Low | SIGCOV-1 future-proofing | **fixed** | `admin_auth.py:ADMIN_LOGIN_TYPES` binds `authType`+`scope` |
| POP-CANON-016 | Info | Ops | **fixed** | `admin_auth.py:validate_admin_config_at_startup` |
| POP-CANON-A3  | Med | Trust roots | **on-chain primitive landed** | `populis_protocol/populis_puzzles/protocol_config_inner.clsp` + `populis_api/populis_api/protocol_config.py` |
| POP-CANON-A2  | High | AUTHZ trust roots | **on-chain primitive landed** | `populis_protocol/populis_puzzles/admin_authority_inner.clsp` + `populis_api/populis_api/admin_authority.py` |
| POP-CANON-A4  | Med | Data integrity / SP-2 | **on-chain primitive landed** | `populis_protocol/populis_puzzles/property_registry_inner.clsp` + `populis_api/populis_api/singletons.py` |
| POP-CANON-A1  | Med | Data integrity / state machine | **on-chain primitive landed** | `populis_protocol/populis_puzzles/mint_proposal_inner.clsp` + `populis_api/populis_api/singletons.py` |
| POP-CANON-017 | Med | AUTHZ / quorum-dilution | **fixed** | `admin_authority_inner.clsp` rejects `[X, X, Y]` allowlists via `has-no-duplicates`; driver preflight in `admin_authority_driver.py` |
| POP-CANON-018 | Med (×4 systemic) | AUTHZ / driver-vs-puzzle drift | **fixed** | `is-size-bls-g1` + `all-bls-g1-pubkeys` in `utility_macros.clib`, asserted in all four A.x puzzles |
| POP-CANON-019 | Med | SP-2 / Data integrity | **fixed** | `pool_singleton_inner.clsp:spend_settlement` rejects duplicate `deed_releases` via `has-no-duplicate-firsts` |
| POP-CANON-020 | Med | SP-2 / cross-coin coordination | **fixed** | `pool_singleton_inner.clsp:spend_generate_offer` emits the `CREATE_PUZZLE_ANNOUNCEMENT` that `vault_singleton_inner.clsp:spend_accept_offer` asserts |
| POP-CANON-021 | Low-Med | TRUTH-1 / cross-layer drift | **fixed** | `admin_auth.py:validate_admin_config_at_startup` raises on EVM↔BLS drift; `/admin/auth/authority` carries `phase`/`gating_source`/`informational_only` disclaimer |

Full audit narratives:

* `research/CANON_POPULIS_API_AUDIT_2026_04_26.md` — first pass (POP-CANON-002…006).
* `research/CANON_POPULIS_DEEP_AUDIT_2026_04_26.md` — second pass (POP-CANON-007…011).
* `research/CANON_POPULIS_ADMIN_DESK_AUDIT_2026_04_28.md` — admin desk pass (POP-CANON-012…016).
* `research/CANON_POPULIS_TRANSPARENCY_SINGLETONS_2026_05_03.md` — transparency-singletons pass (POP-CANON-017…021); all five PoC-confirmed findings fixed in the same commit window.

The `populis_protocol` Chialisp puzzle suite has its own audit at
`populis_protocol/docs/SECURITY_AUDIT_2026_04_19.md` (14 findings).

## On-chain migrations (A.x series)

The off-chain → on-chain migration plan converts API-level trust roots
into Chialisp singletons.  Each phase ships in three layers
(puzzle → driver → API integration) and is tracked under
``A.<n>`` rather than ``POP-CANON-<nnn>`` because they're proactive
hardening rather than audit findings.

### A.3 — Protocol-config singleton (Phase 1: shipped)

**On-chain primitive**: `protocol_config_inner.clsp` is a singleton
whose curried state holds `(POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID,
NETWORK_ID, CONFIG_VERSION)`.  Updates require an `AGG_SIG_ME` signature
from a curried `GOV_PUBKEY` and must strictly increment
`CONFIG_VERSION` (replay protection).  Every update spend emits a
`CREATE_PUZZLE_ANNOUNCEMENT` carrying the deterministic
`content_hash = sha256tree([pool, gov_tracker, network, version])`.

**Off-chain integration**:
- `/protocol` exposes `protocol_config_hash`, `protocol_config_launcher_id`,
  `protocol_config_version` so frontends and external auditors can
  independently verify the operator's config matches on-chain reality.
- `protocol_config.py:build_snapshot` is the single source of truth for
  computing the off-chain content hash; the matching Chialisp `defun`
  is regression-tested in `populis_protocol/tests/test_protocol_config.py`
  via `test_content_hash_matches_on_chain`.

**Closes**: hardens `POP-CANON-002` and `POP-CANON-005` by giving
operators a way to make their pool/governance/network config
publicly verifiable rather than asking users to trust an env var.

**Phase 1.5 (deferred)**: an in-API singleton-lineage indexer that
walks coinset.org → parses the latest spent ancestor's puzzle reveal
→ recovers the curried state directly.  Until that lands, the API
trusts its own settings + manifest as the canonical source for the
four config fields; the on-chain singleton makes that trust auditable
but does not yet *replace* it.

### A.2 — Admin-authority singleton (Phase 2: shipped)

**On-chain primitive**: `admin_authority_inner.clsp` is a singleton
whose curried state is `(ALLOWLIST, QUORUM_M, AUTHORITY_VERSION)`,
where `ALLOWLIST` is an ordered list of BLS G1 pubkeys belonging to
the operator's cold-key team.  Rotation requires *m* ≥ `QUORUM_M`
valid `AGG_SIG_ME` signatures from indices into the *current*
allowlist, plus a strictly-increasing `AUTHORITY_VERSION` (replay
protection).  Each rotation spend emits a `CREATE_PUZZLE_ANNOUNCEMENT`
carrying the deterministic
`state_hash = sha256tree([allowlist, quorum_m, version])`.

The puzzle enforces, on-chain:
- `1 ≤ new_quorum_m ≤ len(new_allowlist)` (sane quorum bounds).
- `signer_indices` is sorted strictly ascending — no duplicate signers.
- Every signer index is in range `[0, len(current.allowlist) - 1]`.
- `len(signer_indices) ≥ current.QUORUM_M` (quorum enforcement).
- `new_authority_version > current.AUTHORITY_VERSION` (replay).
- `my_amount` is odd (singleton convention).

**Off-chain integration**:
- New `GET /admin/auth/authority` endpoint exposes the snapshot:
  `{enabled, launcher_id, allowlist_pubkey_hashes, quorum_m,
  authority_version, state_hash}`.  Public, unauthenticated — any
  third party can fetch it and verify against on-chain state.
- `admin_authority.py:build_admin_authority_snapshot` is the single
  source of truth for the off-chain state hash; cross-repo contract
  with `populis_protocol/populis_puzzles/admin_authority_driver.py`
  (regression-tested on both sides).
- New env vars (operator opt-in):
  - `POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID` — singleton coin id.
  - `POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS` — comma-separated BLS hex.
  - `POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M` — quorum threshold.
  - `POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION` — monotonic version.

**Closes**: foundation for closing `POP-CANON-012` cleanly (live
revocation = on-chain rotation spend rather than env push) and
subsuming `POP-CANON-016` (the JWT secret becomes optional — every
admin request can be re-verified against the on-chain singleton state
once Phase 2.5 lands).

**Phase 2.5b (shipped — chain-verified records JSON)**: replaces
`admin_pubkey_allowlist_set()` with `effective_admin_allowlist_set()`
across `require_admin_jwt`, the challenge endpoint, the login
endpoint, and the JWT-secret guard.  When `POPULIS_ADMIN_RECORDS_PATH`
is set, the API at boot:

1. Loads the operator-supplied admin records JSON.
2. Recomputes its `admins_hash` via the protocol's canonical
   `compute_admins_hash` (so the API and chain cannot drift on
   what an admin records list hashes to).
3. Verifies the result matches `POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH`
   (which itself reflects on-chain singleton state; Phase 2.5b-2
   replaces this env step with a direct coinset.org fetch).
4. Cross-checks the JSON's `launcher_id` against
   `POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID` to catch
   deployment mix-ups.
5. Builds the EVM-address allowlist from leaf metadata; that's
   what `require_admin_jwt` consults at request time.

Drift in any check → API refuses to boot.  POP-CANON-021's
transparency-cardinality check is automatically skipped in records-
path mode because the JSON encodes the EVM↔BLS mapping per-leaf.

The two paths are NEVER unioned: when records JSON is configured,
`POPULIS_ADMIN_PUBKEY_ALLOWLIST` is ignored, so an attacker who
gains env-var write access cannot smuggle an admin past the on-chain
hash check.

**Phase 2.5c (shipped — deterministic leaf-hash service)**:
`POST /admin/auth/eip712/compute_leaf_hash` (no auth) computes the
canonical Eip712Member leaf hash for a given secp256k1 pubkey +
network.  The launch wizard calls this when an operator opts to use
their connected EVM wallet as the genesis admin.  Pure deterministic
computation; verifiable by anyone running the same Python helper.

**Phase 2.5b-2 (deferred)**: replace
`POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH` with a direct
coinset.org fetch at API boot, so the chain becomes the single
source of truth (no operator-supplied env step in the trust path).

**Closes** (now): `POP-CANON-012` is fully addressed for records-
path deployments — revoking an admin is a chain rotation spend +
JSON regeneration + API restart.  The env-push path remains as a
fallback for pre-Phase-2.5 deployments.

### A.4 — Property-registry singleton (Phase 3: shipped)

**On-chain primitive**: `property_registry_inner.clsp` is a singleton
whose curried state is `(SELF_MOD_HASH, GOV_PUBKEY, REGISTRY_VERSION)`.
Each registration spend:

  * Requires an `AGG_SIG_ME` from `GOV_PUBKEY` over a message that
    binds BOTH the canonicalised property id AND the new version slot
    (replay-protected per-property + per-version).
  * Bumps `REGISTRY_VERSION` by exactly 1 (no skipping; version
    doubles as registration index).
  * Recreates the singleton with the new version curried in.
  * Emits `CREATE_PUZZLE_ANNOUNCEMENT` with body
    `PROTOCOL_PREFIX (0x50) || property_id_canon`.  This is the
    permanent on-chain record; A.1's `mint_proposal_inner` ASSERTs
    this exact announcement during DRAFT → APPROVED transitions
    (cross-coin coordination — V2 work).

The puzzle enforces, on-chain:
- `is-size-b32 property_id_canon` (32-byte canonical form).
- `new_registry_version = REGISTRY_VERSION + 1` (no skipping).
- `my_amount` is odd (singleton convention).

**Off-chain integration**:
- `singletons.py:build_singletons_snapshot` exposes the registry
  launcher id + uncurried `property_registry_inner.clsp` mod-hash on
  the `/protocol` endpoint so clients can locate the singleton on
  coinset.org.
- `property_registry_driver.canonicalise_property_id` is the canonical
  human-id → bytes32 conversion: `strip().upper().sha256()`.  The
  off-chain `MintProposalStore.create()` (POP-CANON-014) uses the
  *same* canonicalisation, so the off-chain and on-chain registries
  agree on identity.
- New env var: `POPULIS_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID`.

**Closes**: foundation for closing `POP-CANON-014` cleanly once
Phase 3.5 lands.

**Phase 3.5 (deferred)**: extend the puzzle's curried state with a
sorted-Merkle-tree root and require non-membership proofs at
registration time, making duplicate property registrations
consensus-impossible.  Until then, off-chain
`MintProposalStore.create()` continues to enforce uniqueness; the
on-chain registry is auditable but not yet *replaceable*.

### A.1 — Mint-proposal singleton (Phase 3: shipped)

**On-chain primitive**: `mint_proposal_inner.clsp` is a *per-proposal*
singleton (each mint proposal is its own launcher coin) implementing
the state machine

```
  DRAFT  ──gov-sig──▶  APPROVED
     │
     │ owner-sig
     ▼
  CANCELLED
```

Curried state:
- `SELF_MOD_HASH` (self-recurry)
- `OWNER_PUBKEY`, `GOV_PUBKEY` — BLS G1
- `PROPOSAL_DATA_HASH` — bytes32 sha256tree of `(property_id_canon,
  par_value_mojos, royalty_bps, quorum_threshold)`.  Stored as a hash
  to avoid bloating the curried state; the full data is published
  off-chain at launch time and re-derivable from the launcher coin's
  spend bundle.
- `PROPOSAL_STATE` — `1=DRAFT | 2=APPROVED | 3=CANCELLED`
- `STATE_VERSION` — monotonic uint (replay-protected).

Each transition emits per-transition `AGG_SIG_ME` (gov for APPROVE,
owner for CANCEL), `CREATE_COIN` recurrying with the new state, a
`CREATE_PUZZLE_ANNOUNCEMENT` carrying
`PROTOCOL_PREFIX || sha256tree([transition_case, new_state, new_version])`,
and `ASSERT_MY_AMOUNT`.

The puzzle enforces, on-chain:
- `new_state_version > STATE_VERSION` (replay).
- `PROPOSAL_STATE == DRAFT` (V1 only allows DRAFT-origin transitions;
  V2 adds APPROVED → EXECUTED + governance-cancel).
- `transition_case ∈ {0x61 'a', 0x63 'c'}` (unknown transitions raise).

**Off-chain integration**:
- `singletons.py:build_singletons_snapshot` exposes the uncurried
  `mint_proposal_inner.clsp` mod-hash on the `/protocol` endpoint so
  clients can identify mint-proposal singletons by uncurrying and
  comparing.
- `mint_proposal_driver.compute_proposal_data_hash` is the canonical
  off-chain ↔ on-chain content commitment.

**Closes**: foundation for closing `POP-CANON-013` cleanly once
Phase 3.5 lands.

**Phase 3.5 (deferred)**:
- `APPROVED → EXECUTED` transition gated by `ASSERT_COIN_ANNOUNCEMENT`
  from the actual PGT-driven mint (cross-coin coordination with the
  governance singleton).
- `APPROVED → CANCELLED` via governance (with cooldown / quorum).
- A coinset.org indexer that walks each mint-proposal singleton's
  lineage to replace `MintProposalStore` as the gating source for
  `/admin/mints/*` endpoints.

## Operator deployment checklist

Before pointing the API at real money:

* **`POPULIS_FAUCET_MASTER_SK_HEX`** is set to the faucet's master BLS
  key (32 bytes hex).  Without this the API runs in "no faucet"
  mode and `/vault/register/*` returns 503.
* **`POPULIS_ADMIN_PUBKEY_ALLOWLIST`** is set to the comma-separated
  list of operator EVM addresses authorised to drive the admin desk.
  An empty value disables the admin desk (and its endpoints all 503).
* **`POPULIS_ADMIN_JWT_SECRET`** is set to ≥32 bytes of hex entropy
  whenever the allowlist is non-empty.  The lifespan validator
  (POP-CANON-016) refuses to boot otherwise — there is no silent
  random-secret fallback in production.  Generate with:

      python -c "import secrets; print(secrets.token_hex(32))"

* **`POPULIS_FAUCET_CONSOLIDATION_ENABLED=true`** under sustained
  registration load.  The consolidation worker keeps faucet UTXO
  fragmentation bounded (POP-CANON-008).
* **`POPULIS_PROTOCOL_CONFIG_LAUNCHER_ID`** (optional, A.3)  — set this
  to the launcher coin id of your `protocol_config_inner.clsp`
  singleton once it's been deployed.  The API will then surface the
  launcher id alongside the deterministic `protocol_config_hash` so
  third parties can verify your published config against on-chain
  state.
* **`POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID`** (optional, A.2) —
  set this to the launcher coin id of your `admin_authority_inner.clsp`
  singleton once deployed.  Pair with `POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS`
  (comma-separated BLS G1 hex), `POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M`,
  and `POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION` so the API publishes the
  matching `state_hash` on `/admin/auth/authority`.
* **`POPULIS_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID`** (optional, A.4) —
  set this to the launcher coin id of your
  `property_registry_inner.clsp` singleton once deployed.  The API
  surfaces it on `/protocol` so off-chain consumers can walk the
  singleton's lineage on coinset.org and rebuild the registered-
  property set from the emitted announcements.  No companion env vars
  are needed for V1 — the registry's allowlist is just the curried
  `GOV_PUBKEY`, which lives on-chain.
* **`POPULIS_CORS_ORIGINS`** is set to the exact frontend origin(s);
  don't rely on the dev-mode `127.0.0.1`/`localhost` regex in prod.
* **TLS termination** at the reverse proxy.  The API itself never
  speaks TLS — it expects a CDN/proxy in front.

## Reporting a vulnerability

Email `matthewshintz@tuta.com` with subject `populis-api security`
and we will respond within 72 hours.  Please do not open public
GitHub issues for security-relevant reports.

If your finding has the same shape as one of the existing canon
audits (rate-limit bypass, signature coverage drift, snapshot drift,
ops misconfiguration), include a Stage-1 falsifier as a single
self-contained pytest, in the style of
`tests/test_pop_canon_012_refresh_revocation.py`.  This is the
fastest path to a fix.
