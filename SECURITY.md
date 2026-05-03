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

Full audit narratives:

* `research/CANON_POPULIS_API_AUDIT_2026_04_26.md` — first pass (POP-CANON-002…006).
* `research/CANON_POPULIS_DEEP_AUDIT_2026_04_26.md` — second pass (POP-CANON-007…011).
* `research/CANON_POPULIS_ADMIN_DESK_AUDIT_2026_04_28.md` — admin desk pass (POP-CANON-012…016).

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

### A.2 — Admin-authority singleton (planned)

Replace `POPULIS_ADMIN_PUBKEY_ALLOWLIST` env var + `POPULIS_ADMIN_JWT_SECRET`
with an on-chain authority coin that admins must spend to prove
membership.  Will close `POP-CANON-012` cleanly (live revocation =
chain event, not config push) and subsume `POP-CANON-016` (no JWT
secret needed if every request proves authority via signature + coin
existence).

### A.1 + A.4 — Mint-proposal + property-registry singletons (planned)

Replace the SQLite-backed `MintProposalStore` with an on-chain state
machine, gated by a property-registry singleton whose child-coin
emission per `property_id_canon` makes duplicate-property minting
consensus-impossible.  Will close `POP-CANON-013` and `POP-CANON-014`
in one move.

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
