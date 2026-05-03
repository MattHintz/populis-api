# Populis Admin Desk — Operations Runbook

> Day-to-day operator guide for the JWT-gated `/admin/*` endpoints.
> For first-time protocol bootstrap (PGT genesis, pool/governance/A.x
> singleton launches), read **`GENESIS_README.md`** first.

The admin desk is the operator-facing UI bolted onto the same
FastAPI process that serves users.  It drives:

1. **Mint-proposal lifecycle** — DRAFT → APPROVED → EXECUTED, with
   on-chain mirroring via the A.1 `mint_proposal_inner.clsp` singleton.
2. **Key rotation + JWT issuance** — wallet-signature login, short-lived
   JWTs, refresh-without-re-sign workflow.
3. **Cross-coin coordination with the on-chain trust roots** — A.2
   admin-authority, A.3 protocol-config, A.4 property-registry.

---

## Auth model at a glance

```
┌───────────────────────────────────────────────────────────────┐
│ POPULIS_ADMIN_TOKEN          (one-shot bearer; genesis only)   │
│   └─▶ /admin/deploy/protocol  /admin/deployment                │
├───────────────────────────────────────────────────────────────┤
│ Wallet allowlist + JWT       (interactive admin desk)          │
│   POPULIS_ADMIN_PUBKEY_ALLOWLIST + POPULIS_ADMIN_JWT_SECRET    │
│   └─▶ /admin/auth/* /admin/mint/* /admin/property/* etc.       │
├───────────────────────────────────────────────────────────────┤
│ A.2 admin-authority singleton (on-chain trust root)            │
│   └─▶ exposed via GET /admin/auth/authority                    │
│       (informational in Phase 2; gating in Phase 2.5)          │
└───────────────────────────────────────────────────────────────┘
```

The two off-chain mechanisms (env-var allowlist + on-chain singleton)
**both run in parallel**.  The allowlist is the live gate; the on-chain
singleton is the auditable, third-party-verifiable canonical source
that Phase 2.5 will switch to.  See `SECURITY.md` §A.2 for the full
migration plan.

---

## Required environment

```bash
# Wallet allowlist — comma-separated 0x EVM addresses or BLS G1 hex.
# Empty = admin desk disabled (returns 503).
POPULIS_ADMIN_PUBKEY_ALLOWLIST=0xabc...,0x123...

# HS256 secret for signing admin JWTs.
# Generate once, persist to .env (POP-CANON-016 forbids per-process
# random secrets in production).
POPULIS_ADMIN_JWT_SECRET=$(openssl rand -hex 32)

# JWT lifetime.  Default 900 (15 minutes).
POPULIS_ADMIN_LOGIN_TOKEN_TTL_SECONDS=900
```

Optional, for the A.2 on-chain singleton mirror:

```bash
POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID=0x...
POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS=0xpubkey1,0xpubkey2,...   # BLS G1 hex
POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M=2
POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION=1
```

When all four are set, `GET /admin/auth/authority` publishes a
deterministic `state_hash` matching what the on-chain singleton
emits.  Auditors can recompute the hash from the singleton's curried
state and refuse to trust the API if they diverge.

---

## Login flow

```
┌──── operator wallet ────┐                ┌──── populis-api ─────┐
│                         │                │                       │
│   1. POST /admin/auth/challenge  ───────▶│  issue nonce + EIP-712│
│      {address, auth_type}                │  typed-data envelope   │
│                                          │                       │
│   ◀───────────────────────────  challenge.typed_data              │
│                                          │                       │
│   2. wallet.signTypedData_v4(typed_data) │                       │
│                                          │                       │
│   3. POST /admin/auth/login   ──────────▶│ verify sig + allowlist │
│      {address, nonce, signature,         │ check + bind authType  │
│       authType, scope: "admin"}          │ (POP-CANON-015)        │
│                                          │                       │
│   ◀──────────────────  {jwt, expires_at, owner}                   │
│                                          │                       │
│   4. Authorization: Bearer <jwt>   ─────▶│ require_admin_jwt:     │
│       (every subsequent request)         │ verify + LIVE re-check │
│                                          │ allowlist (POP-CANON-  │
│                                          │ 012)                   │
│                                          │                       │
│   5. POST /admin/auth/refresh  ─────────▶│ extend session w/o     │
│       (Authorization header)             │ re-signing             │
└──────────────────────────────────────────┴───────────────────────┘
```

Critical security properties:

- **Live allowlist re-check.**  `require_admin_jwt` re-reads the env-var
  allowlist on every request — a removed pubkey loses access immediately,
  even if its JWT hasn't expired (POP-CANON-012).
- **`authType` + `scope` claim binding.**  The login envelope's
  `authType` and `scope` are bound into the JWT and re-checked on every
  request, so a token issued for `scope: "user"` cannot be presented at
  an `/admin/*` endpoint (POP-CANON-015).
- **Failure-mode opacity.**  Login errors are uniform: invalid sig, bad
  nonce, missing allowlist all return identical 401s.

---

## Mint-proposal lifecycle

The off-chain `MintProposalStore` (SQLite) is the live gating source.
Each proposal is *also* mirrored on-chain via the A.1
`mint_proposal_inner.clsp` singleton — a per-proposal launcher coin
whose state machine runs in lock-step with the API.

```
   ┌──── operator (admin) ────┐                    ┌──── chain ────┐
   │                          │                    │                │
   │  POST /admin/mint/propose                      │                │
   │   ▶ DRAFT row created                          │                │
   │   ▶ launcher coin built                        │                │
   │     └──▶ /admin/mint/{id}/publish ─────────────▶ A.1 launcher   │
   │                                                  emitted        │
   │  POST /admin/mint/{id}/cancel                   │ owner-sig      │
   │   ▶ CANCELLED row + tx                          │ DRAFT→CANCELLED│
   │                                                  on-chain        │
   │                                                  + announcement  │
   │                                                  (PROTOCOL_PREFIX │
   │                                                   || msg)        │
   │  POST /admin/mint/{id}/execute                  │ PGT-VOTE bundle│
   │   ▶ EXECUTED row + tx                           │ APPROVED→      │
   │                                                  EXECUTED        │
   └──────────────────────────────────────────────────────────────────┘
```

States (matching `populis_puzzles/mint_proposal_inner.clsp` exactly):

| State | Value | Reachable from | Required signer |
|-------|-------|----------------|-----------------|
| DRAFT | 1 | (initial) | — |
| APPROVED | 2 | DRAFT | `GOV_PUBKEY` |
| CANCELLED | 3 | DRAFT | `OWNER_PUBKEY` |
| EXECUTED | (V2) | APPROVED | (PGT-VOTE bundle, V2) |

Each transition emits a `CREATE_PUZZLE_ANNOUNCEMENT` carrying
`PROTOCOL_PREFIX (0x50) || sha256tree([transition_case, new_state, new_version])`.
Off-chain consumers can index these to rebuild the full
proposal-history without trusting the API.

### Practical workflow

```bash
# 1. Authenticate.
JWT=$(curl -s -X POST http://localhost:8787/admin/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"address\": \"$ADDR\", \"nonce\": \"$NONCE\", \"signature\": \"$SIG\", \"authType\": \"evm\", \"scope\": \"admin\"}" \
  | jq -r .jwt)

# 2. Create a proposal.
curl -s -X POST http://localhost:8787/admin/mint/propose \
  -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"property_id": "PROP-001", "par_value_mojos": 1000000, "royalty_bps": 500, "quorum_threshold": 10}' \
  | jq .

# 3. List drafts.
curl -s http://localhost:8787/admin/mint?state=DRAFT \
  -H "Authorization: Bearer $JWT" | jq .

# 4. Approve / publish to chain.
curl -s -X POST http://localhost:8787/admin/mint/{id}/publish \
  -H "Authorization: Bearer $JWT" | jq .

# 5. Or cancel.
curl -s -X POST http://localhost:8787/admin/mint/{id}/cancel \
  -H "Authorization: Bearer $JWT" | jq .
```

The launcher `id` returned by `propose` IS the on-chain proposal id —
walk it on coinset.org to verify the state machine's history matches
what the API reports.

---

## Property-registry administration

Each new property identifier should be registered on-chain via the
A.4 `property_registry_inner.clsp` singleton **before** any mint
proposal that references it gets approved.  This is what makes the
registry an audit-trail of legitimate property identifiers rather
than just an off-chain database.

The registration spend itself is operator-side (it requires the
`GOV_PUBKEY` curried into the registry singleton), so the API does
not currently expose a one-shot `/admin/property/register` endpoint.
For Phase 3, operators drive registrations directly using the
`property_registry_driver.build_registration_spend` helper from a
trusted shell.

`GET /protocol` surfaces:

- `property_registry_launcher_id` — the singleton's launcher coin id.
- `property_registry_mod_hash` — the canonical mod-hash third parties
  use to identify the singleton's puzzle on-chain.

Phase 3.5 will add a coinset.org-driven indexer + an admin endpoint
that gates new mint-proposal `property_id_canon`s on whether they
match a registered announcement.

---

## Key rotation (A.2 admin-authority singleton)

> Phase 2 status: **on-chain primitive landed; informational only.**
> The env-var allowlist remains the live gate.

When you're ready to rotate keys (compromise, team change, scheduled
hygiene), the recommended workflow is:

1. **Update the env-var allowlist** — this takes effect immediately
   on every API request (POP-CANON-012).  Restart is *not* required.
2. **Bump the on-chain singleton** — spend the
   `admin_authority_inner.clsp` singleton with:
   - `new_allowlist` = updated set of pubkeys
   - `new_quorum_m` (if changing)
   - `new_authority_version = current.AUTHORITY_VERSION + 1` (replay)
   - `signer_indices` = sorted strictly ascending list of indices into
     the *current* allowlist
   - `signatures` = corresponding `AGG_SIG_ME`s
3. **Update env vars** — bump
   `POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION` and
   `POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS` to match.  The
   `state_hash` on `GET /admin/auth/authority` will refresh.

The driver helper `populis_puzzles.admin_authority_driver.build_rotation_spend`
constructs the solution + signing message; pair it with your wallet
signing tool of choice.

---

## Disabling the admin desk

If you need to take the admin surface down temporarily (incident
response, planned maintenance):

1. Set `POPULIS_ADMIN_PUBKEY_ALLOWLIST=` (empty).  Every `/admin/*`
   route that uses `require_admin_jwt` returns 503.
2. **Do not** rotate `POPULIS_ADMIN_JWT_SECRET` casually — every
   active session loses its JWT and admins must re-sign to log back
   in.  Acceptable for incident response, painful otherwise.
3. The public `/admin/auth/authority` endpoint stays up — it's
   informational and reads the on-chain singleton.

---

## Cross-references

- **`SECURITY.md`** — `POP-CANON-012`, `POP-CANON-013`, `POP-CANON-015`,
  `POP-CANON-016`, A.1, A.2 sections.
- **`docs/ADMIN_DESK_DESIGN.md`** — the original architecture doc that
  motivated the JWT model (December 2025).
- **`GENESIS_README.md`** — initial trust-root bootstrap, before any
  of this is meaningful.
- **`../populis_protocol/populis_puzzles/admin_authority_inner.clsp`**
  — canonical source of A.2 enforcement logic.
- **`../populis_protocol/populis_puzzles/mint_proposal_inner.clsp`**
  — canonical source of A.1 state-machine logic.
