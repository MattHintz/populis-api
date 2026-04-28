# Populis Admin Desk — Design Document

*Status: DRAFT — Step A.1 deliverable*
*Author: Cascade (with Matthew Hintz)*
*Date: 2026-04-28*
*Cross-references: `populis_protocol/docs/GOVERNANCE_V2_DESIGN.md`, `populis_protocol/docs/STRUCTURAL_OUTLINE.md`*

---

## 1. Purpose

The Admin Desk is the human-facing operator surface for Populis Protocol mints. It is the analogue of Solslot's `admin-property-update` component, redesigned for Populis's **mint-via-governance** flow.

Where Solslot's admin UI **edits an off-chain database row** for an already-minted property, the Populis Admin Desk **proposes a new on-chain mint**, which is then approved by the protocol's governance committee (PGT holders, gated by Quorum DID) before the deed singleton actually launches.

Three actors:

| Actor | Wallet | Role |
|---|---|---|
| **Operator** | Allowlisted pubkey | Drafts mint proposals, monitors lifecycle, triggers execution |
| **Committee member** | PGT holder (any) | Reviews open proposals, votes by locking PGT |
| **Buyer** | Any | Once the deed launches with `mint_offer_delegate` as eve, can purchase via `purchase_payment.clsp` |

The Admin Desk serves the first two actors. Buyer flow is out of scope for Step A (already covered by the existing portal `vault` page + future marketplace work).

---

## 2. Architecture overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         populis_portal (Angular)                         │
│                                                                          │
│   /admin (guard: admin-auth)                                             │
│   ├── /admin              dashboard: my proposals + committee summary    │
│   ├── /admin/mint/new     reactive form: deed metadata fields            │
│   ├── /admin/mint         list view: my proposals + status               │
│   ├── /admin/mint/:id     detail view: tally, lifecycle, actions         │
│   └── /admin/committee    committee voter view (PGT holders only)        │
│                                                                          │
│   admin.service.ts ─────────┐                                            │
└─────────────────────────────┼────────────────────────────────────────────┘
                              │ JWT bearer in Authorization header
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        populis_api (FastAPI)                             │
│                                                                          │
│   /admin/auth/challenge       POST  → nonce + EIP-712 envelope           │
│   /admin/auth/login           POST  → JWT (15-min TTL)                   │
│   /admin/auth/refresh         POST  → new JWT                            │
│                                                                          │
│   /admin/mint/propose         POST  → draft proposal id                  │
│   /admin/mint                 GET   → list (filter: my / open / all)     │
│   /admin/mint/{id}            GET   → detail (lifecycle, vote tally)     │
│   /admin/mint/{id}/publish    POST  → on-chain proposal opened           │
│   /admin/mint/{id}/execute    POST  → mint executed (post-deadline)      │
│   /admin/mint/{id}/cancel     POST  → operator-side cancel (DRAFT only)  │
│                                                                          │
│   /admin/committee/proposals  GET   → open proposals across all admins   │
│   /admin/committee/vote       POST  → submit committee PGT-vote bundle   │
│                                                                          │
│   pending_mint_proposals (SQLite, WAL mode)                              │
└──────────────────────────────────────────────────────────────────────────┘
                              │
                              │ existing protocol_deployment.py + drivers
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         populis_protocol                                 │
│                                                                          │
│   smart_deed_inner.clsp        deed metadata curry                       │
│   mint_offer_delegate.clsp     eve inner puzzle for fresh deeds          │
│   singleton_launcher_with_did.clsp  DID-approved singleton launcher      │
│   quorum_did_inner.clsp        receives MINT message, announces phs      │
│   governance_singleton_inner.clsp   proposal tracker, vote tally         │
│   pgt_governance_inner.clsp    PGT CAT inner: PROPOSE / VOTE modes       │
└──────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                        coinset.org push_tx
```

---

## 3. Authentication model

### 3.1 Why not the existing `POPULIS_ADMIN_TOKEN`?

The existing `/admin/*` endpoints are protected by a static bearer token from env (`POPULIS_ADMIN_TOKEN`). That model is appropriate for **single-operator deployment commands** (the deployer types it once at the CLI), but breaks down for a multi-operator interactive UI:

- A static token shared between admins gives each admin full power, with no per-action attribution.
- Browser localStorage of the token is a phishing target.
- Token rotation requires every admin to update their config simultaneously.

### 3.2 Wallet-signed JWT

The Admin Desk uses **wallet-pubkey allowlist + short-lived JWT**:

1. Client requests a nonce from `POST /admin/auth/challenge` (rate-limited).
2. Client signs the EIP-712 envelope `PopulisAdminLogin(address owner, bytes32 nonce, uint256 issuedAt)` with the operator's wallet (EVM via wagmi, BLS via portal's `chia-wallet.service`).
3. Client POSTs `{ owner, nonce, signature }` to `/admin/auth/login`.
4. Server:
   a. Recovers pubkey from signature.
   b. Validates pubkey is in `POPULIS_ADMIN_PUBKEY_ALLOWLIST` (env: comma-separated 0x-prefixed pubkeys).
   c. Pops the nonce atomically (replay protection).
   d. Issues a 15-min JWT (HS256, secret = `POPULIS_ADMIN_JWT_SECRET`).
5. Client stores JWT in memory only (NOT localStorage). Refresh via `/admin/auth/refresh` while session active.

**JWT claims:**
```json
{
  "sub": "<owner_pubkey_hex>",
  "auth_type": "evm" | "chia_bls",
  "iat": <unix>,
  "exp": <unix + 900>,
  "scope": "admin"
}
```

**Allowlist storage** (Step A): env var (`POPULIS_ADMIN_PUBKEY_ALLOWLIST`).
Rotation works without an API restart: `get_settings` re-reads on each cache miss,
and `require_admin_jwt` re-checks live membership on every request
(POP-CANON-012 fix).  A subject removed from the allowlist immediately
loses authority on the next `/admin/*` request — even if their JWT is
still cryptographically valid under the unchanged secret.

**Allowlist storage** (future): on-chain registry singleton (the `admin_registry_inner.clsp` from earlier sketches) for trustless rotation. Out of scope for Step A.

### 3.3 The bearer-token mechanism stays

`/admin/deploy/protocol` (one-shot deployment) keeps using `POPULIS_ADMIN_TOKEN`. The two auth modes coexist; routes choose explicitly via dependency.

### 3.4 Threat model

| Threat | Mitigation |
|---|---|
| Stolen JWT | 15-minute TTL + memory-only storage; allowlist re-check on every request immediately revokes a stolen JWT once the operator rotates the allowlist (POP-CANON-012). |
| Replay of login | Nonce popped atomically on login |
| Allowlist tampering | Env var, server-side; pubkeys hex-validated on parse |
| MITM of login envelope | EIP-712 chainId binding + HTTPS only in production |
| Cross-action confused-deputy | Each mint action is itself signed (see §6) — JWT alone insufficient to publish |

---

## 4. On-chain commitments

The Admin Desk's job is to fill in the **deed metadata** that becomes curried parameters of `smart_deed_inner.clsp`. Off-chain metadata (description, photos, square footage…) is stored in the API database keyed by `PROPERTY_ID` — same pattern as Solslot but the on-chain commitment is intentionally minimal.

### 4.1 On-chain fields (curried into the deed)

| `smart_deed_inner` curry param | Source | Format | Validator |
|---|---|---|---|
| `SINGLETON_STRUCT` | auto | (mod_hash, launcher_id, launcher_puzhash) | derived |
| `PROTOCOL_DID_PUZHASH` | manifest | bytes32 | manifest |
| `PAR_VALUE` | **operator input** | uint64 mojos | `0 < x ≤ 2^63 - 1` |
| `ASSET_CLASS` | **operator input** | bytes ≤ 32 | regex `^[A-Z0-9-]{1,32}$` |
| `PROPERTY_ID` | **operator input** | bytes ≤ 64 | regex `^[A-Za-z0-9._-]{1,64}$`, unique |
| `JURISDICTION` | **operator input** | bytes ≤ 32 | ISO-style `^[A-Z]{2}(-[A-Z0-9]+)*$` |
| `ROYALTY_PUZHASH` | **operator input** | bytes32 | hex32 |
| `ROYALTY_BPS` | **operator input** | uint16 | `0 ≤ x ≤ 10000` |
| `POOL_SINGLETON_MOD_HASH` | manifest | bytes32 | manifest |
| `P2_POOL_MOD_HASH` | manifest | bytes32 | manifest |
| `P2_VAULT_MOD_HASH` | manifest | bytes32 | manifest |

**Six operator-input fields. Two are integers, four are short strings. That's the entire on-chain commitment — by design.**

### 4.2 Off-chain fields (stored in API DB)

Linked to the on-chain mint by `(launcher_id, property_id)` after launch. Added in a separate `property_metadata` table; not gated by governance.

| Field | Type | Why off-chain |
|---|---|---|
| `description` | text | Marketing copy, mutable |
| `street_address` | text | PII / legal |
| `city`, `state`, `zip_code` | text | PII / legal |
| `lat`, `lng` | float | Display only |
| `bedrooms`, `bathrooms`, `square_footage`, `year_built` | int | Verifiable from public records, not protocol-relevant |
| `images` | array<url> | Bandwidth |
| `documents` | array<{title,url}> | Hash committed via `REMARK` if needed (future) |
| `matterport_url`, `neighborhood` notes | text | Display only |

The on-chain `PROPERTY_ID` is the foreign-key link; verifying off-chain metadata is a buyer's responsibility (e.g., via a hash committed via REMARK). Step A stores raw values; future work can add committed-hash variant.

---

## 5. Mint proposal lifecycle

```
       ┌──────────┐
       │  DRAFT   │  operator created the proposal in API,
       └─────┬────┘  not yet published on-chain
             │
             │  POST /admin/mint/{id}/publish
             ▼
       ┌──────────┐
       │ PROPOSED │  on-chain governance proposal opened (PGT lock).
       └─────┬────┘  Tracker singleton state = (proposal_hash, deadline).
             │
             │  committee members spend PGT in VOTE mode.
             │  /admin/committee/vote forwards their bundles.
             ▼
       ┌──────────┐
       │  VOTING  │  vote_tally < quorum AND now < deadline.
       └─────┬────┘
             │
   ┌─────────┴───────────┐
   │                     │
   ▼                     ▼
 ┌──────┐             ┌──────┐
 │PASSED│             │FAILED│  deadline reached, quorum not met.
 └──┬───┘             └──┬───┘  /admin/mint/{id}/expire clears tracker.
    │                    │
    │  POST .../execute  │  proposal stays in FAILED, no further action.
    ▼                    ▼
 ┌────────┐
 │EXECUTED│  EXECUTE_MINT spend: tracker → DID → launcher → deed singleton
 └────┬───┘
      │
      │  coinset confirms
      ▼
 ┌──────┐
 │MINTED│  deed launcher_id + spend_bundle_id persisted; off-chain
 └──────┘  metadata table populated with property details.
```

Each transition is a row update in `pending_mint_proposals`, with the SpendBundle JSON stashed for audit.

---

## 6. REST API surface

All `/admin/mint/*` and `/admin/auth/refresh` require `Authorization: Bearer <jwt>` (the JWT issued by `/admin/auth/login`). `/admin/auth/challenge` and `/admin/auth/login` are unauthenticated (the login itself is the auth event).

### 6.1 Auth endpoints

#### `POST /admin/auth/challenge`
Rate-limited: 6 / minute / IP.
```json
// Request
{ "owner": "0xABC…", "auth_type": "evm" }

// Response
{
  "nonce": "0x7e3f…",
  "expires_at": 1714345200,
  "typed_data": {
    "domain": { "name": "Populis Protocol", "version": "1", "chainId": 1 },
    "types": {
      "PopulisAdminLogin": [
        { "name": "owner",    "type": "address" },
        { "name": "nonce",    "type": "bytes32" },
        { "name": "issuedAt", "type": "uint256" }
      ]
    },
    "primaryType": "PopulisAdminLogin",
    "message": { "owner": "0xABC…", "nonce": "0x7e3f…", "issuedAt": 1714345200 }
  }
}
```

#### `POST /admin/auth/login`
```json
// Request
{ "owner": "0xABC…", "nonce": "0x7e3f…", "signature": "0x…" }

// Response
{ "jwt": "eyJ…", "expires_at": 1714346100, "owner": "0xABC…" }
```

Errors:
- `401` — signature invalid / pubkey mismatch
- `403` — pubkey not in allowlist
- `404` — nonce not found / already consumed
- `429` — rate-limited

#### `POST /admin/auth/refresh`
```json
// Request: empty body, JWT in header
// Response
{ "jwt": "eyJ…", "expires_at": <new exp> }
```

### 6.2 Mint proposal endpoints

#### `POST /admin/mint/propose`
Creates a DRAFT proposal. Does NOT touch chain.
```json
// Request
{
  "par_value": 1000000000,                  // mojos
  "asset_class": "RWA-RE-RES",
  "property_id": "US-TX-Travis-1234",
  "jurisdiction": "US-TX-Travis",
  "royalty_puzhash": "0xABC…",
  "royalty_bps": 200,
  "off_chain_metadata": {                   // optional — stored as JSON blob
    "description": "...", "street_address": "..."
    /* see §4.2 */
  }
}

// Response
{
  "id": "mp_01HXYZ…",
  "state": "DRAFT",
  "computed": {
    "smart_deed_inner_puzhash": null,
    "eve_inner_puzhash": null,
    "deed_full_puzhash": null,
    "proposal_hash": null
  },
  "created_at": 1714345200
}
```

> **Schema note (Step A.2 implementation discovery):**
> All four computed hashes depend on the launcher coin id, which is
> only chosen when the operator picks a faucet coin to fund the
> launcher at publish time.  The `SINGLETON_STRUCT` curried into
> `smart_deed_inner` carries `launcher_id`, so every downstream
> hash inherits that dependency.  DRAFT carries metadata only; the
> four computed fields flip from `null` → `bytes32` atomically when
> `/admin/mint/{id}/publish` succeeds.

The `computed.proposal_hash` is what governance tracks. It is `sha256tree(deed_full_puzhash)` per `quorum_did_inner.clsp`'s expected message.

#### `GET /admin/mint`
Query params: `?state=PROPOSED,VOTING&owner=me|all`
```json
[
  { "id": "mp_…", "state": "VOTING", "par_value": …, "asset_class": …,
    "vote_tally": 234500, "quorum": 500000, "deadline": 1714400000, … },
  …
]
```

#### `GET /admin/mint/{id}`
Full detail including computed hashes, on-chain coin ids when available, vote tally history, off-chain metadata.

#### `POST /admin/mint/{id}/publish`
DRAFT → PROPOSED. Server:
1. Fetches the operator's PGT coin balance (or expects an attached PGT spend bundle if proposer locking is operator-side).
2. Builds the proposal-tracker spend with `bill_op = MINT, proposal_hash = computed.proposal_hash, deadline = now + voting_window`.
3. Builds the operator's PGT lock spend (PROPOSE mode = first vote).
4. Aggregates and pushes via coinset.
5. Stores `proposal_tracker_coin_id`, `pgt_lock_coin_id`, `bundle_id`, `published_at`.

Returns updated proposal. Errors: `409` if not DRAFT, `503` if quorum tracker singleton not deployed, `502` if push_tx rejected.

#### `POST /admin/mint/{id}/execute`
PASSED → EXECUTED. Server:
1. Validates `now > deadline` and `vote_tally ≥ quorum` from on-chain state.
2. Builds the EXECUTE_MINT spend: tracker → SEND_MESSAGE → quorum_did → CREATE_PUZZLE_ANNOUNCEMENT → launcher → deed singleton creation.
3. Funds the launcher coin from a configured operator XCH source (env var or wallet co-spend — Step A.5 will pick the simpler path).
4. Pushes the bundle.
5. On confirm, transitions to MINTED and populates `property_metadata` table.

#### `POST /admin/mint/{id}/cancel`
DRAFT → CANCELED. No on-chain effect; just cleans up the DB row.

### 6.3 Committee endpoints

> **Auth note (POP-CANON-013):** Both committee endpoints are
> deliberately **NOT** gated by `require_admin_jwt`.  Committee
> voting is open to any PGT holder — locking it behind the admin
> allowlist would conflate "operator desk authority" (an internal
> capability) with "PGT-weighted governance" (a token-holder
> capability), breaking decentralised governance.

#### `GET /admin/committee/proposals`
**Public read.** Returns ALL open proposals across all admins (for
committee voters).  No authentication required; rate-limit at the
reverse-proxy edge if needed.

#### `POST /admin/committee/vote`
**Public publish-only gateway.** No admin JWT required — the embedded
PGT-VOTE signature inside the spend bundle is the authority.

```json
// Request: pre-signed PGT-VOTE bundle from the voter's own wallet
{
  "proposal_id": "mp_…",
  "spend_bundle": { "coin_spends": [...], "aggregated_signature": "..." }
}

// Response
{ "pushed": true, "vote_tally_now": …, "bundle_id": "…" }
```

The committee endpoint is the **publish-only** gateway; the actual signing happens in the voter's wallet (committee members aren't necessarily allowlisted admins). Server validates the bundle structure, pushes, and updates the cached tally.

---

## 7. Database schema

`vault_db.py` already manages the `vault_registry` table. We add two more in the same SQLite database (single-file simplicity):

### `mint_proposals`

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | `mp_` + ULID |
| `owner_pubkey` | TEXT NOT NULL | 0x-hex, foreign-keyed by allowlist (logical) |
| `state` | TEXT NOT NULL | enum: DRAFT/PROPOSED/VOTING/PASSED/FAILED/EXECUTED/MINTED/CANCELED |
| `par_value` | INTEGER NOT NULL | mojos |
| `asset_class` | TEXT NOT NULL | |
| `property_id` | TEXT NOT NULL UNIQUE | enforces "no two deeds for the same property" |
| `jurisdiction` | TEXT NOT NULL | |
| `royalty_puzhash` | BLOB NOT NULL | bytes32 |
| `royalty_bps` | INTEGER NOT NULL | |
| `smart_deed_inner_puzhash` | BLOB NULL | bytes32, populated at PROPOSED |
| `eve_inner_puzhash` | BLOB NULL | bytes32, populated at PROPOSED |
| `deed_full_puzhash` | BLOB NULL | bytes32, populated at PROPOSED |
| `proposal_hash` | BLOB NULL UNIQUE | bytes32, populated at PROPOSED, on-chain identity |
| `proposal_tracker_coin_id` | BLOB NULL | populated on PROPOSED |
| `pgt_lock_coin_id` | BLOB NULL | operator's PROPOSE-mode lock |
| `published_bundle_id` | TEXT NULL | for audit |
| `executed_bundle_id` | TEXT NULL | |
| `deed_launcher_id` | BLOB NULL | populated on MINTED |
| `vote_tally` | INTEGER NOT NULL DEFAULT 0 | mojos of PGT locked in support |
| `quorum_required` | INTEGER NOT NULL | snapshot from manifest at proposal time |
| `deadline` | INTEGER NULL | unix |
| `created_at` | INTEGER NOT NULL | unix |
| `published_at` | INTEGER NULL | |
| `executed_at` | INTEGER NULL | |
| `minted_at` | INTEGER NULL | |
| `off_chain_metadata` | TEXT NULL | JSON blob, optional at draft time |

Indexes: `state`, `owner_pubkey`, `property_id`, `proposal_hash`.

### `property_metadata`

Populated at MINTED. Keyed by `deed_launcher_id`. Holds the off-chain fields from §4.2. Same shape as `mint_proposals.off_chain_metadata` but normalized once the on-chain id exists.

---

## 8. Frontend route table

```ts
// app.routes.ts (additions)
{
  path: 'admin',
  canActivate: [adminAuthGuard],
  loadChildren: () => import('./pages/admin/admin.routes').then(m => m.adminRoutes),
}
```

```ts
// pages/admin/admin.routes.ts
export const adminRoutes: Routes = [
  { path: '',           loadComponent: () => import('./dashboard/admin-dashboard.component').then(m => m.AdminDashboardComponent) },
  { path: 'mint/new',   loadComponent: () => import('./mint-new/mint-new.component').then(m => m.MintNewComponent) },
  { path: 'mint',       loadComponent: () => import('./mint-list/mint-list.component').then(m => m.MintListComponent) },
  { path: 'mint/:id',   loadComponent: () => import('./mint-detail/mint-detail.component').then(m => m.MintDetailComponent) },
  { path: 'committee',  loadComponent: () => import('./committee/committee.component').then(m => m.CommitteeComponent) },
];
```

The guard:
1. If no JWT in memory → redirect to `/connect?return=/admin`.
2. After connect, if connected pubkey is in allowlist (verified via `/admin/auth/login`) → set JWT, allow.
3. Otherwise → render a `403` view with the connected pubkey shown so the operator can confirm what they're seeing.

---

## 9. Differences from Solslot — what's "way better"

| Solslot's admin-property-update | Populis Admin Desk |
|---|---|
| Edits an existing off-chain row | Proposes a new on-chain mint |
| Auth = localStorage'd signature, replayable forever | Wallet-signed JWT, 15-min TTL, in-memory only |
| 50+ form fields, most off-chain | 6 on-chain fields explicit, off-chain in collapsible section |
| No committee approval gate | Mandatory PGT-quorum approval before mint |
| No per-action audit trail | Every state transition records bundle_id + coin_id |
| One-shot REST PUT | Multi-step lifecycle (draft → propose → vote → execute → mint), each step idempotent |
| Single admin (token shared) | Per-pubkey allowlist, attribution per action |
| No on-chain metadata commitment | `PROPERTY_ID` curried into deed; future REMARK-hash committed off-chain blob |
| No threat model documented | Explicit threat table (§3.4) |
| Form validation client-side only | Same regex enforced client + server (DRY via shared schema doc) |

---

## 10. Open questions / future work

| Question | Answer for Step A | Future direction |
|---|---|---|
| Admin pubkey allowlist storage | env var, restart to rotate | on-chain admin registry singleton |
| Off-chain metadata integrity | stored raw, no hash commit | REMARK condition with sha256(metadata blob), buyer verifies |
| Committee voter notifications | none (committee polls `/admin/committee/proposals`) | webhook to Discord / email |
| Multi-admin co-signing | not required (single proposer) | k-of-n proposer threshold, additional curry |
| Proposal cancel after publish | not allowed (on-chain proposals run to deadline) | governance EXPIRE_PROPOSAL after-deadline-without-quorum hatch |
| EVM vs Chia BLS for admin auth | both supported (auth_type field) | passkey support (already a stub in `populis-api.service.ts`) |
| Proposal deadline customization | server config `voting_window_seconds` | per-proposal override with a min/max bound |

---

## 11. Step A delivery breakdown

| Phase | Deliverable | Files | Tests |
|---|---|---|---|
| A.1 | This spec | `populis_api/docs/ADMIN_DESK_DESIGN.md` | review only |
| A.2 | Backend: mint proposal store, auth, mint endpoints | `populis_api/populis_api/admin_auth.py`, `mint_proposals.py`, extended `admin.py`, `config.py` | `tests/test_admin_auth.py`, `tests/test_mint_proposals.py`, `tests/test_admin_mint_endpoints.py` |
| A.3 | Frontend admin gate + dashboard shell | `populis_portal/src/app/services/admin.service.ts`, `admin-auth.guard.ts`, `pages/admin/dashboard/admin-dashboard.component.*`, `app.routes.ts` extension | spec files |
| A.4 | Mint proposal form | `populis_portal/src/app/pages/admin/mint-new/*` | spec files |
| A.5 | Mint status list + detail views | `populis_portal/src/app/pages/admin/mint-list/*`, `mint-detail/*` | spec files |
| A.6 | Committee voter view | `populis_portal/src/app/pages/admin/committee/*` | spec files |

Each phase commits separately with a descriptive message so review can happen at granular checkpoints.

---

*End of Step A.1 — design spec.*
