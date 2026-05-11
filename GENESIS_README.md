# Populis Genesis — First-Time Protocol Deployment

> One-shot bootstrap runbook for spinning up a new Populis deployment
> from a fresh chain.  Once these steps are done, day-to-day operations
> live in **`ADMIN_README.md`**.

## Bootstrap invariants

Genesis has a hard chicken-or-egg boundary:

- `POPULIS_ADMIN_TOKEN` is a bootstrap operator token, not a protocol
  admin identity.
- `POST /admin/deploy/protocol` deploys the base protocol stack; it
  does not create the `admin_authority_v2` singleton and does not make
  the caller the first admin.
- The first protocol admin cannot be voted in by an existing admin,
  because no protocol admin exists yet.
- The first admin must be born at admin-authority genesis as admin slot
  `0`, with its initial admin record, `admins_hash`, and MIPS root
  committed into the first `admin_authority_v2` singleton state.
- Later admin/key rotation is self-governed by the existing
  admin-authority state and its cooldown paths.
- PGT holders are committee/governance participants, not admin-desk
  admins.  PGT voting can drive governance proposals, but it is a
  separate authority system from admin login and admin-authority
  rotation.

Phase 0 is one genesis ceremony even though the current portal executes it
through two visible steps: deploy the base protocol manifest, then create
and finalize first-admin authority.  The implementation seam keeps the
spend construction auditable, but the product boundary is the full
ceremony; genesis is incomplete until admin slot `0` is committed and
`bootstrap_manifest.json` locks the bootstrapper.

## Hybrid bootstrapper target

The target Phase 0 architecture is a **run-once bootstrapper** with a
hybrid manifest + runtime-config handoff:

- The bootstrapper is the only mutable surface that accepts
  `POPULIS_ADMIN_TOKEN`.  It exists to run one genesis ceremony: launch
  Phase A protocol genesis, create/bind admin-authority-v2 admin slot `0`,
  and write the permanent public deployment artifacts.
- On success it writes immutable local artifacts:
  `deployment_manifest.json`, `admin_records.json`,
  `bootstrap_manifest.json`, and `portal_runtime_config.json`.
- `bootstrap_manifest.json` records the network, protocol launcher ids,
  admin-authority launcher id, `admins_hash`, MIPS root, and content
  hashes of the generated artifacts so operators can detect local
  tampering.
- `portal_runtime_config.json` contains **public coordinates only**:
  launcher ids, puzzle/mod hashes, MIPS root, admin records hash, network,
  and read-only API/coinset URLs.  It must never contain
  `POPULIS_ADMIN_TOKEN`, faucet private keys, JWT secrets, wallet
  signatures, or any other bearer credential.
- After the bootstrapper records success, every mutable bootstrap route
  must fail closed.  Re-running `/admin/deploy/protocol` or any future
  `/admin/bootstrap/*` mutation against the same manifest path should
  return a locked/gone state rather than overwrite permanent records.
- The post-genesis app consumes read-only runtime config derived from
  those artifacts.  Runtime config can help the portal avoid a rebuild,
  but it is not an authority source by itself; admin login still has to
  verify against the admin-authority records/hash model.
- No permanent admin membership is ever created by frontend env injection
  alone.  The only permanent first admin is the wallet committed into the
  `admin_authority_v2` genesis state and matching `admin_records.json`.

This keeps the backend dependency narrow: during genesis the operator may
run a privileged bootstrapper, but after successful recordation the
mutable bootstrap authority shuts down and the remaining service surface
is read-only public configuration plus normal protocol APIs.

### Bootstrap challenge boundary

Bootstrap UI access should use a **two-step challenge**, not a permanent
frontend secret:

1. The operator enters `POPULIS_ADMIN_TOKEN` once on the genesis page.
2. The API verifies that the bootstrapper is not locked and issues a
   short-lived bootstrap session cookie scoped only to bootstrap routes.
3. The browser may use that bootstrap session to continue the
   first-admin authority step of the same genesis ceremony and to inspect
   bootstrap status surfaces.
4. The bootstrap session is never an admin-desk session.  It must not
   authorize mint proposals, property registration, normal `/admin/*`
   operations, or any post-genesis mutation.
5. The raw bootstrap token must never be stored in `localStorage`,
   `sessionStorage`, URLs, runtime config, manifests, or downloaded
   artifacts.
6. The bootstrap session must expire quickly, use same-site cookie
   protections, and be invalidated when the bootstrapper writes a success
   `bootstrap_manifest.json`.
7. Once success is recorded, challenge issuance and every mutable
   bootstrap route must return a locked/gone response.  Only read-only
   public runtime-config and normal non-bootstrap APIs remain.

This gives the operator a browser workflow without converting the
one-shot token into a long-lived frontend credential.

### First-admin wallet capture contract

The bootstrap-accessible first-admin authority step of the genesis
ceremony must capture and display the intended first admin wallet before
any permanent record is written:

1. The operator proves control of the intended first admin wallet with a
   one-shot wallet signature.  That raw wallet signature is
   proof-of-possession only; it is not an authority artifact and must not
   be stored as admin authority.
2. Before launch, the UI must show the exact identity that will become
   first admin: EVM address, compressed secp256k1 pubkey,
   Eip712Member leaf hash, admin slot `0`, `m_within`, network/domain
   binding, and the MIPS root that will govern the initial
   `admin_authority_v2` state.
3. The durable off-chain admin artifact is `admin_records.json`.  Its
   initial record must be explicit: `"admin_idx": 0`, `"m_within": 1`
   for the single-wallet bootstrap path, and an `eip712_member` leaf
   containing `leaf_hash`, `evm_address`, `secp256k1_pubkey`,
   `type_hash`, and `prefix_and_domain_separator`.
4. `admins_hash` is computed from the displayed admin records, and the
   MIPS root is computed from the displayed leaf/quorum tree.  Both must
   be committed into the first `admin_authority_v2` singleton state; no
   hidden env-injected admin and no implicit frontend config can become
   first admin.
5. `bootstrap_manifest.json` records public commitments to the result:
   admin-authority launcher id, `admins_hash`, MIPS root, and the
   content hash of `admin_records.json`.  `portal_runtime_config.json`
   may repeat public coordinates only.
6. Neither `admin_records.json`, `bootstrap_manifest.json`, nor
   `portal_runtime_config.json` may contain `POPULIS_ADMIN_TOKEN`, the
   bootstrap session cookie/JWT, raw wallet signatures, auth nonces,
   JWT secrets, faucet private keys, or any bearer credential.

This makes the permanent authority source auditable: admin slot `0` is
the displayed wallet committed on chain and mirrored by
`admin_records.json`, not the operator token, a transient bootstrap
cookie, or frontend environment injection.

### Admin-authority artifact boundary

The first-admin artifacts are also the root of the durable
`admin_authority_v2` audit trail.  They must stay public, replayable, and
strictly separated from any credential:

1. `admin_records.json` is the canonical off-chain roster reveal.  It
   contains `version`, `launcher_id`, and `admin_records` ordered by
   `admin_idx`; each record contains `admin_idx`, `m_within`, and
   kind-specific public leaves.  At genesis this file contains admin slot
   `0` only.
2. `bootstrap_manifest.json` commits to
   `admin_authority_v2.launcher_id`, `admin_authority_v2.admins_hash`,
   `admin_authority_v2.mips_root`,
   `admin_authority_v2.authority_version`, and
   `artifact_hashes.admin_records_json`.  The initial authority version is
   `1`; any later public authority snapshot must name the live
   `authority_version` it corresponds to.
3. `portal_runtime_config.json` may repeat public coordinates under
   `admin_authority_v2`, including `launcher_id`, `admins_hash`,
   `mips_root`, `authority_version`, and `admin_records_hash`.  It is
   read-only runtime discovery, not an authority source and not an
   authorization token.
4. After `bootstrap_manifest.json` is written, the bootstrapper is locked.
   Mutable bootstrap routes must not edit `admin_records.json`, replace
   `bootstrap_manifest.json`, or change the runtime-config authority
   coordinates.
5. Future roster additions are normal admin-authority spends, not a
   bootstrap mutation.  They must use `ADMIN_ROSTER_UPDATE`
   (`SPEND_ADMIN_ROSTER_UPDATE = 0x07`), be authorized by the current
   MIPS admin authority, append exactly one new admin slot, update
   `ADMINS_HASH` and `MIPS_ROOT_HASH` atomically, preserve
   `PENDING_KEY_OPS_HASH`, and bump `authority_version`.
6. Any post-genesis replacement roster artifact must be a new versioned
   `admin_records.json` snapshot whose canonical hash equals the
   on-chain announced `ADMINS_HASH`.  Local edits that do not correspond
   to a confirmed authority spend are invalid.
7. Key-rotation paths (`KEY_ADD_*` and `KEY_REMOVE_*`) mutate keys inside
   existing admin slots only.  They are not admin-slot creation paths and
   must not be represented as appending admin records.

### Bootstrap finalize recordation contract

The final bootstrap mutation is `POST /admin/bootstrap/finalize`.  It is
the browser-facing write that records completion of the same genesis
ceremony after the base protocol deployment manifest already exists:

1. It is authorized by `require_bootstrap_session` and therefore requires
   a valid short-lived `populis_bootstrap_session` cookie.  A normal admin
   JWT, bearer token, or raw `POPULIS_ADMIN_TOKEN` is not sufficient for
   this endpoint.
2. The request body contains the public first-admin artifacts and
   commitments: `admin_records`, `admin_authority_launcher_id`,
   `admins_hash`, `mips_root`, and optional read-only API/coinset URLs.
   The endpoint loads the existing `deployment_manifest.json`; it must not
   invent protocol coordinates from portal env.
3. Before any artifact is written, the API strictly parses
   `admin_records`, recomputes the canonical protocol `admins_hash`, and
   rejects the finalize request if the records do not hash to the
   submitted `admins_hash`.
4. The API builds public-only artifacts, validates them against credential
   markers, and persists them in this order:
   `admin_records.json`, `portal_runtime_config.json`,
   `bootstrap_recovery_anchor.json`, then `bootstrap_manifest.json`.
5. `bootstrap_manifest.json` is the lock marker.  It is written last; once
   present, challenge issuance and bootstrap finalization must fail closed
   rather than overwrite permanent records.
6. A successful response returns only public `bootstrap_manifest`,
   `portal_runtime_config`, and `bootstrap_recovery_anchor` objects and clears
   the bootstrap session cookie.  It never returns or persists raw wallet
   signatures, auth nonces, bootstrap JWT/cookie material, bearer headers,
   faucet keys, or `POPULIS_ADMIN_TOKEN`.
7. The portal first-admin authority step calls `AdminBootstrapService.finalizeBootstrap`
   only after the admin-authority launch has been submitted, first-admin
   wallet metadata is known, `admins_hash` is live, and the MIPS root is
   filled.  The request is cookie-only (`withCredentials`) and sends no
   `Authorization` header.
8. The portal displays returned `bootstrap_manifest.json`,
   `portal_runtime_config.json`, and `bootstrap_recovery_anchor.json` as
   read-only public artifacts and keeps them visible after the bootstrapper
   flips to locked.  It must not store the bootstrap token, session, raw
   signature, or finalized artifacts in `localStorage` or `sessionStorage`.
9. `/admin/genesis` treats locked bootstrap as terminal: it disables
   starting another bootstrap session, hides the first-admin launch CTA,
   names the durable public artifacts, and points the operator to
   permanent admin login using the recorded admin slot `0` wallet.

### Bootstrap recovery anchor contract

The public JSON artifacts are necessary but not sufficient for disaster
recovery if the original API/portal host disappears.  A completed genesis
ceremony must also leave a chain-visible bootstrap recovery anchor that a
future operator can discover without trusting the original server:

1. The recovery anchor is a public discovery marker, not an authority source
   and not an authorization credential.  Admin authority still comes from the
   live `admin_authority_v2` singleton state and verified admin records.
2. The anchor must be emitted by a transaction in the same first-admin
   bootstrap ceremony after the final public artifact hashes are known.  Until
   a chain indexer can observe the anchor, the ceremony is recorded but not
   disaster-recoverable from chain alone.
3. The discoverable marker tag is the ASCII string
   `POPULIS_BOOTSTRAP_V1`.  The first implementation carries it as a
   memo-bearing marker coin.  Puzzle announcement payloads or other
   chain-visible spend records may be added later only if they preserve the
   same canonical payload and tag discoverability.
4. The payload is canonical JSON using the same canonical byte rules as
   `canonical_json_bytes`: sorted keys, compact separators, UTF-8.  It must
   include `version`, `tag`, `network`,
   `admin_authority_v2_launcher_id`, `authority_version`,
   `bootstrap_manifest_hash`, `portal_runtime_config_hash`, and
   `admin_records_hash`.
5. `bootstrap_manifest_hash`, `portal_runtime_config_hash`, and
   `admin_records_hash` are `sha256:` content-hash strings.  A rehosted portal
   may accept mirrored artifacts only when their canonical hashes match the
   anchor and the artifact coordinates match the live on-chain singleton.
6. Optional HTTP/IPFS/Arweave/Git/GitHub locators may be published later as
   hints, but URLs are never authority.  If all locators disappear, the
   anchor hash values still let operators verify any independently mirrored
   artifact copies.
7. The recovery anchor must never contain `POPULIS_ADMIN_TOKEN`, bootstrap
   session cookies/JWTs, raw wallet signatures, auth nonces, bearer tokens,
   admin JWT secrets, faucet private keys, private mnemonics, or any material
   that can authenticate as an admin or spend funds.

### Bootstrap recovery anchor carrier contract

The v1 on-chain carrier for `bootstrap_recovery_anchor.json` is a
memo-bearing marker coin.  This freezes the first discoverability path before
transaction wiring lands:

1. The carrier transaction is the post-finalize bootstrap recovery-anchor
   publish transaction in the same genesis ceremony.  It must be emitted only
   after `/admin/bootstrap/finalize` has returned the final
   `bootstrap_recovery_anchor.json` payload.  The original first-admin launch
   transaction cannot carry the final anchor unless it already knows the final
   artifact hashes.
2. The marker coin is an ordinary XCH output created by a `CREATE_COIN`
   condition with amount at least `1` mojo.  Its puzzle hash, amount, parent
   coin, and future spend are not authority and must not be used as
   validation inputs.
3. The marker output memo list must contain exactly one UTF-8 tag memo equal
   to `POPULIS_BOOTSTRAP_V1` and one payload memo equal to the canonical JSON
   bytes of `bootstrap_recovery_anchor.json`.  The payload memo must parse as
   JSON and must be byte-for-byte equal to `canonical_json_bytes(payload)`.
4. Recovery tooling discovers candidates by scanning chain-visible output
   memos for `POPULIS_BOOTSTRAP_V1`, then parsing the payload memo from the
   same marker output.  Tooling must not require the original API host,
   original portal host, marker puzzle hash, or marker coin id.
5. A candidate anchor is valid only if the payload has the pinned v1 fields,
   `tag == "POPULIS_BOOTSTRAP_V1"`, the payload bytes are canonical, mirrored
   artifact hashes match `bootstrap_manifest_hash`,
   `portal_runtime_config_hash`, and `admin_records_hash`, and the artifact
   authority coordinates match the live `admin_authority_v2` singleton.
6. Re-publishing the exact same payload is idempotent.  Conflicting anchors
   for the same `network`, `admin_authority_v2_launcher_id`, and
   `authority_version` are not automatically resolved; clients must reject
   them or require manual operator/auditor review.
7. The carrier transaction and memos must never include `POPULIS_ADMIN_TOKEN`,
   bootstrap session cookies/JWTs, raw wallet signatures, auth nonces, bearer
   tokens, admin JWT secrets, faucet private keys, private mnemonics, private
   URLs, or mutable service credentials.  HTTP/IPFS/Arweave/Git/GitHub
   locators remain optional hints outside the authority boundary.

### Bootstrap recovery anchor publish-intent API contract

`GET /admin/bootstrap/recovery-anchor/publish-intent` exposes a
non-broadcasting operator handoff for the marker-coin carrier:

1. The endpoint is available only after `bootstrap_manifest.json` exists and
   `bootstrap_recovery_anchor.json` is present.  It reads the persisted
   recovery anchor; it never recomputes a different payload from portal env.
2. The endpoint is authorized by `require_admin_jwt`.  The retired bootstrap
   session cookie and raw `POPULIS_ADMIN_TOKEN` are not accepted as publish
   authority after lock.
3. The response is JSON-safe and public-only: `network`,
   `marker_coin_amount_mojos`, `admin_authority_v2_launcher_id`,
   `authority_version`, `bootstrap_manifest_hash`,
   `portal_runtime_config_hash`, `admin_records_hash`, `tag_memo_utf8`,
   `tag_memo_hex`, `payload_memo_json`, `payload_memo_utf8`,
   `payload_memo_hex`, `memos_hex`, and `payload_hash`.
4. `marker_coin_amount_mojos` defaults to `1`; the API does not include or
   require marker puzzle hash, marker coin id, parent coin id, future spend,
   raw wallet signature, spend bundle, or wallet private material.
5. `tag_memo_utf8` must be `POPULIS_BOOTSTRAP_V1`; `payload_memo_json` must
   equal the persisted `bootstrap_recovery_anchor.json`; `payload_memo_utf8`
   must be canonical JSON bytes decoded as UTF-8; and `memos_hex` must contain
   exactly the tag memo hex and payload memo hex in carrier order.
6. The endpoint does not submit to coinset, push a spend bundle, select a
   wallet coin, or create authority.  It only exports deterministic inputs for
   later operator wallet tooling.

### Bootstrap recovery anchor CREATE_COIN preview API contract

`POST /admin/bootstrap/recovery-anchor/create-coin-preview` exposes the
next non-broadcasting handoff: a JSON-safe preview of the marker
`CREATE_COIN` condition:

1. The endpoint is authorized by `require_admin_jwt` and is available only
   after `bootstrap_manifest.json` and `bootstrap_recovery_anchor.json` exist.
   It reads the persisted recovery anchor and derives the publish intent from
   that payload.
2. The request contains only `marker_puzzle_hash`, a 32-byte hex puzzle hash
   for the ordinary marker coin output.  The marker puzzle hash is a carrier
   address only; it is not authority and clients must not validate anchors by
   this value.
3. The response is JSON-safe and public-only: `condition_opcode`,
   `marker_puzzle_hash`, `marker_coin_amount_mojos`, `tag_memo_hex`,
   `payload_memo_hex`, `memos_hex`, `condition_hex`, and `payload_hash`.
4. `condition_opcode` must be `51` (`CREATE_COIN`).  `condition_hex` must be
   `[51, marker_puzzle_hash, marker_coin_amount_mojos, [tag_memo_hex,
   payload_memo_hex]]`, with `memos_hex` in the same carrier order.
5. The endpoint does not select funding coins, compute a marker coin id,
   create a spend bundle, request or return wallet signatures, push to
   coinset, or broadcast.  It only previews the condition that later wallet
   tooling may include in a spend.

---

## Phase 0 brick map — first-admin birth ceremony

Extreme-atomic implementation order:

```text
Brick -1 — Genesis doctrine and docs-contract tests
Repo: populis_api
Layer: docs/test scaffolding
Goal: Pin the bootstrap invariants before changing behavior.
Outputs: This README section plus tests that fail if the doctrine is removed.
Tests: pytest tests/test_genesis_readme_contract.py
Stop condition: docs state that /admin/deploy/protocol is base protocol only
and that first admin must be born at admin-authority genesis.

Brick 0.1 — Portal copy/UX guardrails
Repo: populis_portal
Layer: /admin/genesis component
Goal: Make the UI say plainly that base genesis does not create admin slot 0.
Tests: focused component tests for the warning and next-step copy.

Brick 0.2A — Hybrid bootstrapper lifecycle contract
Repo: populis_api
Layer: docs/test scaffolding
Goal: Pin the run-once bootstrapper model before opening more routes.
Tests: pytest tests/test_genesis_readme_contract.py
Stop condition: docs state that bootstrap mutation shuts down after success
and portal runtime config is public/read-only, not an authority source.

Brick 0.2B — Bootstrap-accessible first-admin authority step
Repo: populis_portal
Layer: routing/auth boundary
Goal: Continue the genesis ceremony into first-admin authority creation during bootstrap without requiring an admin JWT.
Tests: route/guard tests proving bootstrap access does not open the normal desk.

Brick 0.3 — First-admin wallet capture in genesis
Repo: populis_portal
Layer: EVM wallet/admin record preparation
Goal: Capture the intended admin-0 wallet before the first-admin authority
step and show the operator exactly which address/pubkey will become first admin.
Tests: service/component tests around pubkey recovery, record preview, and
no token persistence.

Brick 0.4 — Combined bootstrap manifest
Repo: populis_portal + populis_api
Layer: manifest handoff
Goal: Produce/export a single bootstrap manifest containing protocol
deployment data, admin-authority launcher id, admin records, admins_hash,
MIPS root, and required env/runtime values.
Tests: pure manifest-builder tests plus API/admin-record hash validation tests.

Brick 0.5 — Admin rotation semantics audit
Repo: populis_protocol
Layer: admin_authority_v2
Goal: Confirm whether current KEY_ADD_* paths add keys to an existing admin
slot only, or whether a distinct brand-new admin-slot add path is required.
Tests: CLVM/unit tests that distinguish key addition, slot addition, removal,
MIPS root updates, and operational authorization after activation.
```

---

A complete Populis deployment currently comprises **seven** on-chain
singletons / coins, deployed in two implementation phases after the
bootstrap doctrine above is satisfied:

```
 Phase A — atomic genesis (one block)
 ────────────────────────────────────
   1. PGT (CAT2) — populis governance token TAIL bound to its own
      genesis coin id (genesis-by-coin-id; never re-issued).
   2. Pool singleton — central state machine (deposits, redeems,
      settlements, secondary offers).
   3. DID singleton — quorum-gated DID controlled by governance.
   4. Governance/tracker singleton — propose / vote / settle / freeze.

 Phase B — per-trust-root singletons (any order, opt-in)
 ──────────────────────────────────────────────────────
   5. A.3 protocol-config singleton — content-hash commitment over
      (pool, governance, network, version).
   6. A.2 admin-authority singleton — m-of-n rotation, replay-protected.
   7. A.4 property-registry singleton — append-only registration log.

 (A.1 mint-proposal singletons are per-proposal, launched on-demand
  via the admin desk; not part of genesis.)
```

Phase A is **atomic at the SpendBundle level** (all four coins commit
together in one block, or none commit) — there's no partial-deploy
state.  Phase B singletons are launched independently after Phase A
succeeds and are fully optional during early testnet operation.

---

## Prerequisites

1. A **chia full node syncing testnet11** (or use coinset.org's public
   RPC at `https://testnet11.api.coinset.org`).
2. A **BLS-keyed wallet with at least 1,000,003 mojos** of TXCH at
   the faucet's puzzle hash:
   - 1,000,000 mojos for the PGT genesis coin
   - 3 mojos for the three Phase A singleton launchers
   - plus fee headroom (default `fee_per_spend=0`)
   - Phase B launchers cost 1 mojo each, but those come later.
3. **Faucet master key** configured as `POPULIS_FAUCET_MASTER_SK_HEX`
   (or `POPULIS_FAUCET_MNEMONIC` / `POPULIS_FAUCET_SEED_HEX`).
4. **Operator admin token** configured as `POPULIS_ADMIN_TOKEN`
   (generate via `openssl rand -hex 32`).  This is the bearer token
   for the one-shot `/admin/deploy/protocol` endpoint — distinct from
   the interactive admin-desk JWT (see `ADMIN_README.md`).

---

## Phase A — atomic genesis

### Step 1.  Fund the faucet

Top up the faucet from the public testnet11 faucet:

```bash
# /protocol exposes the bech32m address.
curl -s http://localhost:8787/protocol | jq .faucet_address
# Submit that address to https://testnet11-faucet.chia.net/
```

Wait for the inbound coin to confirm (one block is enough).

### Step 2.  Dry-run

Verify the deployment plan computes correctly without pushing
anything:

```bash
curl -X POST http://localhost:8787/admin/deploy/protocol \
  -H "Authorization: Bearer ${POPULIS_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}' | jq .
```

This returns the full `ProtocolDeploymentPlan` including:

- `pool_launcher_id` / `did_launcher_id` / `tracker_launcher_id`
- `pgt_tail_hash` / `pgt_full_puzhash`
- `pool_full_puzhash` / `did_full_puzhash` / `tracker_full_puzhash`
- The chosen genesis coin ids

Validate that the chosen coins are the ones you want and that the
launcher ids match the expected derivation
(`Coin(parent.name(), SINGLETON_LAUNCHER_HASH, 1).name()`).

### Step 3.  Atomic deploy

```bash
curl -X POST http://localhost:8787/admin/deploy/protocol \
  -H "Authorization: Bearer ${POPULIS_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

On success:

```json
{
  "spend_bundle_id": "0x...",
  "pushed": true,
  "manifest": { /* full plan */ }
}
```

The manifest is persisted to `POPULIS_DEPLOYMENT_MANIFEST_PATH`
(default `./deployment_manifest.json`).  From this point on, the API
reads pool/governance launcher ids from the manifest on every
request — no restart needed (POP-CANON-011).

### Step 4.  Verify on chain

```bash
LAUNCHER=$(jq -r .pool_launcher_id deployment_manifest.json)

curl -X POST https://testnet11.api.coinset.org/get_coin_record_by_name \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"$LAUNCHER\"}" | jq .
```

The launcher coin will be **spent** (the same bundle that created it
also spent it to launch the singleton).  Look up the singleton's full
puzzle hash to find the live coin:

```bash
PUZ=$(jq -r .pool_full_puzhash deployment_manifest.json)
curl -X POST https://testnet11.api.coinset.org/get_coin_records_by_puzzle_hash \
  -H "Content-Type: application/json" \
  -d "{\"puzzle_hash\": \"$PUZ\", \"include_spent_coins\": false}" | jq .
```

Should return one unspent coin.

---

## Phase B — trust-root singletons (opt-in)

Each A.x singleton is independent.  Launch the ones you need; skip
the rest until later (the API exposes informational-only fields when
they're absent).

### A.3 — protocol-config singleton

> Replaces three trust-root env vars
> (`POPULIS_POOL_LAUNCHER_ID`, `POPULIS_GOVERNANCE_LAUNCHER_ID`,
> `POPULIS_NETWORK`) with an on-chain commitment.

1. Use the `populis_puzzles.protocol_config_driver` helper to build the
   inner puzzle, currying:
   - `(pool_launcher_id, governance_launcher_id, network_byte, GOV_PUBKEY, version=1)`
2. Launch it as a standard singleton (1-mojo launcher coin).  Capture
   the launcher id.
3. Set the env var:
   ```bash
   POPULIS_PROTOCOL_CONFIG_LAUNCHER_ID=0x<launcher_id>
   ```
4. Verify on `/protocol`:
   ```bash
   curl -s http://localhost:8787/protocol | jq '{
     protocol_config_hash, protocol_config_launcher_id, protocol_config_version
   }'
   ```
   The `protocol_config_hash` should match what the singleton's
   `CREATE_PUZZLE_ANNOUNCEMENT` emits.

### A.5 — admin-authority-v2 singleton (Phase 2.5 — chain-gated admin desk)

> Replaces both `POPULIS_ADMIN_PUBKEY_ALLOWLIST` AND the A.2 v1
> singleton with a MIPS-quorum design that supports per-admin
> OneOfN of mixed auth methods (BLS, EIP-712 / MetaMask, passkey).
> The launcher's wallet becomes admin slot 0 — no env-var bootstrap.

#### Recommended path (portal wizard)

The launch-authority-v2 wizard at
`https://localhost:4200/admin/launch-authority-v2` automates the
whole flow:

1. Sign in to the admin desk with an EVM wallet (env-var allowlist
   mode is fine for the bootstrap session).
2. Click **"Use my connected wallet as first admin"**.  Wallet pops
   a one-shot EIP-712 probe; portal recovers your compressed
   secp256k1 pubkey, asks the API to compute the canonical
   Eip712Member leaf hash, and pre-fills the records textarea.
3. Compute the MIPS root hash off-chain (chia-wallet-sdk
   `mOfNHash(config, m, [eip712MemberHash(...)])`) and paste it.
4. Click **"Submit on chain"**.  Goby/Sage signs the funding spend;
   the portal combines it with the launcher's permissionless spend
   and pushes to coinset.org.
5. After confirmation, click **"Download admin_records.json"**.
6. Drop the downloaded file into the API host's deployment dir
   (e.g. `/etc/populis/admin_records.json`) and configure:
   ```bash
   POPULIS_ADMIN_RECORDS_PATH=/etc/populis/admin_records.json
   POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID=0x<launcher_id>
   POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH=0x<admins_hash>
   POPULIS_ADMIN_JWT_SECRET=$(openssl rand -hex 32)   # if not already set
   # remove or empty POPULIS_ADMIN_PUBKEY_ALLOWLIST — JSON is now the gate
   ```
7. Restart the API.  Boot validator loads + verifies the JSON
   against the on-chain `admins_hash`; refuses to start on drift.
8. Verify the new mode:
   ```bash
   curl -s http://localhost:8787/admin/auth/authority_v2 | jq '{
     gating_source, informational_only, admins_hash
   }'
   # → gating_source: "POPULIS_ADMIN_RECORDS_PATH"
   # → informational_only: false
   ```

#### Direct CLI path (for ops who prefer it)

1. Choose your initial admin records: each admin slot is
   `(admin_idx, leaves: [Eip712Member|Bls|...], m_within)`.
2. Compute leaf hashes via
   `populis_puzzles.eip712_helpers.compute_eip712_member_leaf_hash`
   for each EIP-712 admin's pubkey.
3. Compute `admins_hash` via
   `populis_puzzles.admin_authority_v2_driver.compute_admins_hash`.
4. Compute the MIPS root hash via the chia-wallet-sdk MIPS helpers.
5. Build the inner puzzle with
   `admin_authority_v2_driver.make_inner_puzzle(mips_root_hash,
   admins_hash, ...)` and launch as a singleton.
6. Hand-author `admin_records.json` matching the schema in
   `populis_api/admin_records.py`, or run the launch via the
   wizard for the pre-baked download.

> **Phase 2.5b-2 (pending):** the API will fetch
> `admins_hash` directly from coinset.org at boot, eliminating the
> operator-supplied `POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH`
> env step.  Until then, drift between env and chain is caught by
> the boot validator.

### A.2 — admin-authority v1 singleton (legacy, still supported)

> Pre-Phase-2.5 deployments use this; new deployments should jump
> straight to A.5 above.

1. Choose your initial allowlist of BLS G1 pubkeys (typically the
   operator team's cold-key set) and a quorum threshold *m*.
2. Use the `populis_puzzles.admin_authority_driver.make_inner_puzzle`
   helper to build the inner puzzle with curried state
   `(allowlist, quorum_m=m, authority_version=1)`.
3. Launch as a singleton.  Capture the launcher id.
4. Set the env vars:
   ```bash
   POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID=0x<launcher_id>
   POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS=0xpub1,0xpub2,...   # BLS G1 hex
   POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M=<m>
   POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION=1
   ```
5. Verify on `/admin/auth/authority`:
   ```bash
   curl -s http://localhost:8787/admin/auth/authority | jq .
   ```
   The `state_hash` should match the singleton's announcement payload.

> **A.2 caveat:** v1 singleton is *informational only* in all
> phases — the live gate is either the env-var allowlist (legacy)
> or the A.5 v2 records JSON (Phase 2.5+).  See `SECURITY.md` §A.2
> and §A.5.

### A.4 — property-registry singleton

> Append-only on-chain log of registered Populis property identifiers,
> paired with the A.1 mint-proposal singleton.

1. Choose the governance pubkey that authorises new registrations
   (typically the same as A.3's `GOV_PUBKEY`).
2. Use `populis_puzzles.property_registry_driver.make_inner_puzzle`
   with curried state `(GOV_PUBKEY, registry_version=0)`.
3. Launch as a singleton.  Capture the launcher id.
4. Set the env var:
   ```bash
   POPULIS_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID=0x<launcher_id>
   ```
5. Verify on `/protocol`:
   ```bash
   curl -s http://localhost:8787/protocol | jq '{
     property_registry_launcher_id, property_registry_mod_hash
   }'
   ```

To register a property, build a registration spend with
`build_registration_spend(...)`, sign with the governance key, and
push.  The driver's docstring covers the full procedure.

---

## Re-deployment

`/admin/deploy/protocol` refuses to re-deploy when a manifest already
exists (returns 409).  To re-deploy:

1. Move the existing manifest aside (don't delete — it's history):
   ```bash
   mv deployment_manifest.json deployment_manifest.$(date +%s).json
   ```
2. Re-run Step 3.

A new deployment uses fresh genesis coins and produces an entirely
**different** PGT TAIL hash, pool launcher id, etc.  This is by
design: the audit-frozen security argument requires a single bound
genesis.  Every PGT-holding wallet, deed launcher, and pool/vault
user must re-onboard against the new IDs — there is no migration
path.

The Phase B singletons (A.2/A.3/A.4) can be re-deployed independently
without affecting Phase A; they're additive trust roots.

---

## Configuration reference

| Setting | Default | Phase | Notes |
|---------|---------|-------|-------|
| `POPULIS_NETWORK` | `testnet11` | A | Also accepts `mainnet` |
| `POPULIS_COINSET_BASE_URL` | testnet11 coinset | A | Override for self-hosted RPC |
| `POPULIS_FAUCET_MASTER_SK_HEX` | — | A | **Required** for deployment |
| `POPULIS_ADMIN_TOKEN` | — | A | **Required** for `/admin/deploy/*` |
| `POPULIS_DEPLOYMENT_MANIFEST_PATH` | `./deployment_manifest.json` | A | Persistence location |
| `POPULIS_PROTOCOL_CONFIG_LAUNCHER_ID` | — | B (A.3) | Optional |
| `POPULIS_PROTOCOL_ADMIN_AUTHORITY_*` (4 vars) | — | B (A.2) | Optional |
| `POPULIS_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID` | — | B (A.4) | Optional |

See `.env.example` for the complete list with comments.

---

## Deployment plan internals

The Phase A atomic deploy bundle contains 7 coin spends:

| # | Coin | Spend | Output |
|---|------|-------|--------|
| 1 | Cpgt (faucet) | parent | `CREATE_COIN(CAT2_PGT_FULL_PH, 1_000_000)` + change |
| 2 | Cpool (faucet) | parent | `CREATE_COIN(SINGLETON_LAUNCHER_HASH, 1)` + change |
| 3 | pool_launcher | launcher | `CREATE_COIN(POOL_FULL_PH, 1)` |
| 4 | Cdid (faucet) | parent | `CREATE_COIN(SINGLETON_LAUNCHER_HASH, 1)` + change |
| 5 | did_launcher | launcher | `CREATE_COIN(DID_FULL_PH, 1)` |
| 6 | Cgov (faucet) | parent | `CREATE_COIN(SINGLETON_LAUNCHER_HASH, 1)` + change |
| 7 | gov_launcher | launcher | `CREATE_COIN(TRACKER_FULL_PH, 1)` |

Faucet spends are signed with the faucet's synthetic BLS key.
Launcher spends are signature-less (the launcher puzzle validates the
inner ph itself).

PGT uses standard CAT2 genesis-by-coin-id issuance: the new CAT2
coin's parent is Cpgt's coin id, and the curried PGT TAIL accepts
this match.  No CAT TAIL launcher needed.

---

## Troubleshooting

### `503: Faucet not configured`

`POPULIS_FAUCET_MASTER_SK_HEX` is unset.  The lifespan logged a
warning on startup; check the API logs.

### `503: Admin endpoints are disabled`

`POPULIS_ADMIN_TOKEN` is unset.  Add it to your `.env` and restart.

### `409: Deployment manifest already exists`

A previous deployment succeeded.  See "Re-deployment" above.

### `503: no unspent faucet coin with amount ≥ 1000000`

Top up the faucet (Step 1).

### `502: coinset.org rejected the spend`

The bundle was cryptographically valid but the network rejected it.
Common causes:

- Faucet coin already spent in another transaction (race).
- Network unstable / mempool busy.

The manifest is **NOT** persisted on push failure — re-run the deploy.

---

## Security checklist

After Phase A deployment, the protocol's trust anchors are:

1. **The PGT TAIL hash** — curried with the chosen genesis coin id;
   never spent twice.
2. **The tracker singleton's launcher id** — and therefore its full
   puzzle hash.
3. **The DID singleton's launcher id** — curried into both the
   tracker and future deed launchers.

These three IDs are **immutable** for the life of this deployment.

After Phase B (when launched), additional trust anchors:

4. **A.3 protocol-config launcher id** — content-hash commitment.
5. **A.2 admin-authority launcher id** — admin allowlist commitment.
6. **A.4 property-registry launcher id** — registration log root.

All six are simultaneously published on `GET /protocol` and
`GET /admin/auth/authority` once the corresponding env vars are set,
so third-party verifiers can pin them.

---

## Cross-references

- **`README.md`** — endpoint reference, EIP-712 domain, quick-start.
- **`ADMIN_README.md`** — day-to-day operations after genesis.
- **`SECURITY.md`** — full POP-CANON-* audit trail and A.x phase status.
- **`docs/ADMIN_DESK_DESIGN.md`** — the JWT model rationale.
- **`../populis_protocol/docs/TESTNET_DEPLOYMENT.md`** — the original
  deployment runbook this guide subsumes; kept for historical context.
- **`../populis_protocol/docs/TESTNET_SETUP.md`** — chia testnet11
  full-node setup if you're not using coinset.org.

## Tests

- `populis_protocol/tests/test_protocol_deployment.py` — plan derivation,
  manifest round-trip, bundle structure, governance puzzle curry verification.
- `populis_api/tests/test_admin_unit.py` — admin auth gates, coin
  selection, schema validation.
- `populis_protocol/tests/test_admin_authority.py` — A.2 m-of-n
  rotation, replay protection, signing-message derivation, CLVM-level
  quorum guards (35 tests).
- `populis_protocol/tests/test_protocol_config.py` — A.3 content-hash
  determinism, governance-signed updates.
- `populis_protocol/tests/test_property_registry.py` — A.4 append-only
  log semantics, canonicalisation, replay rejection (27 tests).
- `populis_protocol/tests/test_mint_proposal.py` — A.1 per-proposal
  state machine (38 tests).
- `populis_api/tests/test_singletons.py` — cross-repo mod-hash contract
  + `/protocol` endpoint integration (8 tests).

End-to-end testnet11 testing is left as a manual smoke test (the
verification curl above).
