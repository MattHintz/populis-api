# Populis Genesis — First-Time Protocol Deployment

> One-shot bootstrap runbook for spinning up a new Populis deployment
> from a fresh chain.  Once these steps are done, day-to-day operations
> live in **`ADMIN_README.md`**.

A complete Populis genesis comprises **seven** on-chain singletons /
coins, deployed in two phases:

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
