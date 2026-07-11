# Populis API

FastAPI service for the parts of Populis that still need a server-side
wallet: faucet-funded vault launcher spends, EIP-712/BLS registration
challenges, persisted vault registration status, and operator bootstrap
helpers.

> **Phase 9-Hermes-D**: the portal now owns the admin-desk UX (mint
> proposal drafts, trust roots, admin-authority-v2 launch, and key
> rotation flows) and reads Chia state directly from coinset.org via
> `chia-wallet-sdk-wasm`.  The API's `/admin/auth/*` and
> `/admin/mint/*` endpoints are compatibility surfaces for the older
> server-side admin desk, not the canonical operator path.

> **Operator audience?**  Skip ahead:
> - **`GENESIS_README.md`** — first-time protocol bootstrap (PGT, pool, governance, A.2/A.3/A.4 singletons).
> - **`ADMIN_README.md`** — day-to-day admin-desk operations (JWT, mint proposals, key rotation).
> - **`SECURITY.md`** — full audit trail (POP-CANON-* findings, A.x phase status).

## Current technical scope

1. **Registration challenges** — issues short-lived nonces plus the
   EIP-712 typed data or BLS message the portal asks the wallet to
   sign.
2. **Faucet-funded vault launches** — verifies the wallet signature,
   recovers or checks the owner pubkey, selects a faucet coin, builds
   the parent + singleton-launcher spend bundle, signs the faucet
   spend, and pushes the bundle to coinset.org.
3. **Registration persistence** — records launched vaults in SQLite
   so callers can look up the API-observed launch result by launcher
   id or EVM address.  The current portal also performs chain-native
   discovery after registration using CHIP-22 hints and singleton
   lineage reads from coinset.org.
4. **Protocol/bootstrap metadata** — exposes `/health`, `/protocol`,
   the deployment manifest, faucet address/balance, protocol puzzle
   hashes, and optional A.x trust-root coordinates.
5. **Operator bootstrap** — keeps the static-token gated genesis
   helper (`/admin/deploy/protocol`) for first-time testnet
   deployments.
6. **Legacy admin compatibility** — keeps JWT login and the
   SQLite-backed mint-proposal CRUD endpoints for older tooling.
   `propose`, `list`, `read`, and DRAFT `cancel` are implemented;
   chain-moving `publish`, `execute`, and committee `vote` currently
   return `501` placeholders.

## Quick start

```bash
# 1. Populis protocol must already be importable from the same venv.
cd populis_api
python3 -m venv .venv
.venv/bin/pip install -e . -e ../populis_protocol

# 2. Configure
cp .env.example .env
# — Fill in POPULIS_FAUCET_SEED_HEX or POPULIS_FAUCET_MNEMONIC
# — Fund the faucet address the server logs on boot from
#   https://testnet11-faucet.chia.net

# 3. Run
.venv/bin/uvicorn populis_api.app:app --host 0.0.0.0 --port 8787 --reload
```

Server docs at `http://localhost:8787/docs`.

## Endpoints

### Public

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/health` | Backend liveness + chain peak |
| GET    | `/protocol` | Pool launcher id, vault mod hash, EIP-712 domain, faucet address + balance, **A.3** `protocol_config_hash`, **A.4** `property_registry_launcher_id` + `property_registry_mod_hash`, **A.1** `mint_proposal_mod_hash` |
| POST   | `/auth/challenge` | Issue nonce + EIP-712 typed data |
| POST   | `/vault/register/evm` | Recover secp256k1 pubkey → build + push launcher |
| POST   | `/vault/register/chia` | Verify BLS signature → build + push launcher |
| GET    | `/vault/{launcher_id}` | Vault state (confirmed, current coin id, balance) |
| GET    | `/vault/by-evm/{address}` | Look up vault by owner EVM address |
| GET    | `/admin/auth/authority` | **A.2 v1** public snapshot of the on-chain admin-authority singleton state (BLS m-of-n) |
| GET    | `/admin/auth/authority_v2` | **A.2 v2** public snapshot of the CHIP-0043 MIPS quorum admin-authority singleton (used by the portal's `/admin/login` flow to cross-check the env-pinned MIPS root) |

### Legacy admin compatibility (JWT-gated — see `ADMIN_README.md`)

| Method | Path | Purpose |
|--------|------|---------|
| POST   | `/admin/auth/challenge` | Issue admin login nonce |
| POST   | `/admin/auth/login` | Verify wallet sig → return short-lived JWT |
| POST   | `/admin/auth/refresh` | Refresh active JWT |
| POST   | `/admin/auth/eip712/compute_leaf_hash` | Deterministic Eip712Member leaf-hash helper for admin-authority-v2 records |
| POST   | `/admin/mint/propose` | Create a mint proposal (DRAFT) |
| GET    | `/admin/mint`, `/admin/mint/{id}` | List / read mint proposals |
| POST   | `/admin/mint/{id}/cancel` | Cancel a DRAFT proposal |
| POST   | `/admin/mint/{id}/publish` | `501` placeholder; chain publish moved to client/WASM work |
| POST   | `/admin/mint/{id}/execute` | `501` placeholder; chain execute moved to client/WASM work |
| GET    | `/admin/committee/proposals` | Public committee view (no auth — for the PGT-VOTE flow) |
| POST   | `/admin/committee/vote` | `501` placeholder for PGT-VOTE bundle submission |

### Operator (admin-token-gated — see `GENESIS_README.md`)

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/admin/deployment` | Read current deployment manifest |
| POST   | `/admin/deploy/protocol` | One-shot atomic genesis (PGT + pool + DID + governance) |

## EIP-712 domain

Must be identical on the backend and in `populis_puzzles/vault_driver.py`:

```
name:    "Populis Protocol"
version: "1"
chainId: 1
```

Legacy protocol spend typehash, kept for existing wallet/protocol compatibility:
```
PopulisVaultSpend(bytes32 spend_case,bytes32 deed_launcher_id,bytes32 vault_coin_id)
```

The portal uses a separate, simpler typehash for onboarding:
```
SolslotVaultRegister(address owner,bytes32 nonce,bytes32 poolLauncherId,string authType,string chiaNetwork)
```

## Tests

```bash
.venv/bin/pytest tests/ -v
```
