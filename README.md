# Populis API

Backend for the Populis Portal.  Turns EVM and Chia wallet signatures
into launched vault singletons on Chia testnet11 (via coinset.org),
plus operator endpoints for genesis deployment and mint-proposal
persistence used by the admin desk.

> **Phase 9-Hermes-D**: the portal now owns the admin-desk UX (mint
> proposals, trust roots, key rotation) and reads on-chain state
> directly from coinset.org via WASM.  The endpoints under
> `/admin/mint/*` and the `/admin/auth/*` flow remain for backward
> compat with the legacy server-side admin tooling, but the canonical
> operator path is now the portal's WASM-first flow.

> **Operator audience?**  Skip ahead:
> - **`GENESIS_README.md`** — first-time protocol bootstrap (PGT, pool, governance, A.2/A.3/A.4 singletons).
> - **`ADMIN_README.md`** — day-to-day admin-desk operations (JWT, mint proposals, key rotation).
> - **`SECURITY.md`** — full audit trail (POP-CANON-* findings, A.x phase status).

## What it does

1. **User onboarding** — issues short-lived challenge nonces + EIP-712
   typed-data envelopes for the frontend to sign.
2. **Vault creation** — recovers the user's secp256k1 public key from
   the signed EIP-712 payload (server-side ecrecover) — this is what
   Populis curries into the vault singleton as `OWNER_PUBKEY` for
   `AUTH_TYPE_SECP256K1`.
3. **Launcher broadcast** — selects an unspent XCH coin from the
   configured **faucet**, builds a signed two-coin launcher bundle
   (parent + launcher), and broadcasts to coinset.org's `push_tx`.
   The faucet's per-spend cap is enforced at coin selection time, and
   a configurable opt-in worker periodically consolidates the
   faucet's UTXO set so registration cost stays constant as volume
   grows.
4. **Registry persistence** — registered vaults live in a SQLite
   database (WAL mode, indexed reverse lookup by EVM address) so
   state survives process restart.  Frontends poll
   `GET /vault/{launcher_id}` for confirmation status;
   `GET /vault/by-evm/{address}` returns the vault for a given
   owner key.
5. **Admin desk + genesis deploy** — operator endpoints under
   `/admin/*` provide the one-shot genesis deployment helper plus a
   server-side mint-proposal store retained for backward compat.
   Trust-root singleton state (admin-authority v1+v2, protocol-config,
   property-registry, mint-proposal) is exposed read-only via
   `/admin/auth/authority` and `/admin/auth/authority_v2` so the
   portal (and any external monitor) can verify the on-chain quorum
   without re-implementing the singleton-walker logic.

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

### Admin (JWT-gated — see `ADMIN_README.md`)

| Method | Path | Purpose |
|--------|------|---------|
| POST   | `/admin/auth/challenge` | Issue admin login nonce |
| POST   | `/admin/auth/login` | Verify wallet sig → return short-lived JWT |
| POST   | `/admin/auth/refresh` | Refresh active JWT |
| POST   | `/admin/mint/propose` | Create a mint proposal (DRAFT) |
| GET    | `/admin/mint`, `/admin/mint/{id}` | List / read mint proposals |
| POST   | `/admin/mint/{id}/cancel` | Cancel a DRAFT proposal |
| POST   | `/admin/mint/{id}/publish` | DRAFT → APPROVED |
| POST   | `/admin/mint/{id}/execute` | APPROVED → EXECUTED |
| GET    | `/admin/committee/proposals` | Public committee view (no auth — for the PGT-VOTE flow) |
| POST   | `/admin/committee/vote` | Submit a PGT-VOTE bundle |

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

Typehash (for actual vault spends, not registration):
```
PopulisVaultSpend(bytes32 spend_case,bytes32 deed_launcher_id,bytes32 vault_coin_id)
```

The portal uses a separate, simpler typehash for onboarding:
```
PopulisVaultRegister(address owner,bytes32 nonce)
```

## Tests

```bash
.venv/bin/pytest tests/ -v
```
