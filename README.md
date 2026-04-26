# Populis API

Backend for the Populis Portal.  Turns EVM and Chia wallet signatures into
launched vault singletons on Chia testnet11 (via coinset.org).

## What it does

1. Issues short-lived challenge nonces + EIP-712 typed-data envelopes for
   the frontend to sign.
2. Recovers the user's secp256k1 public key from the signed EIP-712 payload
   (server-side ecrecover) — this is what Populis curries into the vault
   singleton as `OWNER_PUBKEY` for `AUTH_TYPE_SECP256K1`.
3. Selects an unspent XCH coin from the configured **faucet**, builds a
   signed two-coin launcher bundle (parent + launcher), and broadcasts to
   coinset.org's `push_tx`.  The faucet's per-spend cap is enforced at
   coin selection time, and a configurable opt-in worker periodically
   consolidates the faucet's UTXO set so registration cost stays
   constant as volume grows.
4. Persists registered vaults in a SQLite database (WAL mode, indexed
   reverse lookup by EVM address) so registry state survives process
   restart.  Frontends poll `GET /vault/{launcher_id}` for confirmation
   status; `GET /vault/by-evm/{address}` returns the vault for a given
   owner key.

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

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/health` | Backend liveness + chain peak |
| GET    | `/protocol` | Pool launcher id, vault mod hash, EIP-712 domain, faucet address + balance |
| POST   | `/auth/challenge` | Issue nonce + EIP-712 typed data |
| POST   | `/vault/register/evm` | Recover secp256k1 pubkey → build + push launcher |
| POST   | `/vault/register/chia` | Verify BLS signature → build + push launcher |
| GET    | `/vault/{launcher_id}` | Vault state (confirmed, current coin id, balance) |
| GET    | `/vault/by-evm/{address}` | Look up vault by owner EVM address |

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
