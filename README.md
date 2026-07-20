# Solslot API

Solslot API is the testnet protocol coordinator for vault registration,
chain-bound administrator authentication, mint proposals, protocol artifacts,
and anonymous zkPassport credential stamping.

The V2 cutover is intentionally breaking:

- Python imports use `solslot_api.*` and `solslot_puzzles.*` only.
- Runtime configuration uses `SOLSLOT_*` only.
- Protocol writes default to disabled.
- A valid, signed Solslot V2 ceremony artifact is required before vault,
  mint, offer, or credential writes can be enabled.
- Retired launchers, browser state, databases, bridge policies, contracts, and
  signatures are never migrated.

## Trust Boundaries

- Chia singleton state is authoritative for protocol coordinates and vault
  credentials.
- The API's SQLite-WAL indexes are recovery and anti-replay state, not a
  substitute for Chia confirmation.
- Admin JWTs are issued only to EIP-712 members in a records file whose
  launcher and hash match the current admin-authority singleton.
- The bootstrap operator token is limited to the run-once ceremony surface.
- zkPassport validator signing is internal. There is no public signing route.
- Offer artifacts require a current, server-confirmed Chia credential receipt.

## Protocol Payment Configuration

The coordinator is authoritative for protocol pricing and fulfillment terms.
Clients select a published deed and rail; they do not submit a price, launcher,
share allocation, or delivery address.

- `SOLSLOT_PAYMENT_ORACLE_ROUNDS_PATH` points to strict canonical XCH/CAT
  rounds. Native prices are accepted only with a live 2-of-3 BLS authorization
  from `SOLSLOT_PAYMENT_ORACLE_OPERATOR_PUBKEYS`.
- `SOLSLOT_PAYMENT_ORACLE_ALLOWED_CAT_ASSET_IDS` is the explicit native CAT
  allowlist.
- `SOLSLOT_PAYMENT_EVM_USDC_TOKENS` maps an EVM chain ID to its reviewed
  six-decimal test stablecoin contract.
- `SOLSLOT_PAYMENT_PURCHASE_DB_PATH` is the coordinator-owned SQLite-WAL
  purchase and replay ledger.
- `SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN` protects server-to-server purchase
  construction and finalization.

Native XCH and CAT purchases are completed as standard atomic Chia offer files.
The sealed USD target raise and deed share determine the exact integer USD
minor-unit price; the H-system oracle round converts that price to XCH mojos or
CAT base units. The offer requests those exact units and delivers exactly one
governed SmartDeed to the canonical vault puzzle hash in one atomic settlement.
Native offers do not pass through Samuel, Key of Solomon, or the EVM escrow.
EVM and Stripe use escrow-backed fulfillment, but must bind the same purchase
ID, artifact hash, deed launcher, vault launcher, destination, quantity, and
expiry.

## Local Verification

Create an isolated environment and pin the exact protocol checkout:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip wheel
.venv/bin/python -m pip install -c constraints.lock zstd==1.5.7.3
.venv/bin/python -m pip install -c constraints.lock -e ../solslot-protocol -e '.[dev]'
PYTHON=.venv/bin/python bash scripts/check_dependency_audit.sh
.venv/bin/python -m compileall -q solslot_api
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_namespace.py --paths .
```

`PYSEC-2026-1845` is ignored only while Chia's current
`chia-puzzles-py` release requires `pytest<9`; remove the waiver as soon as the
Chia dependency stack allows `pytest>=9.0.3`.
`zstd==1.5.7.3` is installed explicitly because Chia 2.7.x requires that
yanked wheel; remove the preinstall once Chia accepts a non-yanked `zstd`
release.

Start the API only with a fresh V2 state directory:

```bash
SOLSLOT_RUNTIME_ENVIRONMENT=development \
SOLSLOT_API_DOCS_ENABLED=true \
SOLSLOT_CORS_ORIGINS=http://localhost:4200 \
SOLSLOT_ALPHA_WRITES_ENABLED=false \
SOLSLOT_MINTING_ENABLED=false \
.venv/bin/uvicorn solslot_api.app:app --host 127.0.0.1 --port 5001
```

The release workflow verifies the OpenAPI schema in-process before deployment.
Staging and production disable `/docs`, `/redoc`, and `/openapi.json`; public
URLs remain under `/protocol-api` at the reverse proxy.

Production must use the systemd command and proxy limits in
[the staging deployment contract](docs/STAGING_BACKEND_DEPLOY.md). Never use
`--reload`, never bind the application to `0.0.0.0`, and never expose the
uvicorn port directly.

## Operator Documents

- [Security model](SECURITY.md)
- [Admin authority](ADMIN_README.md)
- [Clean genesis ceremony](GENESIS_README.md)
- [KoS MINT execute signer](docs/KOS_MINT_EXECUTE_SIGNER.md)
- [Staging deployment](docs/STAGING_BACKEND_DEPLOY.md)
- [zkPassport to Chia stamp](docs/ZKPASSPORT_CHIA_VAULT_ATTESTATION.md)

Minting remains disabled until the independent audit, namespace gate,
ceremony preflight, and live EVM/BLS smoke evidence all pass.
