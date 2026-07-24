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
- `SOLSLOT_PAYMENT_EVM_USDC_TOKENS` must contain exactly one binding when the
  omnichain rail is enabled. Alpha binds Base Sepolia chain `84532` to Circle
  USDC `0x036CbD53842c5426634e7929541eC2318f3dCF7e` and accepts no USDT.
- `SOLSLOT_PAYMENT_OMNICHAIN_ENABLED` remains false until the separately
  deployed CCIP/Warp rail is approved. Enabling it also requires
  `SOLSLOT_PAYMENT_OMNICHAIN_PREFLIGHT_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_ACTIVATION_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_GOVERNANCE_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_SAMUEL_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_OWNERSHIP_INTENT_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_SOURCE_SHA`, and
  `SOLSLOT_PAYMENT_OMNICHAIN_GATEWAY_PROFILE`; the API verifies the evidence
  hashes, source SHA, chain, token, gateway profile, runtime-code descriptors,
  and a post-handoff governance-ownership attestation before it quotes or
  finalizes an EVM buy. RC19 requires schema-v2 owner-required governance:
  slot 0 owns a 1-of-1 Owner Identity Safe, slots 1 and 2 own a 1-of-2 Coadmin
  Safe, and those child Safes own a 2-of-2 root Safe. The API rejects the old
  flat 2-of-3 Safe, pre-RC19 rail schemas, guardian key reuse, incorrect Safe
  thresholds, missing seven-day recovery acceptance, and any payout or
  timelock role not bound to the root Safe.
- The one-shot ownership handoff desk is separately gated by
  `SOLSLOT_PAYMENT_OMNICHAIN_OWNERSHIP_ACTIVATION_ENABLED`. It requires the
  reviewed Safe-operation path and exact artifact hash. Administrators sign
  the actual nested Safe messages in the portal; the API stores no EVM private
  key and accepts a broadcast receipt only when the Root Safe destination and
  calldata match the reconstructed sealed transaction.
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
