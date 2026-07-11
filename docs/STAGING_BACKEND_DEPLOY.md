# Staging Backend Deploy Runbook

Staging backend deploys are owned by `MattHintz/solslot-api` on the `staging`
branch. Do not patch the API from the frontend repo except for an explicitly
temporary emergency.

## Normal Deploy

1. Work in a clean clone of `MattHintz/solslot-api` on `staging`.
2. Run focused tests locally before pushing.
3. Commit and push to `staging`.
4. Watch the workflow:

```bash
gh run list -R MattHintz/solslot-api --workflow "Staging Backend Deploy" --limit 5
gh run watch <run-id> -R MattHintz/solslot-api --exit-status
```

The workflow packages a release, uploads it to the AWS staging host, switches
`/opt/solslot/api-staging/current`, restarts the staging systemd service, and
checks both local and public `/health` plus OpenAPI.

For changes to identity enrollment, the minimum local gate is:

```bash
python -m pytest \
  tests/test_zkpassport_enrollments.py \
  tests/test_zkpassport_relay.py \
  tests/test_zkpassport_validator.py -q
```

The end-to-end state and failure rules are defined in
[`ZKPASSPORT_CHIA_VAULT_ATTESTATION.md`](ZKPASSPORT_CHIA_VAULT_ATTESTATION.md).

## Verification

```bash
curl -fsS https://staging.solslot.com/protocol-api/health
curl -fsS https://staging.solslot.com/protocol-api/openapi.json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["info"]["title"]); print("/zkpassport/enrollments" in d["paths"])'

curl -fsS -X POST https://staging.solslot.com/protocol-api/auth/challenge \
  -H 'content-type: application/json' \
  --data '{"address":"0x1234567890123456789012345678901234567890","auth_type":"evm"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["typed_data"]["primaryType"])'
```

Expected registration primary type is `SolslotVaultRegister`. The legacy
`PopulisVaultSpend` typehash may still appear in `/protocol` until a versioned
protocol migration replaces that in-puzzle spend type.

## zkPassport Bridge Pool

The enrollment endpoint fails closed until unspent bridge coins exist at the
configured bridge policy hash. The API now auto-discovers those coins from
Coinset and reserves by full bridge coin id. The old
`SOLSLOT_ZKPASSPORT_BRIDGE_PARENT_IDS` environment variable remains only as an
emergency static override.

Staging deploys set `POPULIS_ZKPASSPORT_BRIDGE_AUTO_TOPUP_ENABLED=true`, so a
testnet11 enrollment request can create a fresh bridge batch from the staging
faucet when every discovered bridge coin is already reserved. This is disabled
by default in code and must remain off for mainnet.

1. Confirm bridge coins exist at the configured bridge policy hash:

```bash
curl -fsS -X POST https://testnet11.api.coinset.org/get_coin_records_by_puzzle_hash \
  -H 'content-type: application/json' \
  --data '{"puzzle_hash":"0xc87f45cd23d052c88256de8823a4a01f40da4e2066156f48f3b3dfc0a50350d7","include_spent_coins":false}' \
  | python3 -m json.tool
```

2. If the pool is empty or fully reserved and auto-top-up is unavailable, create
   more bridge coins from the staging faucet. Prefer the GitHub deploy
   workflow's top-up inputs so the admin token never leaves the staging host:

```bash
gh workflow run deploy-staging.yml \
  -R MattHintz/solslot-api \
  --ref staging \
  -f bridge_pool_topup_count=6 \
  -f bridge_pool_topup_start_amount=1 \
  -f bridge_pool_topup_dry_run=true
```

Then run the same workflow with `bridge_pool_topup_dry_run=false`.

If SSH is unavailable but you already have the admin token locally, the
equivalent direct API call is:

```bash
curl -fsS -X POST https://staging.solslot.com/protocol-api/admin/zkpassport/bridge-pool/top-up \
  -H "authorization: Bearer $SOLSLOT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"count":6,"start_amount":1,"dry_run":true}' \
  | python3 -m json.tool
```

Then push directly:

```bash
curl -fsS -X POST https://staging.solslot.com/protocol-api/admin/zkpassport/bridge-pool/top-up \
  -H "authorization: Bearer $SOLSLOT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"count":6,"start_amount":1,"dry_run":false}' \
  | python3 -m json.tool
```

3. Verify reservation succeeds:

```bash
curl -fsS -X POST https://staging.solslot.com/protocol-api/zkpassport/enrollments \
  -H 'content-type: application/json' \
  --data '{"vaultLauncherId":"0x5807c4716d82028ed3c2e47d46f87d815a975120443bdab827ae29f64454df7d"}' \
  | python3 -m json.tool
```

Each top-up creates several bridge coins from one faucet parent with distinct
amounts. The amount is part of the coin id and EVM attestation, so those bridge
coins can be reserved independently without hand-editing server config.

## Rollback

Use the workflow rollback input rather than SSH:

```bash
gh workflow run deploy-staging.yml \
  -R MattHintz/solslot-api \
  --ref staging \
  -f rollback_sha=<existing-release-sha>
```

Then rerun the verification checks above.
