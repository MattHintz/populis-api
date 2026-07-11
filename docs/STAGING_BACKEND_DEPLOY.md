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

The enrollment endpoint fails closed with HTTP 503 until a bridge coin pool is
configured. Configure public bridge parent ids through the GitHub staging
environment, not by editing the server manually.

1. Confirm one-mojo bridge coins exist at the configured bridge policy hash:

```bash
curl -fsS -X POST https://testnet11.api.coinset.org/get_coin_records_by_puzzle_hash \
  -H 'content-type: application/json' \
  --data '{"puzzle_hash":"0xc87f45cd23d052c88256de8823a4a01f40da4e2066156f48f3b3dfc0a50350d7","include_spent_coins":false}' \
  | python3 -m json.tool
```

2. Use each unspent bridge coin's `coin.parent_coin_info` as a parent id.
   Do not use the bridge coin id, and do not use faucet fan-out coin ids unless
   they actually created a coin at the bridge policy hash.

3. Set the staging environment variable:

```bash
gh variable set SOLSLOT_ZKPASSPORT_BRIDGE_PARENT_IDS \
  -R MattHintz/solslot-api \
  --env staging \
  --body "0xc17c5ec22db8c526a99ef77d899d0134d06cef4992f4b3d67fa2caf25aa52ee2"
```

4. Rerun the staging backend workflow from `staging`.

5. Verify reservation succeeds:

```bash
curl -fsS -X POST https://staging.solslot.com/protocol-api/zkpassport/enrollments \
  -H 'content-type: application/json' \
  --data '{"vaultLauncherId":"0x5807c4716d82028ed3c2e47d46f87d815a975120443bdab827ae29f64454df7d"}' \
  | python3 -m json.tool
```

One parent id reserves one vault enrollment. Add more unspent bridge parent ids
before broader testing.

## Rollback

Use the workflow rollback input rather than SSH:

```bash
gh workflow run deploy-staging.yml \
  -R MattHintz/solslot-api \
  --ref staging \
  -f rollback_sha=<existing-release-sha>
```

Then rerun the verification checks above.
