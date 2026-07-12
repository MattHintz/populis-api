# Solslot API Staging Deployment

The canonical backend deploy is `.github/workflows/deploy-staging.yml` in the
API repository. Do not copy individual Python files to the host and do not
deploy from either frontend repository.

## Release Contract

Every normal deploy:

1. Checks out the API commit and an exact 40-character protocol commit.
2. Installs both in an isolated Python 3.12 environment.
3. Runs compile/import smoke, full pytest, namespace scan, and secret scan.
4. Writes `release.json` with API commit, protocol commit, repositories,
   package, app module, and UTC build time.
5. Packages the complete release and scans the archive again.
6. Uploads to `/tmp/solslot-api-release-<sha>.tgz`.
7. Extracts to `/opt/solslot/api-staging/releases/<sha>/` and builds a fresh
   release virtual environment.
8. Validates OpenAPI before switching the `current` symlink.
9. Restarts `solslot-api-staging.service`.
10. Verifies local and public health and OpenAPI through `/protocol-api`.
11. Keeps the five newest releases for rollback.

The systemd unit must run:

```text
/opt/solslot/api-staging/current/.venv/bin/uvicorn solslot_api.app:app --host 127.0.0.1 --port 8790
```

## Persistent Layout

```text
/opt/solslot/api-staging/
  current -> releases/<sha>
  releases/<sha>/
  shared/
    state/
      deployment_manifest_v2.json
      bootstrap_manifest_v2.json
      admin_records_v2.json
      portal_runtime_config_v2.json
      bootstrap_recovery_anchor_v2.json
      vault_registry_v2.db
      admin_desk_v2.db
      zkpassport_v2.db
```

The environment file is outside release directories and must be mode `0600`.
State files are never packaged, copied from an earlier ceremony, or deleted by
release cleanup.

## Required GitHub Configuration

The `staging` environment holds SSH secrets. Repository variables pin the
expected host, service, release root, port, and exact protocol commit. The
workflow refuses a host-name mismatch or branch-like protocol reference.

No passphrase, private key, bearer token, seed, or RPC secret belongs in a
workflow variable, source file, release archive, or issue log.

## Bridge Pool

Enrollment discovers confirmed unspent coins at the active bridge policy
hash. Static parent-ID configuration is not used. Public enrollment cannot
create coins or spend the faucet. Replenishment is a deliberate post-genesis
admin action through `/admin/zkpassport/bridge-pool/top-up` using a current
chain-bound admin JWT.

## Rollback

Dispatch the workflow with `rollback_sha` set to an existing release. Rollback
changes only the `current` symlink, restarts the service, and reruns local and
public checks. It does not roll back shared state or ceremony coordinates.

If a release changed persistent schema incompatibly, stop and restore from the
matching checksummed state backup rather than pointing old code at newer data.

## Diagnostics

Dispatch with `diagnostics_only=true` to print host identity, current release,
systemd status, recent journal lines, local health, zkPassport OpenAPI routes,
and shared-state inventory. A failed deploy prints the same evidence
automatically while the prior release remains available.
