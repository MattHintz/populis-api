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
8. Validates OpenAPI in-process before switching the `current` symlink.
9. Restarts `solslot-api-staging.service`.
10. Verifies local/public health, security headers, release identity, and that
    public OpenAPI routes are disabled.
11. Keeps the five newest releases for rollback.

The systemd unit must run:

```text
/opt/solslot/api-staging/current/.venv/bin/uvicorn solslot_api.app:app --host 127.0.0.1 --port 8790 --proxy-headers --forwarded-allow-ips 127.0.0.1 --timeout-keep-alive 5 --timeout-graceful-shutdown 30 --limit-concurrency 100 --backlog 256 --no-server-header
```

Do not add `--reload` or bind to `0.0.0.0`. The current service intentionally
uses one worker because faucet coin selection is serialized in-process; adding
workers before that coordinator is process-safe can create conflicting spends.
Availability comes from systemd restart and atomic rollback, not unsafe worker
fan-out.

## Persistent Layout

```text
/opt/solslot/api-staging/
  current -> releases/<sha>
  releases/<sha>/
  shared/
    .env
    state/
      deployment_manifest_v2.json
      bootstrap_manifest_v2.json
      admin_records_v2.json
      portal_runtime_config_v2.json
      bootstrap_recovery_anchor_v2.json
      vault_registry_v2.db
      admin_desk_v2.db
      challenges_v2.db
      zkpassport_v2.db
```

The environment file is outside release directories and must be mode `0600`.
State files are never packaged, copied from an earlier ceremony, or deleted by
release cleanup.

The workflow pins `SOLSLOT_RUNTIME_ENVIRONMENT=staging`, secure bootstrap
cookies, HSTS/security headers, a 4 MiB application body limit, and a 30 second
request timeout in the systemd drop-in. Staging startup fails if public docs,
development CORS, insecure cookies, or disabled security headers are detected.
The effective service environment must include:

```text
SOLSLOT_API_DOCS_ENABLED=false
SOLSLOT_SECURITY_HEADERS_ENABLED=true
SOLSLOT_HSTS_ENABLED=true
SOLSLOT_MAX_REQUEST_BODY_BYTES=4194304
SOLSLOT_REQUEST_TIMEOUT_SECONDS=30
SOLSLOT_CHALLENGE_STORE_PATH=/opt/solslot/api-staging/shared/state/challenges_v2.db
```

The challenge database is SQLite-WAL state shared by vault registration and
admin-login namespaces. It makes issuance quotas and nonce consumption atomic
across process restarts and future worker fan-out. Never place it inside a
release directory or replace it during a code rollback.

## Reverse Proxy Contract

The proxy is the only public listener. It must route `/protocol-api/` to
`127.0.0.1:8790`, overwrite forwarded headers, cap request bodies, bound client
and upstream timeouts, and enforce connection/request rates. The reviewed
nginx template is `docs/nginx/solslot-api-hardening.conf.example`. The current
Apache deployment uses `docs/apache/solslot-api-hardening.conf.example` and
must load `headers`, `proxy`, `remoteip`, `reqtimeout`, and `rewrite`. Validate
every proxy change with `apache2ctl configtest` before a graceful reload.

Host firewall rules must deny public access to port `8790`. Uvicorn trusts
forwarded headers only from `127.0.0.1`; client-supplied forwarding headers from
any other source are ignored.

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
