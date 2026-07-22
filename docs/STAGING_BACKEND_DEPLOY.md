# Solslot API Staging Deployment

The canonical backend deploy is `.github/workflows/deploy-staging.yml` in the
API repository. Do not copy individual Python files to the host and do not
deploy from either frontend repository.

## Canonical Runtime Ownership

There is one staging API release path:

- Source: `MattHintz/solslot-api`, branch `staging`.
- Build and deploy: `.github/workflows/deploy-staging.yml`.
- Runtime package: `solslot_api`.
- Runtime unit: `solslot-api-staging.service`.
- Release root: `/opt/solslot/api-staging`.
- Public identity: `/protocol-api/release` must report the deployed API and
  frozen protocol commits.

Temporary clones, retired ceremony services, frontend workflows, and manual
file copies are not deployment authorities. If their output differs from the
public release endpoint, stop and diagnose the workflow target; do not patch a
second process.

An earlier staging experiment let public enrollment replenish an exhausted
bridge pool. That behavior is retired. The current security boundary is
intentional: enrollment only reserves existing confirmed coins, while
replenishment is an explicit chain-admin-authenticated operation.

## Release Contract

Every normal deploy:

1. Checks out the API commit and an exact 40-character protocol commit.
2. Installs both in an isolated Python 3.12 environment.
3. Runs compile/import smoke, full pytest, namespace scan, and secret scan.
4. Writes `release.json` with API commit, protocol commit, repositories,
   package, app module, and a UTC build epoch normalized to the API commit.
5. Packages the complete release twice with normalized ownership, ordering,
   timestamps, and gzip headers; requires byte-for-byte equality; then scans
   the archive again.
6. Uploads to `/tmp/solslot-api-release-<sha>.tgz`.
7. Extracts to
   `/opt/solslot/api-staging/releases/<api-sha>-<protocol-prefix>/` and builds
   a fresh release virtual environment. A ready release is immutable and may
   be reused; the workflow writes `.release-ready` only after metadata and
   import validation pass, and never removes the active release directory.
8. Validates OpenAPI in-process before switching the `current` symlink.
9. Installs and restarts `solslot-api-staging.service` under the dedicated
   `solslot-api` system account.
10. Verifies local/public health, security headers, release identity, loopback
    binding, locked write surfaces, blocked localhost CORS, and disabled
    OpenAPI and validator-metadata routes.
11. Writes a local-verification marker after local checks and promotes it to a
    full release-verification marker only after public checks, retains the
    previous target through that promotion, and restores it automatically if
    the external check fails.
12. Keeps the five newest releases for rollback.

The API release archive also contains the private signer application and host
templates, but the coordinator service always starts `solslot_api.app:app`.
It must never start or mount `solslot_api.validator_app:app`. Signers are
deployed independently on their private hosts using the same frozen archive.

The systemd unit must run:

```text
/opt/solslot/api-staging/current/.venv/bin/uvicorn solslot_api.app:app --host 127.0.0.1 --port 8790 --proxy-headers --forwarded-allow-ips 127.0.0.1 --timeout-keep-alive 5 --timeout-graceful-shutdown 30 --limit-concurrency 100 --backlog 256 --no-server-header
```

Do not add `--reload` or bind to `0.0.0.0`. The current service intentionally
uses one worker because faucet coin selection is serialized in-process; adding
workers before that coordinator is process-safe can create conflicting spends.
Availability comes from systemd restart and atomic rollback, not unsafe worker
fan-out.

The workflow installs the complete unit, not a drop-in that depends on a
retired service. If local health or release identity fails after the symlink
switch, it restores the prior target before reporting failure.

## Persistent Layout

```text
/opt/solslot/api-staging/
  current -> releases/<api-sha>-<protocol-prefix>
  releases/<api-sha>-<protocol-prefix>/
    .release-ready
    .release-local-verified
    .release-verified
    release.json
  shared/
    .env
    deployments/
      <active transaction>.previous
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
cookies, HSTS/security headers, the reviewed Cloudflare IPv4 and IPv6 source
ranges, a 4 MiB application body limit, and a 30 second request timeout in the
systemd unit. Staging startup fails if the proxy pin is absent, public docs or
development CORS are enabled, cookies are insecure, or security headers are
disabled. The effective service environment must include:

```text
SOLSLOT_API_DOCS_ENABLED=false
SOLSLOT_SECURITY_HEADERS_ENABLED=true
SOLSLOT_HSTS_ENABLED=true
SOLSLOT_VAULT_SESSION_COOKIE_SECURE=true
SOLSLOT_TRUSTED_PROXY_CIDRS=<reviewed Cloudflare IPv4 and IPv6 ranges>
SOLSLOT_CORS_ORIGINS=https://staging.solslot.com
SOLSLOT_MAX_REQUEST_BODY_BYTES=4194304
SOLSLOT_REQUEST_TIMEOUT_SECONDS=30
SOLSLOT_CHALLENGE_STORE_PATH=/opt/solslot/api-staging/shared/state/challenges_v2.db
```

The challenge database is SQLite-WAL state shared by vault registration and
admin-login namespaces. It makes issuance quotas and nonce consumption atomic
across process restarts and future worker fan-out. Never place it inside a
release directory or replace it during a code rollback.

The Cloudflare range pin is non-secret infrastructure configuration. Its
versioned value lives in the staging workflow and is sourced from
`https://api.cloudflare.com/client/v4/ips`. Compare it with that endpoint
before each release candidate and whenever Cloudflare announces an address
change. Do not replace it with a broad public range or a forwarded-header
wildcard.

The staging unit overrides any stale CORS value in the shared environment and
permits only `https://staging.solslot.com`, without credentialed cross-origin
requests. The production unit is independently pinned to the production
origin; do not combine development, staging, and production origins in one
runtime setting.

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

The `staging` environment holds SSH secrets. Environment variables pin the
expected host, service, release root, port, retired API host, and exact
protocol commit. Environment values take precedence over repository values;
update and verify both scopes when a pin exists in both. The workflow refuses
a host-name mismatch or branch-like protocol reference.

No passphrase, private key, bearer token, seed, or RPC secret belongs in a
workflow variable, source file, release archive, or issue log.

The coordinator preflight rejects validator seed configuration in its private
environment, conventional signer-host seed paths, and actual `.seed` files in
release or shared state. Public seed-generation tooling is intentionally part
of the release archive so operators can prepare signer hosts offline; its
filename is not evidence that a private seed is present.

Reusable credentials follow
`docs/CREDENTIAL_CARRYOVER_RC2_20260714.md`. A release does not trigger blanket
rotation. The exposed provider credential must be revoked and replaced; new
signer and private-network credentials are installed directly on their target
hosts.

## Bridge Pool

Enrollment discovers confirmed unspent coins at the active bridge policy
hash. Static parent-ID configuration is not used. Public enrollment cannot
create coins or spend the faucet. Replenishment is a deliberate post-genesis
admin action through `/admin/zkpassport/bridge-pool/top-up` using a current
chain-bound admin JWT plus a single-use slot-0-and-one-coadmin operation
approval.

## Rollback

Dispatch the workflow with `rollback_sha` set to an existing release ID of the
form `<api-sha>-<protocol-prefix>`. Rollback changes only the `current`
symlink, restarts the service, and reruns local and public checks. It does not
roll back shared state or ceremony coordinates.

Rollback refuses any directory without `.release-ready` or whose
`release.json` does not exactly match the requested API and protocol commits.
It also requires `.release-verified`, so an archive that imported successfully
but failed runtime or public acceptance can never become a rollback target.
Rollback itself is transactional: local and public identity/security checks
must pass, otherwise the pre-rollback release is restored.

If a release changed persistent schema incompatibly, stop and restore from the
matching checksummed state backup rather than pointing old code at newer data.

## Diagnostics

Dispatch with `diagnostics_only=true` to print host identity, current release,
systemd status, recent journal lines, local health, zkPassport OpenAPI routes,
and shared-state inventory. A failed deploy prints the same evidence
automatically while the prior release remains available.
