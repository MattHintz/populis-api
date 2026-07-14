# Alpha Audit Remediation Status

This ledger is the shared checkpoint for security work that spans the API,
protocol, EVM contracts, customer web, admin portal, DNS, and staging host.
It records containment separately from final closure so a disabled feature is
never mistaken for a completed launch control.

## Canonical Live Baseline

- API release: `37b82ba46c0e2ce1d387f73127c2c3b785c44767`.
- Protocol dependency: `9b0a411c035ee23fca197b2de20122eeaabfafdf`.
- Runtime: `solslot-api-staging.service` under `/opt/solslot/api-staging`.
- Network binding: Chia `testnet11` and Ethereum Sepolia `11155111`.
- Public API documentation: disabled.
- Alpha writes and minting: disabled.
- Validator: unconfigured on the clean staging state.
- Ceremony coordinates: absent; the vulnerable deployment is not reused.

## Canonical Security Branches

- API: `238d2fa` on `security/alpha-v2-remediation`; 507 tests pass.
- Protocol: `8d8c2ce` on `security/alpha-v2-remediation`; 716 tests pass.
- EVM: `1f33083` on `security/alpha-v2-remediation`; 14 tests and the
  provider-credential gate pass.
- Customer web: `2a29fca` on `security/alpha-v2-remediation`; 202 tests,
  production build, source namespace gate, and compiled-release namespace
  gate pass.
- Admin portal: `15cd90b` on `security/alpha-v2-remediation`; 792 tests,
  production build, source namespace gate, and compiled-release namespace
  gate pass.
- Six cross-repository V2 schema contracts pass across protocol, API, EVM,
  customer web, and admin portal. The EVM emitter accepts only enrollment
  binding data, derives proof fields from the verifier adapter, and computes
  credential commitments internally.
- All five namespace gates now reject plain-text and hex-encoded retired
  namespace material. The portal's stale V1 bootstrap memo bytes were removed,
  and every active protocol announcement reader/builder uses prefix `0x53`.

## Finding Ledger

| Finding | State | Evidence or remaining gate |
| --- | --- | --- |
| C-1 provider credential in EVM history | History fixed, provider revocation open | Both public EVM branches use scrubbed ancestry, current config is environment-only, CI rejects provider credentials, and the canonical local object database no longer contains the retired blob. A private mode-0400 pre-scrub bundle preserves evidence. The provider account owner must still revoke the credential. |
| C-2 portal runtime coordinates | Contained | Public runtime files no longer contain active admin or ceremony coordinates. Fresh V2 coordinates may be published only through the signed ceremony artifact. |
| C-3 retired pro-origin API | Contained, verification open | The reported API surface is not present on the reviewed staging runtime. The unrelated pro host must remain outside the protocol trust boundary and must not expose API mutation routes or wildcard CORS. |
| C-4 challenge throttling | Code fixed, live write test pending | SQLite-WAL quotas persist across restarts and use the proxy-normalized peer IP. A 100-request concurrent regression admits exactly the configured 12 requests. Writes are locked, so the public 429 saturation smoke is deferred until the controlled prelaunch window. |
| H-1 raw protocol manifest disclosure | Fixed live | `/protocol` returns typed public coordinates only; faucet fields and the raw manifest are null. |
| H-2 authority commitment disclosure | Risk removed from current staging | Authority is disabled and all fields are null. Future launcher and commitment hashes are public on-chain verification data, never an authorization source. Admin records and Merkle paths remain private. |
| H-3 public database listener | Fixed live | Port 3306 is not reachable publicly; the database listener is loopback-only. |
| H-4 permissive CORS | Fixed live | Staging accepts exact HTTPS origins only, rejects wildcard headers, and normalizes forwarding headers at the proxy. |
| H-5 validator threshold one | Contained | Clean staging has no validator. Mainnet production refuses to start below threshold two; the fresh ceremony must use independent keys and a matching bridge policy. |
| M-1 academy DNS 1014 | DNS fixed, Intercom activation open | The Intercom CNAME is DNS-only and resolves correctly. The Intercom workspace must finish custom-domain validation and certificate activation before closure. |
| M-2 malformed enrollment 500 | Fixed live | Malformed launcher paths return 422. |
| Committee endpoints | Protocol-authenticated by design | Read access and signed-bundle forwarding are public; the API cannot create SGT authority. Consensus and signature tests remain part of the launch gate. |
| JWT refresh window | Fixed | Every authenticated request and refresh rechecks current hash-verified admin records, so removal revokes an otherwise unexpired token. |
| Missing HSTS and server bounds | Fixed live | HSTS, CSP, no-sniff, frame denial, no-store, body cap, timeout, concurrency cap, and loopback binding are enforced. |

## Thread Convergence

Bridge auto-top-up commit `1261d8f` is an ancestor of the canonical API
branch, not a competing release. Its useful bridge allocation and admin-route
work remains in history. The later V2 security cutover intentionally removed
public faucet spending and retained only the chain-admin-authenticated top-up
route.

The clean API cutover initially omitted the already-reviewed mint collection,
share-PPM, and publish-validation schema from the older checkout. API commit
`b1d6256` restores that bounded work with Solslot-only settings, a versioned
SQLite migration, structured CLVM validation, and cross-repo drift tests.

The frontend work is now converged as two intentional repositories, not two
competing implementations. `solslot/solslot` owns the customer experience and
vault-owner proof flow. `MattHintz/solslot-portal` owns administration,
governance, ceremony review, and protocol tooling. The admin portal's CLVM
modules were regenerated from protocol commit `8d8c2ce` before its final test
and build pass.

No work should target temporary staging-fix directories or retired runtime
units. Before changing staging, compare the local commit to `/protocol-api/release`
and use workflow diagnostics when they differ.

## Launch Blockers

Alpha remains blocked on the clean V2 protocol and EVM re-audit, provider-key
revocation, portal/customer-web convergence, secret rotation, signed ceremony
artifacts, fresh contract and singleton deployment, and complete EVM plus BLS
zkPassport-to-Chia confirmation with storage-free recovery.

No current browser result is accepted as full-cycle credential success. That
gate requires a fresh V2 EVM vault and a fresh V2 BLS vault to reach
`chia_confirmed`, recover from Chia plus the API with browser storage cleared,
and remain bound to the current singleton coin and reconstructed puzzle hash.
