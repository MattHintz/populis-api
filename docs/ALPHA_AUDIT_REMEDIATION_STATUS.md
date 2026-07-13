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

## Finding Ledger

| Finding | State | Evidence or remaining gate |
| --- | --- | --- |
| C-1 provider credential in EVM history | Contained, not closed | Current public config is environment-only and release scans reject provider credentials. A private read-only pre-scrub bundle exists. Published history still requires the prepared targeted rewrite, and the provider account owner must revoke the credential. |
| C-2 portal runtime coordinates | Contained | Public runtime files no longer contain active admin or ceremony coordinates. Fresh V2 coordinates may be published only through the signed ceremony artifact. |
| C-3 retired pro-origin API | Contained, verification open | The reported API surface is not present on the reviewed staging runtime. The unrelated pro host must remain outside the protocol trust boundary and must not expose API mutation routes or wildcard CORS. |
| C-4 challenge throttling | Code fixed, live write test pending | SQLite-WAL quotas persist across restarts and use the proxy-normalized peer IP. Writes are locked, so the public 429 saturation smoke is deferred until the controlled prelaunch window. |
| H-1 raw protocol manifest disclosure | Fixed live | `/protocol` returns typed public coordinates only; faucet fields and the raw manifest are null. |
| H-2 authority commitment disclosure | Risk removed from current staging | Authority is disabled and all fields are null. Future launcher and commitment hashes are public on-chain verification data, never an authorization source. Admin records and Merkle paths remain private. |
| H-3 public database listener | Fixed live | Port 3306 is not reachable publicly; the database listener is loopback-only. |
| H-4 permissive CORS | Fixed live | Staging accepts exact HTTPS origins only, rejects wildcard headers, and normalizes forwarding headers at the proxy. |
| H-5 validator threshold one | Contained | Clean staging has no validator. Mainnet production refuses to start below threshold two; the fresh ceremony must use independent keys and a matching bridge policy. |
| M-1 academy DNS 1014 | DNS repair pending propagation | The Intercom CNAME is DNS-only. The Intercom custom-domain status and certificate must become active before closure. |
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

No work should target temporary staging-fix directories or retired runtime
units. Before changing staging, compare the local commit to `/protocol-api/release`
and use workflow diagnostics when they differ.

## Launch Blockers

Alpha remains blocked on the clean V2 protocol and EVM re-audit, provider-key
revocation, portal/customer-web convergence, secret rotation, signed ceremony
artifacts, fresh contract and singleton deployment, and complete EVM plus BLS
zkPassport-to-Chia confirmation with storage-free recovery.
