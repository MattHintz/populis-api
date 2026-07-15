# Alpha Audit Remediation Status

This ledger is the shared checkpoint for security work that spans the API,
protocol, EVM contracts, customer web, admin portal, DNS, and staging host.
It records containment separately from final closure so a disabled feature is
never mistaken for a completed launch control.

## Deployed Locked Baseline

- API release: `8e2d697fc2164780d4f817ac7d913472c1f631e0`.
- Protocol dependency: `8d8c2ce508777317ccb27a5a62732ec6ade3f091`.
- Compound release ID:
  `8e2d697fc2164780d4f817ac7d913472c1f631e0-8d8c2ce50877`.
- Runtime: `solslot-api-staging.service` under `/opt/solslot/api-staging`.
- Network binding: Chia `testnet11` and Ethereum Sepolia `11155111`.
- Public API documentation: disabled.
- Alpha writes and minting: disabled.
- Validator: unconfigured on the locked staging state.
- Ceremony coordinates: absent; the vulnerable deployment is not reused.

## Candidate Security Worktrees

The candidate worktrees below are deliberately **not frozen**. They contain
the remediation implementation but remain dirty and therefore fail the new
ceremony repository gate by design. Their listed SHAs are branch bases, not
release approvals or ceremony inputs.

- API base `d5d3459c713a1bac602d46e455c9ddbc4eaf3587`: 529 tests pass;
  namespace and whitespace gates pass.
- Protocol base `8d8c2ce508777317ccb27a5a62732ec6ade3f091`: 742 tests pass,
  including deterministic eight-surface ceremony, Pool V3, signed artifact,
  2-of-3 bridge, and split preflight regressions.
- EVM base `1f330831271948875ea4b7c5671709d05be465d6`: 17 tests, compile,
  provider-secret scan, namespace gate, and whitespace gate pass.
- Customer web base `320d8677b883c0e23a02237324553520790bd6d8`: 220 tests,
  staging build, source namespace scan, compiled bundle scan, public-secret
  scan, and whitespace gate pass.
- Admin portal base `15cd90be8c22cf35deb6f4629d8769a0ac3d529a`: 778 tests,
  staging build, source namespace scan, compiled bundle scan, and whitespace
  gate pass.
- Legacy Beta backend base `aa1f4f63be4e49836aafd9f019980f02d47d1590`:
  11 focused protocol-intent tests plus compile, namespace, and whitespace
  gates pass. It remains outside the five-source ceremony artifact.

Cross-repository V2 schema contracts pass across protocol, API, EVM, customer
web, and admin portal. The emitter accepts enrollment binding data, derives
proof fields from the verifier adapter, and computes credential commitments
internally. Active announcement readers and builders use prefix `0x53`.

No ceremony may begin until these changes are reviewed, committed, rebuilt
from clean checkouts, and recorded as five new full source SHAs.

## Finding Ledger

| Finding | State | Evidence or remaining gate |
| --- | --- | --- |
| C-1 provider credential in EVM history | History fixed, provider revocation open | Both public EVM branches use scrubbed ancestry, current config is environment-only, CI rejects provider credentials, and the canonical local object database no longer contains the retired blob. A private mode-0400 pre-scrub bundle preserves evidence. The provider account owner must still revoke the credential. |
| C-2 portal runtime coordinates | Contained | Public runtime files no longer contain active admin or ceremony coordinates. Fresh V2 coordinates may be published only through the signed ceremony artifact. |
| C-3 retired API on public port `5001` | Contained live | The PM2 process is removed and saved, direct port `5001` refuses connections, port `8790` is externally unreachable, and no retired database or state was deleted. |
| C-4 credentialed localhost CORS | Contained live | Staging rejects localhost and attacker-origin preflights without allow-origin or allow-credentials. Pro mutation routes are retired at `410` and return no CORS grant. |
| C-5 challenge throttling | Code fixed, live write test pending | SQLite-WAL quotas persist across restarts, count valid and invalid requests before body validation, and use the proxy-normalized peer IP. A concurrent regression admits only the configured quota. Writes are locked, so the public 429 saturation smoke is deferred until the controlled prelaunch window. |
| C-6 cross-tenant default vhost | Contained live | The staging VPS loads a first/default deny vhost. Unknown Solslot Host/SNI values return `403`; intended named vhosts remain available. |
| C-7 protocol and retired API co-served on pro | Contained live | Pro serves only a static mainnet-disabled page; retired protocol routes return `410`; the separate Solomon health route remains available. |
| C-8 chain authority not enforced | Contained, not completed | Authority reports `not-deployed`, all writes and ceremony operations are locked, and non-ceremony write mode now requires complete chain-bound authority coordinates. Closure requires the fresh V2 genesis. |
| C-9 threshold-one validator | Code completed, provisioning and audit open | Public validator metadata and generic signing routes return `404`; the coordinator stores no private key; the bridge and coordinator require two signatures from exactly three distinct planned keys. Closure requires three separately controlled signer hosts, private transport, live failover evidence, and independent review. |
| H-1 raw protocol manifest disclosure | Fixed live | `/protocol` returns typed public coordinates only; faucet fields and the raw manifest are null. |
| H-2 authority commitment disclosure | Risk removed from current staging | Authority is disabled and all fields are null. Future launcher and commitment hashes are public on-chain verification data, never an authorization source. Admin records and Merkle paths remain private. |
| H-3 public database listener | Fixed live | Port 3306 is not reachable publicly; the database listener is loopback-only. |
| H-4 permissive CORS | Fixed live | Staging accepts exact HTTPS origins only, rejects wildcard headers, and normalizes forwarding headers at the proxy. |
| H-5 legacy SSH ciphers | Not reproduced | Effective host configurations expose only ChaCha20, AES-CTR, and AES-GCM cipher suites. CBC and 3DES are not enabled. |
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

Alpha remains blocked on the following external and release-control work:

1. Revoke the exposed provider credential and rotate every staging, ceremony,
   signer, relayer, deployer, SSH, CI, JWT, admin, faucet, and database secret.
2. Review and commit all five dirty candidate worktrees, reproduce every gate
   from clean checkouts, and freeze five new full source SHAs.
3. Obtain independent protocol, EVM, credential-bridge, and ceremony approval
   against those exact commits. No unresolved security finding is accepted.
4. Provision three separately controlled validator hosts and prove true 2-of-3
   behavior over private authenticated transport.
5. Deploy fresh reviewed Sepolia contracts, wait 12 confirmations, fund nine
   fresh Chia inputs, enroll three administrators, and pass both live and
   offline pre-broadcast gates.
6. Broadcast one deterministic ceremony, obtain three Chia confirmations,
   collect two artifact signatures, write the lock last, deploy pinned
   consumers, and pass the offline post-genesis gate.
7. Complete fresh EVM and BLS zkPassport-to-Chia stamps, validator failover,
   replay rejection, and storage-free recovery before offers can be enabled.
8. Complete the Academy custom-domain activation and public certificate check.

No current browser result is accepted as full-cycle credential success. That
gate requires a fresh V2 EVM vault and a fresh V2 BLS vault to reach
`chia_confirmed`, recover from Chia plus the API with browser storage cleared,
and remain bound to the current singleton coin and reconstructed puzzle hash.
