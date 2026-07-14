# Alpha Security Containment - 2026-07-14

This record consolidates the aggressive server-audit thread and the Alpha V2
remediation thread. It describes containment, not launch approval. Protocol
writes, credential enrollment, offers, minting, and ceremony operations remain
locked.

## Active Locked Release

- API commit: `8e2d697fc2164780d4f817ac7d913472c1f631e0`
- Protocol commit: `8d8c2ce508777317ccb27a5a62732ec6ade3f091`
- Network: `testnet11`
- Runtime: `solslot_api.app:app` on `127.0.0.1:8790`
- Public API base: `https://staging.solslot.com/protocol-api`
- Release directory:
  `/opt/solslot/api-staging/releases/8e2d697fc2164780d4f817ac7d913472c1f631e0-8d8c2ce50877`
- Release state: immutable `.release-ready` marker present; `release.json`
  matches both full source commits.

## Live Containment

| Finding | State | Evidence |
| --- | --- | --- |
| Retired vault API exposed on `98.80.97.197:5001` | Contained | PM2 process removed and saved; no listener remains; direct TCP connection is refused. |
| Credentialed localhost CORS | Contained | Staging rejects localhost preflight with `400`; pro protocol routes are retired; neither response includes allow-origin or allow-credentials. |
| Challenge drain | Contained | All Alpha writes return `503`; deployed code also counts valid and invalid challenge attempts before body validation in persistent SQLite-WAL state. |
| Cross-tenant default vhost | Contained | The staging VPS loads a first/default deny vhost. Unknown Solslot Host/SNI values return `403`; intended named vhosts remain available. |
| Two APIs on the pro origin | Contained | Pro now serves a static mainnet-disabled page; retired API paths return `410`; listeners `5001` and `8790` are stopped. |
| Missing chain authority | Contained, not completed | Authority reports `not-deployed`; startup and middleware prohibit writes. Non-ceremony writes require complete chain-bound authority coordinates. |
| One validator and public validator metadata | Contained, not completed | Public validator metadata and generic signing routes return `404`; staging/production refuses write mode below threshold two. A real multi-validator implementation is still required. |
| Weak SSH cipher report | Not reproduced | Effective SSH configurations expose only modern ChaCha20, AES-CTR, and AES-GCM cipher suites. |
| Public RPC credential in source history | Source contained, provider action pending | The active EVM tree contains no Alchemy endpoint and its current refs were searched. Source removal cannot revoke a credential already copied from public history. |
| Admin and ceremony coordinates in portal source | Active source cleared | Ceremony-sensitive portal fields are empty, the emitter start block is zero, and the release remains unable to derive operational coordinates without a signed V2 artifact. |
| Academy Help Center unavailable | DNS repaired, Intercom activation pending | `academy.solslot.com` is a DNS-only CNAME to `us.intercomhelpcenter.com`; the former `1014` is gone. HTTPS currently returns `403` until the domain is saved and set live in the Intercom Help Center. |

Backups were created before each host change. No retired API database,
manifest, enrollment ledger, or Chia state directory was deleted.

## Verification

- API suite: `510 passed`.
- Customer staging bundle: build passed; generated namespace gate passed for
  510 files.
- API source namespace gate: passed.
- API credential scan: passed.
- Public health reports the active API and protocol commits above.
- Public OpenAPI and validator metadata routes return `404`.
- A valid public challenge request returns the Alpha security lock (`503`).
- Pro `/protocol-api/health` returns `410` and the Solomon health route remains
  `200`.
- GitHub Actions run `29345249750` passed build, full tests, namespace and
  credential scans, atomic activation, and local/public post-deploy checks.
- The host `current` symlink resolves to the compound API/protocol release;
  its `.release-ready` marker is present and only `127.0.0.1:8790` listens.

## Still Blocking Alpha

1. Revoke the exposed third-party RPC credential at the provider. Source
   removal and scans do not invalidate a copied credential.
2. Complete the independent protocol and EVM review, including the pool V3
   and credential bridge changes.
3. Implement and audit threshold validator signing; a configured number alone
   is not sufficient.
4. Deploy a fresh chain-bound admin authority and rotate all ceremony secrets.
5. Run a clean V2 genesis from frozen, clean commits and publish signed,
   checksummed artifacts.
6. Complete a new zkPassport-to-EVM-to-Chia vault stamp and prove recovery
   with browser state cleared before enabling offers or minting.
7. Save and set `academy.solslot.com` live in Intercom, then require a public
   `200` response before marking the Help Center operational.

No item in this document authorizes restoring a retired process or enabling
`SOLSLOT_ALPHA_WRITES_ENABLED`, `SOLSLOT_MINTING_ENABLED`, or
`SOLSLOT_CEREMONY_MODE_ENABLED`.
