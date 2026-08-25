# RC2 Credential Carryover Record - 2026-07-14

> **Historical record — not a current ceremony checklist.** Preserve the dated
> body below as July 2026 provenance, but do not complete its pending table or
> use it to authorize RC27.36. The official Testnet11 release requires
> a new private credential-carryover record bound to
> `solslot-v2-alpha-rc27.36-20260824`, current host fingerprints, two current
> operators, and proof that the exposed provider credential was revoked and
> replaced. A July one-time `SOLSLOT_ADMIN_TOKEN` must never be reused.

This record defines which credentials carry into the Solslot V2 Alpha release.
It contains identifiers and public fingerprints only. Secret values, seed
material, bearer tokens, recovery phrases, and private keys must never be
added to this file or any release artifact.

## Policy

Secure reusable credentials are retained. Rotation is not a release ritual;
it is required only when a credential was exposed, cannot satisfy the V2
topology, is deliberately one-time, or is invalidated by its provider.

The confirmed public RPC provider credential is the only existing reusable
credential that must be replaced. Removing it from active source does not
revoke copies from public history. Revoke it in the provider console, create a
replacement with the minimum required Sepolia scope and budget, and install it
only in protected runtime configuration on the coordinator and three signer
hosts. Each signer must query Sepolia independently; the replacement value is
never copied into source, release archives, workflow output, or ceremony
evidence.

No further shared-history rewrite is required. The active source and release
archive scanners still reject provider credentials.

## Retained Credentials

The following credential classes carry over unless a separate incident record
shows actual exposure:

| Credential class | Carryover rule | Evidence recorded before ceremony |
| --- | --- | --- |
| SSH host and operator keys | Retain | Host key and operator public-key fingerprints |
| GitHub and CI identities | Retain | Repository/environment identifiers and workflow actor |
| AWS and Cloudflare credentials | Retain | Account identifiers and least-privilege role names |
| Database credentials | Retain | Database role and host binding, never password |
| Stripe and mail credentials | Retain | Provider account and restricted-key identifiers |
| Chia faucet key | Retain | Public puzzle hash and funding policy |
| EVM deployer and relayer wallets | Retain | Chain ID and public addresses |
| JWT, challenge, session, and artifact-token secrets | Retain | Configuration fingerprint and creation record |
| Genesis administrator wallets | Retain wallet ownership | Public addresses; each ceremony still uses fresh invitations and signatures |
| Validator signer 0 seed | Retain on Vaults EC2 | Signer index and derived BLS public key |

This table authorizes reuse only. It does not authorize printing, copying, or
moving private material into source control, workflows, deployment archives,
or ceremony evidence.

## Replaced Or Newly Generated Material

| Material | Action | Lifetime and storage |
| --- | --- | --- |
| Publicly exposed RPC provider credential | Revoke and replace | Protected coordinator runtime environment |
| Validator signer 1 seed | Generate | Root-readable file on signer 1 only |
| Validator signer 2 seed | Generate | Root-readable file on signer 2 only |
| WireGuard key pairs | Generate for all four peers | Root-readable peer files; public keys in topology record |
| Private mTLS CA and certificates | Generate | Offline CA; coordinator client and signer server credentials on their hosts |
| `SOLSLOT_ADMIN_TOKEN` | Generate once | Ceremony window only; remove after finalization |
| Genesis invitation fragments | Generate per slot | 30 minutes, single use, URL fragment delivered to the intended administrator |

Signer 0 keeps its existing seed in place. The generation tooling reads it
only to derive and verify roster position zero; it does not copy or rewrite
the seed. The coordinator stores no validator seed.

The current design does not require a separate bridge-batch private key.
Bridge allocations remain bound to the signed artifact, chain administrator
authorization, validator lineage checks, replay ledgers, and budget controls.
If a later reviewed design introduces such a key, it is new material and must
be recorded here before use.

## Public Fingerprint Record

Complete this table in private ceremony evidence before enabling ceremony
mode. Public values may also appear in the signed artifact where required.

| Item | Identifier or public fingerprint | Verified by | Date |
| --- | --- | --- | --- |
| Replacement RPC credential | Provider-side key identifier only | pending | pending |
| Signer 0 BLS public key | pending | pending | pending |
| Signer 1 BLS public key | pending | pending | pending |
| Signer 2 BLS public key | pending | pending | pending |
| WireGuard coordinator public key | pending | pending | pending |
| WireGuard signer public keys | pending | pending | pending |
| mTLS CA SHA256 fingerprint | pending | pending | pending |
| Coordinator client certificate fingerprint | pending | pending | pending |
| Signer certificate fingerprints | pending | pending | pending |
| EVM deployer address | pending | pending | pending |
| EVM relayer address | pending | pending | pending |
| Chia faucet puzzle hash | pending | pending | pending |

## Ceremony Session Expiry

Before ceremony mode starts:

1. Keep `SOLSLOT_ALPHA_WRITES_ENABLED=false`,
   `SOLSLOT_CEREMONY_MODE_ENABLED=false`, and
   `SOLSLOT_MINTING_ENABLED=false` continuously for at least 15 minutes.
2. Restart the coordinator from the frozen RC2 release while all three flags
   remain false.
3. Clear bootstrap cookies in the coordinator's trusted administrative
   browsers and confirm an old bootstrap session cannot mutate state.
4. Create and install the one-time `SOLSLOT_ADMIN_TOKEN` only for the ceremony
   window.
5. Remove that token and restart the coordinator immediately after the
   bootstrap lock is written.

This expires reusable bootstrap and administrator sessions without replacing
unexposed signing secrets.

## Required Approval

The ceremony credential checkpoint passes only when:

- the exposed RPC provider credential is revoked and its replacement works;
- retained credentials have identifiers or public fingerprints recorded;
- signer 1 and signer 2 derive the expected roster public keys;
- private-network certificates and peer keys match the live hosts;
- no validator seed exists on the coordinator;
- release and ceremony archives pass the credential scanner; and
- two operators sign the private carryover record.

An empty or pending row is a ceremony blocker, not permission to substitute a
new credential silently.
