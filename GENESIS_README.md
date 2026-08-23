# Solslot V2 Clean Genesis Ceremony

This is a one-way launch. Existing testnet vaults, proofs, tokens, bridge
coins, contracts, state databases, and singleton coordinates are abandoned.
No artifact from a retired deployment may be copied into the V2 state tree.

## Current Official Testnet11 Policy

The current guided release target is
`solslot-v2-alpha-rc27.33-20260823` on
`release/testnet-alpha-rc27.33-20260823`. The browser cannot choose its review
class. The protected server setting
`SOLSLOT_LAUNCH_GENESIS_REVIEW_CLASS=independent-release-review` is mandatory
for the official Testnet11 genesis. An operator may explicitly configure
`internal-engineering-testnet` only for a disposable engineering run, which
must never be represented as the official independently reviewed genesis.

The official flow uses the guided owner claim. The protected direct
`POST /admin/genesis/drafts` operator endpoint remains available for an
explicitly authorized compatibility workflow; it is not a bypass when the
guided readiness gate is incomplete. Retired bootstrap routes are not mounted.
Keep the one-time owner claim, launch session secret, and ceremony operator
token separate and server-generated. Deliver only the single-use owner claim
to a trusted browser through the URL fragment; launch-session and ceremony
operator secrets stay out of browser-readable storage. None of them belongs
in logs, evidence, or source control.

Fresh Sepolia identity-contract deployment evidence remains a pre-plan
readiness requirement. The plan-bound independent audit approval is required
after plan approval and again by strict preflight; do not create a placeholder
approval before a plan exists. Base Sepolia payment-rail ownership does not
block the ceremony. It remains mandatory for the separate, post-genesis
payment-activation gate, and all payment workers stay disabled through
genesis.

The `V2`, `V3`, and `RC23` strings in artifact, puzzle, and on-chain schema
names below are compatibility identifiers, not permission to use an older
release or state tree.

## Hard Gate

Do not begin until:

- protocol, EVM, Omnichain, API, legacy backend, Key of Solomon, Samuel,
  customer web, and admin portal commits are frozen, clean, and bound to the
  coordinated release manifest;
- full suites and exploit regressions pass from those exact commits;
- release archives and compiled assets pass the namespace scanner;
- for the official release, a reviewer outside the implementation team has
  completed the pre-deployment source-scope review and recorded all findings;
  the plan-bound approval and post-deployment addenda remain later strict
  gates. Alternatively, this is an explicitly configured
  `internal-engineering-testnet` disposable run with three distinct enrolled
  administrators and normal 2-of-3 plan/artifact signatures;
- guided launch configuration names the exact RC27.33 tag, source-evidence
  path and SHA-256, plan-template path, and protected review class;
- the credential carryover record is complete, the provider credential found
  in public history is revoked and replaced, signer 1/2 and private-network
  material are generated, and the one-time ceremony token is ready;
- `SOLSLOT_MINTING_ENABLED=false` is confirmed publicly. Keep ordinary Alpha
  customer writes disabled before the ceremony. The isolated ceremony process
  must then start with `SOLSLOT_CEREMONY_MODE_ENABLED=true` and
  `SOLSLOT_ALPHA_WRITES_ENABLED=true`; startup rejects any other combination.
  This temporary server ceiling does not authorize a push: the fresh signed
  `ceremonyBroadcast` gate and exclusive genesis faucet purpose remain
  mandatory. Stop the ceremony process after finalization before changing the
  normal customer-write posture.

## Fresh State

Create a new private ceremony directory with mode `0700` and a new shared
runtime state directory. The following files must not exist before the run:

- `deployment_manifest_v2.json`
- `public_artifact_v4.json`
- `bootstrap_manifest_v2.json`
- `bootstrap_recovery_anchor_v2.json`
- `portal_runtime_config_v2.json`
- `admin_records_v2.json`
- `vault_registry_v2.db`
- `admin_desk_v2.db`
- `zkpassport_v2.db`

Never rename an older file into one of these paths.

## Sequence

1. Record exact source commits and reproducible protocol package hash.
2. Deploy fresh Sepolia `SolslotForwarder`, verifier adapter, and attestation
   emitter identity contracts. Record chain ID, addresses, bytecode hashes,
   transactions, exact source SHAs, and at least 12 confirmations.
3. Derive the V2 bridge policy from the new validator set and emitter.
4. Run the Chia deployment dry-run using newly funded ceremony coins.
5. Review every derived SGT, pool V3, DID, governance, protocol Statutes,
   protocol config, admin authority, and vault-version-registry coordinate.
6. Verify pool V3 commits the governance singleton struct, Statutes-bound NAV
   parameters, treasury destinations, and deed commitment parameters.
7. Persist the exact fee-funded Chia spend bundle before pushing it. A partial
   or ambiguous push preserves that durable bundle and its reserved fee coin
   for reconciliation. After a fresh owner-plus-one signed
   `ceremonyBroadcast` gate opens, only that exact preserved bundle may be
   replayed; never build or submit a replacement bundle.
8. Confirm every exact reserved input spend, singleton, and generated
   bridge-pool coin through the synced local primary Chia node. Coinset is not
   accepted as genesis confirmation authority.
9. Bind the first administrator through the admin-authority flow and generate
   `admin_records_v2.json` from the confirmed state.
10. Finalize public artifacts. Write `bootstrap_manifest_v2.json` last so its
    presence permanently locks the bootstrapper.
11. Canonicalize JSON, compute SHA256 for every public and private artifact,
    sign the public bundle, and store immutable copies in the audit packet.
12. Deploy API and both portals atomically, pinned only to the signed bundle.
13. Keep minting disabled while completing the live smoke gate.

## Artifact Contract

The signed public bundle must include:

- `schemaVersion: 4`
- `sourceManifestVersion: 4`
- `protocolVersion: "solslot-v2-rc23"`
- exact protocol, EVM, Omnichain, API, legacy Stripe adapter, Key of Solomon,
  Samuel, customer-web, and admin-portal commit SHAs
- build timestamp and artifact hash
- explicit `reviewClass`, `testOnly`, and `auditStatus` markers
- all puzzle module hashes and singleton launcher IDs
- `sgtGenesisCoinId` and `sgtTailHash`
- pool V3 and SmartDeed V2 versions
- governance singleton struct
- immutable MINT-only KoS co-signer public key (never its private key)
- protocol DID singleton material and the empty property-registry authority
- bridge policy and fresh EVM contract addresses
- admin authority and vault-version-registry state
- a complete retired-coordinate denylist
- signatures and checksum manifest

No seed, mnemonic, private key, bearer token, JWT secret, SSH credential,
unsigned spend bundle, or private recovery material may enter a public
artifact.

## Live Smoke Gate

Before enabling minting:

1. Confirm OpenAPI says `Solslot API` and exposes no public validator signer.
2. Create a fresh EVM vault and a fresh BLS vault.
3. Complete zkPassport proof, canonical EVM event, internal validator step,
   owner-authorized Chia stamp, and Coinset confirmation for both vaults.
4. Clear browser state and reconnect; both vaults must recover from Chia and
   the API receipt index.
5. Attempt replay of owner challenge, relay request, event, nullifier, and
   bridge coin; every replay must fail.
6. Confirm Beta ignores Alpha vaults and credentials.
7. For an internal disposable run, mint one synthetic SmartDeed through the
   complete admin proposal, SGT vote, and five-spend committee execution path;
   then exercise one offer, pool/deposit, and redemption path.
8. Run ceremony preflight without report-only mode and archive its clean exit.

Payment-rail ownership, Stripe rehearsal, and settlement activation are not
part of this smoke gate. They remain closed until their separately approved
post-genesis activation evidence is complete.

Only then may an authorized operator exit ceremony mode, apply the separately
approved customer-write and minting release gates, and mint the first real
testnet SmartDeed through the complete admin and committee path.
