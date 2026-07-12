# Solslot V2 Clean Genesis Ceremony

This is a one-way launch. Existing testnet vaults, proofs, tokens, bridge
coins, contracts, state databases, and singleton coordinates are abandoned.
No artifact from a retired deployment may be copied into the V2 state tree.

## Hard Gate

Do not begin until:

- protocol, EVM, API, customer web, and admin portal commits are frozen and
  clean;
- full suites and exploit regressions pass from those exact commits;
- release archives and compiled assets pass the namespace scanner;
- the independent pool and credential-path reviews are signed off;
- all staging deployer, faucet, validator, relayer, bootstrap, admin, JWT,
  SSH, and CI credentials have been rotated;
- `SOLSLOT_ALPHA_WRITES_ENABLED=false` and
  `SOLSLOT_MINTING_ENABLED=false` are confirmed publicly.

## Fresh State

Create a new private ceremony directory with mode `0700` and a new shared
runtime state directory. The following files must not exist before the run:

- `deployment_manifest_v2.json`
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
2. Deploy fresh `SolslotForwarder`, verifier adapter, and attestation emitter
   contracts. Record chain ID, addresses, bytecode hashes, and transactions.
3. Derive the V2 bridge policy from the new validator set and emitter.
4. Run the Chia deployment dry-run using newly funded ceremony coins.
5. Review every derived SGT, pool V3, DID, governance, NAV registry, protocol
   config, admin authority, and vault-version-registry coordinate.
6. Verify pool V3 commits the governance singleton struct, NAV trust roots,
   treasury destinations, and deed commitment parameters.
7. Push the Chia ceremony once. A partial or ambiguous push ends the ceremony;
   do not reuse its coins or coordinates.
8. Confirm every singleton and generated bridge-pool coin on Coinset.
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

- `schemaVersion: 2`
- `protocolVersion: "solslot-v2"`
- protocol, API, EVM, customer-web, and admin-portal commit SHAs
- build timestamp and artifact hash
- all puzzle module hashes and singleton launcher IDs
- `sgtGenesisCoinId` and `sgtTailHash`
- pool V3 and SmartDeed V2 versions
- governance singleton struct
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
7. Confirm Alpha contains no listing before the admin and committee mint flow.
8. Run ceremony preflight without report-only mode and archive its clean exit.

Only then may an authorized operator set both write gates true and mint the
first real testnet SmartDeed through the complete admin and committee path.
