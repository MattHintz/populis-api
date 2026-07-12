# Solslot V2 Admin Desk Design

The Admin Desk coordinates public proposal metadata with chain-authorized
actions. It never replaces Chia governance or consensus checks.

## Actors

- **Bootstrap operator:** runs the one-time ceremony before the lock exists.
- **Administrator:** authenticates through a current admin-authority member.
- **Committee member:** signs proposal votes through the committee authority.
- **Auditor:** reads public proposals, authority snapshots, and artifact hashes.

## Authentication

Administrator login is EIP-712 `SolslotAdminLogin`, domain
`Solslot Protocol`, version `2`. A short-lived challenge binds owner, nonce,
issue time, auth type, and scope. The server recovers the signer and checks a
hash-verified V2 records file. JWT membership is rechecked on every request.

Bootstrap cookies, ceremony bearer tokens, browser state, and unverified
environment lists cannot authorize the desk.

## Mint Proposal Lifecycle

```text
draft -> published -> voting -> approved -> executed
   \-> cancelled       \-> rejected / expired
```

1. An administrator drafts canonical property, collection, share, valuation,
   and document commitments.
2. Publish creates the on-chain proposal state and records its launcher.
3. Committee votes are verified against the current committee authority.
4. Execution requires the approved on-chain state, current V2 protocol
   coordinates, enabled mint gate, and property-registry uniqueness proof.
5. Only an executed real testnet mint can enter Alpha inventory.

The API database is an index and workflow cache. It cannot manufacture an
approved proposal, bypass committee signatures, or substitute coordinates.

## Data Rules

- Store canonical IDs, hashes, public URLs, status, and transaction references.
- Never store seeds, wallet private keys, raw identity files, or passport data.
- Commit mutable document sets through a canonical metadata hash before
  publication.
- Treat duplicate property IDs and mismatched collection/share commitments as
  hard conflicts.

## Route Families

- `/admin/auth/*`: challenge, login, refresh, and public authority snapshot.
- `/admin/mint/*`: chain-admin-authenticated proposal lifecycle.
- `/admin/committee/*`: committee reads and signed votes.
- `/admin/bootstrap/*`: run-once ceremony session and lock.
- `/admin/zkpassport/bridge-pool/top-up`: chain-admin-authenticated bridge
  replenishment.

## UI Requirements

The desk must display current network, protocol version, source artifact hash,
authority launcher, admin subject, and write-gate state before any mutation.
Buttons stay disabled when coordinates are missing, the ceremony is unlocked,
the API release differs from the signed bundle, or minting is off.

Every transaction preview identifies what will be signed, which chain receives
it, and the resulting launcher or coin. Success appears only after the
authoritative chain confirms the expected state.
