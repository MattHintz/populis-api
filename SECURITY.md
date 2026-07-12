# Solslot V2 Security Gate

## Launch State

Alpha is locked while the clean V2 ceremony is prepared. Mainnet protocol
functionality is disabled. No SmartDeed may be minted and no offer may be
created until every gate in this document is green.

## Required Invariants

### Namespace and release identity

- Release sources, paths, archives, OpenAPI output, process commands, and
  compiled assets pass `scripts/check_namespace.py`.
- Every API release records exact API and protocol commits in `release.json`.
- The protocol dependency is an exact 40-character commit, never a branch.
- A deployment accepts only `schemaVersion: 2` and
  `protocolVersion: "solslot-v2"` artifacts.

### Protocol coordinates

- Trust-critical writes load a structurally valid V2 deployment manifest.
- Zero, missing, malformed, or retired coordinates fail closed.
- Pool V3, SmartDeed V2, SGT, governance, bridge policy, and vault registry
  coordinates must all come from the signed ceremony bundle.
- Request parameters cannot replace canonical pool, governance, treasury,
  registry, or bridge coordinates.

### Administrator authority

- Interactive admin authority comes only from `SOLSLOT_ADMIN_RECORDS_PATH`.
- The records launcher and computed `admins_hash` must match the current
  admin-authority singleton or startup fails.
- A removed member loses access on the next request even if its JWT has not
  expired.
- Ceremony bearer credentials cannot authorize post-genesis mutations.
- The bootstrap lock manifest is written last and cannot be reopened.

### zkPassport and vault credentials

- Every enrollment mutation requires a fresh EVM or BLS vault-owner challenge.
- The EVM event must come from the pinned emitter and must match the reserved
  Chia bridge coin, vault launcher, policy, scope, nullifier, and proof time.
- Validator signatures are produced only inside the verified enrollment state
  machine; there is no public signer endpoint.
- Nullifiers, bridge coins, EVM events, relay nonces, and enrollment actions are
  single-use in a persistent SQLite-WAL ledger.
- The UI may report verified only when Coinset confirms the current unspent
  vault successor whose puzzle hash contains the receipt's identity root.
- Browser storage is never an authorization source.

### Relay and faucet economics

- Relay limits persist across processes and restarts and are keyed by source
  IP, owner, vault, nullifier, and bridge coin.
- One relay is allowed per enrollment; request digests and forwarder nonces are
  locked before submission.
- Global gas budgets and the relay circuit breaker fail closed.
- Public enrollment requests cannot spend the faucet or create bridge coins.
- Bridge-pool replenishment requires current chain-bound admin authority.

### Offers and minting

- Mint writes require both `SOLSLOT_ALPHA_WRITES_ENABLED=true` and
  `SOLSLOT_MINTING_ENABLED=true` plus the signed V2 ceremony coordinates.
- Offer files are Solslot V2, bind canonical coordinates, and include a current
  server-confirmed Chia credential receipt.
- Empty, stale, mismatched, or unconfirmed identity roots are rejected by the
  API, portal builder, and protocol spend.
- Alpha inventory contains only canonical testnet SmartDeeds created by the
  complete admin and committee flow.

## Acceptance Evidence

The launch packet must contain clean protocol, EVM, API, customer-web, and
admin-portal test reports; namespace scans of release archives; exploit
regressions; reproducible puzzle and contract hashes; secret-rotation evidence;
the signed ceremony bundle; and EVM plus BLS zkPassport-to-Chia smoke receipts.

No Critical, High, Medium, or Low security finding is accepted for Alpha. A
failed ceremony is abandoned with all coordinates and secrets rotated before a
new attempt.
