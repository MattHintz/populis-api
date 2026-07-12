# zkPassport to Chia Vault Credential

The Alpha credential is an anonymous, vault-bound 18+ proof. Solslot stores no
passport image or identity file. Verification is complete only when the
current Chia vault singleton coin commits to the credential root.

## State Machine

```text
reserved -> evm_confirmed -> stamp_pending -> chia_confirmed
                                      \-> receipt_syncing
```

- `reserved`: an authenticated vault owner has reserved one confirmed,
  unspent bridge-policy coin.
- `evm_confirmed`: the API verified one canonical emitter event and persisted
  its proof commitments.
- `stamp_pending`: the owner-authorized Chia spend was submitted and its exact
  successor coin is known.
- `chia_confirmed`: Coinset reports that successor as the current unspent
  vault coin and its puzzle hash reconstructs from the receipt root.
- `receipt_syncing`: Chia state is visible but the public receipt index still
  needs reconciliation. Offers remain blocked.

## Owner Authentication

Every mutation uses a fresh owner challenge bound to:

- vault launcher;
- network and policy version;
- action name and canonical request payload;
- nonce and expiry.

EVM owners sign `SolslotVaultCredentialAction` under `Solslot Protocol`,
version `2`. BLS owners sign the equivalent CHIP-0002/WalletConnect message.
Challenges are one-time and persistently consumed.

## Proof and EVM Event

The phone produces the proof through the configured zkPassport project. The
fresh verifier adapter extracts authoritative public inputs. The emitter, not
the caller, derives the attestation leaf and emits exactly one event containing
the vault, scoped nullifier, scope commitments, proof time, policy, bridge
coin, bridge message, and root.

The API accepts the event only when:

- transaction status and minimum confirmations are valid;
- emitter address and event signature match the signed V2 bundle;
- exactly one event targets the requested vault;
- event sender matches the registered vault owner where required;
- nullifier, scope, subscope, proof timestamp, leaf, root, policy, bridge
  policy, bridge coin ID, and bridge message recompute exactly;
- the bridge coin exists on Chia, is unspent, and is reserved to this
  enrollment.

Validator signing is an internal state transition after those checks. There is
no public signing endpoint.

## Chia Stamp

The API builds `SPEND_UPDATE_IDENTITY` against the current unstamped vault
coin and combines it atomically with the bridge coin spend.

- EVM vaults sign `SolslotVaultSpend` as EIP-712 and the API verifies the
  recovered key reconstructs the current vault puzzle.
- BLS vaults receive the exact vault coin spend through the Chia wallet path,
  sign its AGG_SIG_ME message, and return only the signature.
- The validator signature is aggregated only after owner verification.
- Coinset submission failure leaves the enrollment unverified.

The receipt is authoritative for UI recovery only after the API recomputes the
stamped full puzzle hash and matches the current unspent one-mojo successor.

## Public Receipt

`VaultCredentialReceipt` exposes only public commitments and chain references:

```text
vaultLauncherId, network, policyVersion, identityAttestRoot,
attestationLeafHash, attestationProof, scopedNullifier, serviceScopeHash,
serviceSubscopeHash, proofTimestamp, bridgePolicyHash, bridgeParentId,
bridgeAmount, bridgeCoinId, bridgeMessage, evmTxHash, chiaVaultCoinId,
confirmedBlockIndex, chiaSpendBundleId, enrolledAt
```

The root cannot be used across vaults because the proof subscope binds
`vault:<launcher>`. Browser storage may display pending progress but cannot
set verified state, enable checkout, or create an offer.

## Replay and Budget Controls

The SQLite-WAL credential ledger uniquely consumes vault enrollment, bridge
coin, EVM transaction, scoped nullifier, relay request digest, and forwarder
nonce. Relay budgets are keyed by IP, owner, vault, nullifier, and bridge coin,
with a global budget and circuit breaker. Replays fail after restart and across
multiple API workers.

## Required Routes

- `POST /zkpassport/enrollments/{vault}/owner-challenge`
- `POST /zkpassport/enrollments`
- `GET /zkpassport/enrollments/{vault}`
- `POST /zkpassport/enrollments/{vault}/proof`
- `POST /zkpassport/enrollments/{vault}/stamp/prepare`
- `POST /zkpassport/enrollments/{vault}/stamp/submit`
- `POST /zkpassport/enrollments/{vault}/stamp/sync`
- `POST /zkpassport/relay`

A 404 receipt, unavailable API, missing root, mismatched coin, or incomplete
state must render as unverified and block all protocol offers.
