# zkPassport Chia Vault Attestation Runbook

This document defines the Testnet Alpha credential lifecycle. A phone proof or
an EVM event alone is not verification. The credential is usable only after a
new current Chia vault singleton coin confirms with the non-empty identity root
curried into its puzzle.

## Release Gate

The full cycle is:

1. The API reserves a unique, unspent one-mojo bridge coin for one vault.
2. zkPassport proves the Alpha 18+ policy on the user's phone.
3. The canonical Sepolia emitter records a vault-bound attestation event.
4. The API re-reads that event and rejects any browser field that differs.
5. The vault owner authorizes `SPEND_UPDATE_IDENTITY`:
   - EVM vault: EIP-712 signature by the event sender and vault owner.
   - Chia vault: CHIP-0002 coin-spend signature by the registered BLS key.
6. The API builds one atomic Chia bundle containing the bridge spend and vault
   singleton spend, then aggregates the owner and validator signatures.
7. Coinset confirms the expected stamped successor coin on testnet11.
8. The API recomputes the stamped full puzzle hash, matches the unspent current
   coin, persists the receipt, and returns `chia_confirmed`.
9. The portal performs a fresh API read and confirms that the receipt coin id
   equals its independently discovered current vault coin id.

Only step 9 may display `ID verified`, unlock checkout, or populate an offer
credential receipt.

## Enrollment States

| State | Meaning | May unlock protocol actions |
| --- | --- | --- |
| `reserved` | A bridge coin is reserved; no accepted proof exists. | No |
| `evm_confirmed` | The canonical Sepolia event is indexed. The Chia vault is unchanged. | No |
| `stamp_pending` | Coinset accepted the atomic Chia bundle. Confirmation is pending. | No |
| `receipt_syncing` | A previously confirmed receipt cannot currently be matched to the current unspent coin. | No |
| `chia_confirmed` | The current unspent vault coin matches the root and receipt recomputed by the API. | Yes, after a fresh portal read |

Browser storage is never an authority for these states.

## Public Endpoints

```text
POST /zkpassport/enrollments
GET  /zkpassport/enrollments/{vaultLauncherId}
POST /zkpassport/enrollments/{vaultLauncherId}/proof
POST /zkpassport/enrollments/{vaultLauncherId}/stamp/prepare
POST /zkpassport/enrollments/{vaultLauncherId}/stamp/submit
POST /zkpassport/enrollments/{vaultLauncherId}/stamp/sync
```

`stamp/prepare` returns either EIP-712 typed data for an EVM vault or the exact
vault coin spend and timestamp for a Chia BLS vault. `stamp/submit` rebuilds the
authorization from canonical server state. It does not trust a client-provided
coin spend, root, expected successor, or block height.

## Live Verification

Set the launcher under test without placing wallet secrets in shell history:

```bash
export VAULT_LAUNCHER_ID=0x...
```

Confirm route deployment and read the authoritative state:

```bash
curl -fsS https://staging.solslot.com/protocol-api/openapi.json \
  | python3 -c 'import json,sys; p=json.load(sys.stdin)["paths"]; print([x for x in p if "/zkpassport/enrollments" in x])'

curl -fsS \
  "https://staging.solslot.com/protocol-api/zkpassport/enrollments/$VAULT_LAUNCHER_ID" \
  | python3 -m json.tool
```

A successful receipt must contain all of the following:

```text
status = chia_confirmed
receipt.identityAttestRoot = non-empty 32-byte root
receipt.chiaVaultCoinId = current unspent singleton coin id
receipt.confirmedBlockIndex = non-zero Coinset height
receipt.chiaSpendBundleId = submitted atomic bundle id
```

Then hard-refresh Alpha, reconnect the same wallet, and clear browser storage.
The portal must recover the same verified state from Chia and the API. Switching
to Beta must hide the protocol vault and credential state completely.

## Failure Handling

- A `404` enrollment read means no server receipt exists. Show unverified.
- `evm_confirmed` means the phone/EVM half worked but the owner has not stamped
  the Chia vault. Ask for the vault-owner signature; do not rescan the passport.
- `stamp_pending` means the bundle was submitted. Poll `stamp/sync`; do not ask
  for another owner signature unless the API explicitly expires the attempt.
- `receipt_syncing` means the receipt cannot prove the current coin. Block all
  offer and checkout actions until reconciliation succeeds.
- A bridge coin mismatch, owner mismatch, stale BLS timestamp, reused event, or
  wrong current coin is a hard failure and requires a fresh prepared package.

## Versioned Legacy Names

Existing v1 vault puzzles commit to the EIP-712 names `Populis Protocol` and
`PopulisVaultSpend`. Those strings cannot be changed for an already-launched
vault without invalidating its puzzle and signatures. Registration and public
product surfaces use Solslot. Removing the v1 cryptographic names requires a
new Solslot vault puzzle version and a version-registry migration, not a text
replacement in a deployed contract.
