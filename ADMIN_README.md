# Solslot V2 Administrator Authority

The API has deliberately separate ceremony and post-genesis authority
surfaces.

## Official Testnet11 Operator Boundary

For `solslot-v2-alpha-rc27.33-20260823`, the official initialization path is
the guided owner claim with the protected server review class
`independent-release-review`. The protected direct genesis API is an operator
compatibility surface, not a way to bypass guided readiness, independent
evidence, or strict preflight.

Names such as `admin_authority_v2`, `bootstrap_manifest_v2.json`, and the
`/admin/auth/authority_v2` route identify preserved Chia puzzle, artifact, or
API schemas. They do not describe the current release authority model and do
not replace the cross-chain Authority V3 evidence and independent-review
receipt required for the official Testnet11 ceremony.

## Ceremony Authority

`SOLSLOT_ADMIN_TOKEN` unlocks only the protected direct `/admin/genesis/*`
operator endpoints while isolated ceremony mode is active. The retired
`/admin/bootstrap/*`, `/admin/deploy/protocol`, `/admin/deployment`, and
`/admin/protocol-config/finalize` routes are intentionally not mounted.

The official guided flow instead starts from the single-use owner claim and
issues an HTTP-only, secure, same-site launch session. Administrator wallets
then sign the exact enrollment, plan, gate, and artifact actions required by
the ceremony. Neither a guided session nor the direct operator token can
authorize normal post-genesis admin routes. Finalization writes the bootstrap
lock last; remove the owner-claim and operator-token material immediately
after the ceremony evidence is archived.

## Chain-Bound Admin Authority

Post-genesis admin operations use wallet-signed EIP-712 login and short-lived
JWTs. The only membership source is a V2 `admin_records_v2.json` file at
`SOLSLOT_ADMIN_RECORDS_PATH`.

At startup the API:

1. Requires `schemaVersion: 2` and rejects the retired `version` field.
2. Recomputes the records `admins_hash` with the protocol implementation.
3. Matches that hash and launcher to the current admin-authority ceremony
   coordinates.
4. Refuses startup on malformed records, drift, missing trust roots, or a
   non-empty retired environment-only allowlist.
5. Requires a stable `SOLSLOT_ADMIN_JWT_SECRET` whenever the desk is enabled.

The login flow is:

1. `POST /admin/auth/challenge`
2. Wallet signs `SolslotAdminLogin` under `Solslot Protocol`, version `2`.
3. `POST /admin/auth/login`
4. API recovers the signer, checks the current records set, and issues a
   short-lived JWT.
5. Every protected request checks membership again, providing immediate
   revocation without waiting for JWT expiry.

## Route Boundaries

- Mint proposal mutations require the chain-bound admin JWT.
- zkPassport bridge-pool top-up requires the chain-bound admin JWT.
- Committee voting uses its own signed committee authority.
- Bootstrap cookies and ceremony tokens are rejected by post-genesis routes.
- Public authority and receipt reads expose only on-chain/public material.

## Records Format

```json
{
  "$schema": "https://solslot.io/schemas/admin_records_v2.json",
  "schemaVersion": 2,
  "launcher_id": "0x...",
  "admin_records": [
    {
      "admin_idx": 0,
      "m_within": 1,
      "leaves": [
        {
          "kind": "eip712_member",
          "leaf_hash": "0x...",
          "evm_address": "0x...",
          "secp256k1_pubkey": "0x...",
          "type_hash": "0x...",
          "prefix_and_domain_separator": "0x..."
        }
      ]
    }
  ]
}
```

Admin records contain public keys, addresses, and commitments, not private
keys. They still belong in the checksummed ceremony bundle because modifying
them changes the authority interpretation and must fail startup.
