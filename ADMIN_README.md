# Solslot V2 Administrator Authority

The API has two deliberately separate authority surfaces.

## Ceremony Authority

`SOLSLOT_ADMIN_TOKEN` unlocks only the run-once ceremony endpoints while no
bootstrap lock exists:

- `POST /admin/bootstrap/challenge`
- `POST /admin/deploy/protocol`
- `POST /admin/protocol-config/finalize`
- `GET /admin/deployment`

The challenge exchanges the bearer credential for an HTTP-only, secure,
same-site bootstrap cookie. The cookie is scoped to `/admin/bootstrap`, has a
short TTL, and cannot authorize normal admin routes. Finalization writes the
bootstrap lock last. The bearer credential must be rotated or removed after
the ceremony evidence is archived.

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
