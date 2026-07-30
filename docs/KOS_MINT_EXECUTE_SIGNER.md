# KoS MINT Execute Signer

## Purpose

KoS is a separate, testnet-only co-signer for one protocol condition:
`governance-mint-execute-v1`. It is not a coordinator wallet, a general BLS
signing API, an administrator key, or an authority to move funds.

The RC governance singleton curries one KoS public key. On a passed MINT
execution it emits exactly one `AGG_SIG_ME` condition over:

```text
PROTOCOL_PREFIX || "KOSM" || sha256tree(
  governance_singleton_struct,
  live_governance_coin_id,
  proposal_hash
)
```

Consensus accepts the execution only when the resulting aggregate contains a
valid signature for that exact condition. No proposal, vote, freeze, settlement,
offer, vault, or arbitrary transfer path emits the KoS condition.

The public key is part of the signed genesis artifact at
`governanceStruct.mintExecuteCosignerPubkey`. Rotating it changes the immutable
governance puzzle and therefore requires a new RC and ceremony; it is not an
environment-variable change.

## Separation Of Duties

| Component | Holds | May do |
| --- | --- | --- |
| Portal | Administrator wallet signatures | Build and submit the canonical five-spend MINT bundle |
| Coordinator API | mTLS client credential only | Re-derive a valid MINT condition and request a signature |
| KoS signer | One BLS private key and its SQLite action ledger | Sign one verified MINT condition for one live governance coin |

The coordinator never receives the KoS private key. The signer exposes no
generic signing route and must never be mounted below `/protocol-api/` or
published through Cloudflare.

## Ceremony Input

Before generating a ceremony plan, create the KoS BLS key in the approved HSM
or offline key ceremony. Record only its 48-byte compressed public key in the
plan as:

```json
{
  "kosMintExecutePubkey": "0x<96 lowercase hex characters>"
}
```

Keep the private scalar out of the plan, artifact, release archives, GitHub
Actions, browser storage, and coordinator environment. The protocol preflight
and artifact verifier reject a missing, zero, or malformed key.

## Isolated Signer Host

Deploy the signer from the same exact API/protocol release as the coordinator,
but to a separate private host or private network namespace. It must have:

- a private loopback or WireGuard `10/8` listener;
- a server TLS certificate, private key, and client-CA file;
- a systemd credential containing exactly the 32-byte serialized BLS private
  key as lowercase hex, mode `0600`;
- a persistent SQLite-WAL ledger outside the release directory; and
- the signed public artifact and matching `release.json` mounted read-only.

Example non-secret service configuration:

```ini
[Service]
User=solslot-kos
Group=solslot-kos
WorkingDirectory=/opt/solslot/kos-mint-execute/current
Environment=SOLSLOT_KOS_SIGNER_NETWORK=testnet11
Environment=SOLSLOT_KOS_SIGNER_BIND_HOST=10.77.0.30
Environment=SOLSLOT_KOS_SIGNER_BIND_PORT=9445
Environment=SOLSLOT_KOS_SIGNER_LEDGER_DB_PATH=/var/lib/solslot-kos/kos-mint-execute.db
Environment=SOLSLOT_KOS_SIGNER_PUBLIC_ARTIFACT_PATH=/etc/solslot-kos/public_artifact_v4.json
Environment=SOLSLOT_KOS_SIGNER_RELEASE_METADATA_PATH=/opt/solslot/kos-mint-execute/current/release.json
Environment=SOLSLOT_KOS_SIGNER_PRIVATE_KEY_FILE=%d/kos-mint-execute.key
Environment=SOLSLOT_KOS_SIGNER_TLS_CERT_FILE=/etc/solslot-kos/tls/server.pem
Environment=SOLSLOT_KOS_SIGNER_TLS_KEY_FILE=/etc/solslot-kos/tls/server-key.pem
Environment=SOLSLOT_KOS_SIGNER_TLS_CLIENT_CA_FILE=/etc/solslot-kos/tls/coordinator-ca.pem
LoadCredential=kos-mint-execute.key:/secure/operator-provisioned/kos-mint-execute.key
ExecStart=/opt/solslot/kos-mint-execute/current/.venv/bin/python -m solslot_api.kos_mint_execute_main
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
```

The service refuses to start without TLS and a client CA. Its `/health` result
must report the signed artifact hash, the exact artifact-bound public key, and
the matching API and protocol commits. Do not expose this health endpoint to
the public Internet.

## Coordinator Configuration

The normal API keeps this capability disabled by default. On Testnet11 only,
after independent signer-health evidence is archived, configure the
coordinator with file paths owned by its service account:

```text
SOLSLOT_KOS_MINT_EXECUTE_SIGNER_ENABLED=true
SOLSLOT_KOS_MINT_EXECUTE_SIGNER_URL=https://kos-signer.testnet.internal:9445
SOLSLOT_KOS_MINT_EXECUTE_SIGNER_MTLS_CA_PATH=/etc/solslot-api/kos-ca.pem
SOLSLOT_KOS_MINT_EXECUTE_SIGNER_MTLS_CERT_PATH=/etc/solslot-api/kos-client.pem
SOLSLOT_KOS_MINT_EXECUTE_SIGNER_MTLS_KEY_PATH=/etc/solslot-api/kos-client-key.pem
```

Startup rejects this configuration unless alpha writes and minting are already
enabled, the network is `testnet11`, the endpoint is HTTPS, and all three mTLS
files exist. Those gates remain off by default. A signer request independently
checks the signed artifact, release pins, live unspent one-mojo governance
coin, public-key match, exact message, and a one-action-per-governance-coin
ledger before it returns a signature.

## Operational Checks

1. Verify the ceremony plan, artifact, coordinator release, and signer health
   all report the same KoS public key and exact API/protocol commit pair.
2. Verify the signer listener is reachable only over the private mTLS network.
3. Run the automated signer, coordinator-client, and full protocol consensus
   suites before enabling the feature.
4. Execute one disposable Testnet11 MINT from a browser. Archive the portal
   bundle id, KoS request hash, Coinset response, and confirmed coin evidence.
5. Confirm a replay, altered proposal hash, stale governance coin, invalid
   artifact, missing client certificate, or second different request for the
   same governance coin is rejected.

An unavailable signer returns a coordinator `503` before a bundle is submitted.
The operator should repair the signer and rebuild the execution from current
chain state; neither the browser nor the coordinator can substitute a generic
signature.
