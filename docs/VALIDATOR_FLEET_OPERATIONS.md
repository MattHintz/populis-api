# Validator Fleet Operations

The Solslot V2 credential bridge uses three independent BLS signers and a
two-signature threshold. The public API coordinates claims but holds no
validator seed and never mounts validator signing routes.

For the official Testnet11 ceremony, all three signer health responses must be
bound to the exact API and Protocol commits in the coordinated
`solslot-v2-alpha-rc27.36-20260824` source manifest. Do not substitute a prior
RC placeholder, uploaded health JSON, or a two-of-three reachability result for
the required three-of-three pre-genesis health check. Payment/Stripe readiness
is a separate post-genesis activation gate.

## Topology

| Role | WireGuard address | Runtime |
| --- | --- | --- |
| API coordinator and WireGuard hub | `10.77.0.1` | `solslot_api.app:app` |
| Signer 0 on Vaults EC2 | `10.77.0.10` | `solslot_api.validator_app:app` |
| Signer 1 on the new Ubuntu VPS | `10.77.0.11` | `solslot_api.validator_app:app` |
| Signer 2 on the fallback host | `10.77.0.12` | `solslot_api.validator_app:app` |

Each signer listens on HTTPS port `9443` only on its WireGuard address. It
requires a coordinator mTLS client certificate. The host firewall drops
public traffic to the signer port.

## Generate Private Material

Run generation from a trusted machine into an empty mode-0700 directory. The
commands require their exact confirmation phrase and never emit private values
to standard output.

```bash
.venv/bin/python scripts/generate_validator_seeds.py \
  --signer-zero-seed-file /secure/existing/signer-0.seed \
  --output-dir /secure/validator-material \
  --confirm GENERATE-SOLSLOT-VALIDATOR-SEEDS-1-AND-2

bash scripts/generate_validator_network_material.sh \
  /secure/validator-network \
  GENERATE-SOLSLOT-VALIDATOR-NETWORK-MATERIAL
```

The first command verifies signer 0 and generates only signer 1 and signer 2.
Record public BLS keys, WireGuard public keys, and certificate fingerprints in
the private credential carryover record. Keep the mTLS CA private key offline
after certificate issuance.

## Provision A Signer

The operator must first install the hub configuration from
`ops/validator/wg0-coordinator.conf.example` and each signer configuration
from `ops/validator/wg0.conf.example`. The cloud/provider firewall permits UDP
`51820` only on the coordinator; signer hosts need no public signer port.
Verify private peer connectivity before installing the service. Then copy the
release archive and that host's seed and certificates through an authenticated
administrative channel.

```bash
sudo bash scripts/install_validator_host.sh \
  1 \
  10.77.0.11 \
  /secure/releases/solslot-api-<sha>.tgz \
  /secure/validator-1.env \
  /secure/validator-material/private/signer-1.seed \
  /secure/validator-network/public/mtls/ca.crt \
  /secure/validator-network/public/mtls/signer-1.crt \
  /secure/validator-network/private/mtls/signer-1.key \
  /secure/validator-material/private/signer-1-stripe-read.key

sudo bash scripts/configure_validator_firewall.sh 1
```

The installer creates an atomic release, validates the app import, verifies
both the signer seed and that host's distinct Stripe restricted test key,
installs root-readable credentials through systemd `LoadCredential`, and
verifies the process and private bind. It refuses an index/address mismatch
and does not configure a public listener. The coordinator then performs the
authenticated mTLS health check for the whole fleet.

After genesis confirmation and two administrator artifact signatures, install
the same verified public artifact on each signer. The command rejects an
invalid signature quorum or source SHA mismatch and updates the local copy
atomically:

```bash
sudo bash /opt/solslot/validator/current/scripts/install_validator_artifact.sh \
  /secure/ceremony/public_artifact_v4.json
```

Run the fleet check after all three hosts report the same artifact hash. Never
install a draft, unsigned, or pre-confirmation artifact.

## Runtime Configuration

Start from `config/validator.env.example`. Supply only public configuration in
the environment: signer index, roster public keys, network, bridge policy,
signed artifact path, EVM addresses, Stripe test account ID/API version, and
RPC endpoints. The seed, Stripe restricted read key, and TLS private key are
systemd credentials, never environment variables. Generate a different Stripe
restricted key for each validator and permit only Account, Event,
PaymentIntent, and Charges reads. Charges read access is required because the
service may request `GET /v1/charges/{id}` while verifying evidence. The
Sepolia RPC URL contains the replacement provider credential: install it
directly in the root-managed host configuration, redact it from diagnostics,
and never place the completed file in a release archive or ceremony evidence.

Signer state is local SQLite-WAL storage. Unique constraints cover claim hash,
scoped nullifier, bridge coin, vault action, and EVM transaction. A signer
derives vault ownership from the exact owner authorization and proves it
against the current Chia coin; it does not trust or replicate the coordinator's
vault database. Back up signer state with the online SQLite backup command:

```bash
sudo bash scripts/backup_validator_state.sh /secure/backups/signer-1
```

Restoring a ledger is a security operation. Stop the signer, verify checksums,
restore only to the same signer index and roster, and rerun the full live
preflight before returning it to quorum.

## Health And Preflight

The coordinator probes all three signers over mTLS. Uploaded health JSON does
not satisfy preflight.

```bash
.venv/bin/python scripts/check_validator_fleet.py \
  --api-commit <exact-rc27.36-api-sha-from-source-manifest> \
  --protocol-commit <exact-rc27.36-protocol-sha-from-source-manifest> \
  --bridge-policy-hash 0x<policy> \
  --forwarder 0x<address> \
  --verifier-adapter 0x<address> \
  --attestation-emitter 0x<address> \
  --require-no-artifact
```

Each response must match signer index, ordered BLS roster, API and protocol
commits, network, bridge policy, fresh EVM addresses, and ledger readiness.
All three signers must be healthy before genesis, even though runtime claim
authorization accepts any valid two. They must report `artifactReady: false`
at this phase because a signed artifact cannot exist before genesis confirms.
After finalization and artifact installation, rerun the same command with
`--require-artifact-hash 0x<artifact-hash>`; all three must then report
`artifactReady: true` before credential or mint writes are enabled.

The public coordinator must return `404` for `/v1/zkpassport/sign` and must
not publish validator OpenAPI. Confirm no seed exists under the coordinator
release, shared state, process environment, workflow secrets, or release
archive.

## Incident Rules

- One unavailable signer: credential writes stop unless two healthy signers
  remain; investigate before ceremony or release transitions.
- Ledger corruption: remove the signer from service, preserve evidence, and
  restore a verified backup. Do not initialize an empty ledger as a shortcut.
- Seed exposure: retire that signer identity, derive a new signed artifact and
  bridge policy through reviewed governance, and keep writes locked.
- EVM or Chia ambiguity: do not sign. Preserve the claim and chain evidence.
- Roster, artifact, release, or network mismatch: treat health as failed and
  do not override the check.

Signer 1 infrastructure must be provisioned by the operator. This repository
does not create a cloud account or paid host.
