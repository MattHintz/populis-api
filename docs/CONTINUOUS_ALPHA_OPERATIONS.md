# Continuous Public Alpha Operations

This runbook governs the open Testnet11 Alpha until the three-administrator authority approves teardown.

## Required Live Controls

- Confirm the promoted Testnet11 artifact hash and source SHA match API, portal, validator, KoS/Samuel, Base gateway/spoke, and relayer status endpoints.
- Keep Beta/mainnet protocol writes disabled and verify Alpha/Beta browser-session isolation after every deployment.
- Observe API error rate, pending payment age, Base gateway fee balance, CCIP/Warp failures, validator quorum, bridge inventory, reconciliation mismatches, and bug-report volume.
- Preserve immutable audit events, payment evidence, chain IDs, release metadata, and incident records in persistent backups.

## Payment Incident Procedure

1. Pause new purchases through the reviewed authority path.
2. Identify the last confirmed state from spoke, CCIP, gateway, Warp/Samuel, KoS, Chia, and API evidence using the global payment ID.
3. Retry only the next idempotent forwarding operation. Do not issue a replacement payment ID or reroute an in-flight payment.
4. Use the authenticated voucher refund path only before series launch/cancellation settlement; refunds always target the original Base depositor.
5. Use delayed emergency refund only after fulfillment is halted and the incident owner confirms no successful result can arrive.
6. Record the correlation ID, chain/message/coin IDs, timing, operator, resolution, and user-facing status update.

## Telemetry and Bug Reports

- `/alpha/telemetry` stores pseudonymous Alpha events with release and artifact binding.
- `/alpha/bug-reports` records user reports; client diagnostics are sent only when explicitly opted in.
- Never submit seed phrases, private keys, tokens, authorization headers, raw zkPassport proofs, or validator material.
- Triage payment/security reports first, link every report to telemetry correlation IDs and chain records, and publish active user-impacting incidents on the status surface.

## Teardown

Teardown requires recorded three-admin approval. Pause writes, reconcile every non-terminal payment, preserve valid refund availability, export evidence/bug records, archive the signed artifact and release metadata, revoke operational credentials, and verify mainnet configuration was never changed.
