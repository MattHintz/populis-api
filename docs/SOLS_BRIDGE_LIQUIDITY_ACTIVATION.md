# Sols Bridge And Liquidity Activation

This is the release boundary for customer Sols bridging and governed liquidity.
It does not apply to Testnet11 SmartDeed/Sols swaps, which remain native Chia
protocol actions.

Official Warp references:

- <https://docs.warp.green/developers/cat-bridge>
- <https://docs.warp.green/users/creating-a-new-wrapped-cat>

## What Is Already Wired

- Protocol statutes reconstruct the exact governed `BridgeRoute` and
  `LiquidityVenue` records from Chia.
- The customer API exposes each record and a five-check activation report.
- The customer site renders the checks and never trusts browser-supplied
  portals, assets, factories, pools, prices, or fee recipients.
- Runtime flags are mainnet-only. A flag cannot bypass missing release
  evidence or an absent transaction adapter.
- Release evidence is bounded, checksum-pinned, mainnet-only, and must match
  the current statutes root and exact records.
- The Samuel/Base Sepolia Warp portal remains the purchase-message rail. Its
  evidence is preserved, but it does not authorize a customer wSOLS CAT route.

## Owner Decisions Needed Before Mainnet Beta

1. Approve the official Warp registration process for Sols.
2. Fund the Base mainnet `WrappedCAT` deployment and a small two-direction test.
3. Approve which initial venues and pairs should be proposed to SGT:
   - TibetSwap: `SOLS/wUSDC` and `SOLS/wUSDC.b` on Chia.
   - Uniswap: `wSOLS/USDC` and `wSOLS/USDT` on an approved EVM network.
   - Aerodrome: `wSOLS/USDC` and `wSOLS/USDT` on Base.
4. Approve the initial liquidity amount and price range for each pool. This is
   market liquidity, not Pool V4's governed SmartDeed exchange value.
5. Approve the SGT proposals that activate the exact route and venue records.

Do not send private keys, OAuth secrets, validator keys, or Safe owner seed
phrases to the API or repository.

## Warp Deliverables

The official Warp CAT flow requires all of the following before activation:

- Base mainnet `WrappedCAT` address for wSOLS.
- Chia Sols CAT asset ID and decimal conversion.
- Official Warp portal and Chia locker/unlocker coordinates.
- Runtime bytecode and puzzle hashes re-derived from reviewed source.
- Asset registry, watcher/explorer, and UI registration evidence.
- One successful Sols-to-wSOLS transfer and one successful return transfer.
- A reviewed Solslot transfer adapter with resume, replay, toll, sponsorship,
  destination, and amount fixtures.

The API will continue to report `AWAITING_EXECUTION_SURFACE` until that adapter
is actually present in code. Evidence and a feature flag cannot change this
code-owned boundary.

## Liquidity Deliverables

For each native adapter:

- Exact chain, protocol, factory, pool, base asset, quote asset, and runtime
  code hash.
- Quote and calldata fixtures for add, inspect, collect, and remove.
- Approval amount, slippage, minimum received, price-range, fee, and gas tests.
- Runtime bytecode re-verification and a small reversible rehearsal.
- One active statutes `LiquidityVenue` record matching the evidence exactly.

Other community venues remain verified external handoffs until their native
adapter receives the same review.

## Release Evidence

Each capability uses a separate JSON file:

```json
{
  "schemaVersion": 1,
  "kind": "solslot-sols-capability-release",
  "capability": "warp-cat-bridge",
  "network": "mainnet",
  "releaseTag": "solslot-v2-beta-rcN",
  "sourceSha": "40-lowercase-hex-characters",
  "governedRoot": "0x...",
  "auditStatus": "reviewed",
  "testOnly": false,
  "adapterIds": ["warp-cat-bridge-v1"],
  "records": [],
  "runtimeEvidence": {
    "verified": true,
    "evidenceRoot": "0x..."
  },
  "implementation": {
    "complete": true,
    "fixturesPassed": true
  }
}
```

The raw file SHA-256 must be recorded in the signed release manifest and set
with the matching deployment variables:

```text
SOLSLOT_SOLS_BRIDGE_RELEASE_EVIDENCE_PATH=
SOLSLOT_SOLS_BRIDGE_RELEASE_EVIDENCE_SHA256=
SOLSLOT_SOLS_LIQUIDITY_RELEASE_EVIDENCE_PATH=
SOLSLOT_SOLS_LIQUIDITY_RELEASE_EVIDENCE_SHA256=
```

Only after the evidence, installed adapter, mainnet network, active statutes
record, and rehearsal all match may the final runtime flags be enabled:

```text
SOLSLOT_SOLS_BRIDGE_ENABLED=true
SOLSLOT_SOLS_LIQUIDITY_ENABLED=true
```

These variables must remain false for Testnet11 alpha.
