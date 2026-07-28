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
- The customer API exposes each record and an activation report covering
  governance, network, release evidence, installed adapter execution,
  transfer confirmation where applicable, and the runtime gate.
- The customer site renders the checks and never trusts browser-supplied
  portals, assets, factories, pools, prices, or fee recipients.
- Authenticated customers can prepare evidence-bound EVM liquidity intents
  when every gate passes. The Warp transaction builders and official handoff
  are implemented, but bridge intent creation remains blocked until Solslot
  can independently observe pending, relayed, and completed Warp transfers.
- Release loading exercises every adapter path and binds its chain, assets,
  decimals, factory, pool, and runtime coordinates to the exact statutes
  record before readiness can become `READY`.
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

The Warp transaction builders and customer EVM executor are present. The route
must still remain inactive until wSOLS is registered by Warp, the resulting
two-direction transfer evidence is independently reviewed, and the official
watcher/explorer completion contract is pinned behind a resumable Solslot
status endpoint. Warp documents that its watcher powers pending and finished
transfer views, but does not currently publish a stable watcher API contract
that this release can safely embed.

## Liquidity Deliverables

For each native adapter:

- Exact chain, protocol, factory, pool, base asset, quote asset, and runtime
  code hash.
- Quote and calldata fixtures for add, inspect, collect, and remove.
- Approval amount, slippage, minimum received, price-range, fee, and gas tests.
- Runtime bytecode re-verification and a small reversible rehearsal.
- One active statutes `LiquidityVenue` record matching the evidence exactly.

The release includes exact transaction builders for Aerodrome V1 and Uniswap
V3 and an exact TibetSwap V2 wallet-offer builder. Do not activate a TibetSwap
record until Goby, Sage, Chia WalletConnect, and Google Vault offer creation
all pass the release fixture; preparing an offer description is not sufficient
execution evidence. This is enforced in API readiness: an active TibetSwap
record keeps liquidity execution disabled in this release. Other community
venues remain verified external handoffs until their native adapter receives
the same review.

## Release Evidence

Each capability uses a separate JSON file:

```json
{
  "schemaVersion": 2,
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
    "evidenceRoot": "0x...",
    "adapters": [
      {
        "adapterId": "warp-cat-bridge-v1",
        "kind": "WARP_CAT",
        "recordId": "0x...",
        "networkLabel": "Base",
        "assetSymbol": "SOLS",
        "assetDecimals": 3,
        "chiaChainId": "0x...",
        "evmChainId": 8453,
        "solsAssetId": "0x...",
        "wrappedCat": "0x...",
        "warpPortal": "0x...",
        "assetRegistry": "0x...",
        "runtimeCodeHashes": {
          "wrappedCat": "0x...",
          "warpPortal": "0x...",
          "assetRegistry": "0x..."
        },
        "messageTollWei": "0",
        "chiaMessageTollMojos": "0",
        "officialHandoffUrlTemplate": "https://warp.green/bridge?destination={destination}&amount={amountMojos}&asset={assetId}",
        "explorerUrlTemplate": "https://warp.green/explorer/{operationId}"
      }
    ]
  },
  "implementation": {
    "complete": true,
    "fixturesPassed": true
  }
}
```

Liquidity descriptors use the same envelope and additionally bind
`networkLabel`, `baseSymbol`, `baseDecimals`, `quoteSymbol`, `quoteDecimals`,
and `liquidityDecimals`. Aerodrome and Uniswap descriptors carry the exact EVM
chain, token, factory, pool, router or position-manager coordinates. TibetSwap
descriptors carry the Chia chain ID, factory singleton, pair launcher, CAT and
LP asset IDs, quote asset ID, and official HTTPS API origin. The evidence
loader rejects a descriptor whose execution coordinates do not reproduce the
governed `LiquidityVenue`.

Every adapter descriptor also carries `runtimeCodeHashes`. Warp requires the
WrappedCAT, portal, and asset-registry runtime hashes. Aerodrome requires the
router, factory, pool, and both token hashes. Uniswap requires the position
manager, factory, pool, and both token hashes. TibetSwap requires the live pair
puzzle hash as `runtimeCodeHashes.pair`. The governed venue's `poolCodeHash`
must equal the descriptor's pool or pair hash. Generate these values from the
same confirmed chain state used for the independent release review; do not
copy them from a browser or venue UI.

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

## What The Owner Must Provide

No Solslot private key or secret is needed. Before a later mainnet beta, the
owner must authorize and retain evidence for these external actions:

1. Register the final mainnet Sols CAT through Warp's official wrapped-CAT
   process and approve the deployment funding transaction.
2. Supply the resulting wSOLS addresses, official registry/watcher pull
   requests, runtime code hashes, message tolls, and successful transfer IDs
   in both directions.
3. Choose the initial pools and funding amounts. The technical coadministrator
   then records each exact factory, pool, pair, asset, and code hash for the SGT
   proposal.
4. Approve the administrator proposal and SGT vote for each route or venue.
   Records not approved on chain stay absent or inactive.
5. Approve an independent review of the adapter fixtures and signed evidence
   checksum before the operator changes either runtime flag.

For Testnet11 alpha, none of these external actions are required. Keep both
flags false; the customer pages remain educational and the native SmartDeed
and Sols swap directions continue to operate independently.
