from __future__ import annotations

from eth_abi import decode as abi_decode
from eth_utils import keccak
import pytest

from solslot_api.sols_capability_adapters import (
    SolsCapabilityAdapterError,
    build_aerodrome_liquidity_intent,
    build_tibetswap_liquidity_intent,
    build_uniswap_v3_liquidity_intent,
    build_warp_bridge_intent,
    descriptor_for_record,
)


RECORD_ID = "0x" + "11" * 32
SOLS_ASSET_ID = "0x" + "12" * 32
TOKEN_A = "0x1111111111111111111111111111111111111111"
TOKEN_B = "0x2222222222222222222222222222222222222222"
ACCOUNT = "0x3333333333333333333333333333333333333333"
ROUTER = "0x4444444444444444444444444444444444444444"
FACTORY = "0x5555555555555555555555555555555555555555"
POOL = "0x6666666666666666666666666666666666666666"


def _selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def test_warp_evm_to_chia_builds_exact_bridge_back_call() -> None:
    descriptor = {
        "adapterId": "warp-base-v1",
        "kind": "WARP_CAT",
        "recordId": RECORD_ID,
        "evmChainId": 8453,
        "wrappedCat": TOKEN_A,
        "messageTollWei": "10000000000000",
        "explorerUrlTemplate": "https://warp.green/explorer/{operationId}",
    }
    result = build_warp_bridge_intent(
        descriptor=descriptor,
        direction="EVM_TO_CHIA",
        amount_mojos="9000",
        destination="0x" + "ab" * 32,
    )
    transaction = result["transactions"][0]
    raw = bytes.fromhex(transaction["data"][2:])

    assert transaction["to"] == TOKEN_A
    assert transaction["value"] == "10000000000000"
    assert raw[:4] == _selector("bridgeBack(bytes32,uint256)")
    assert abi_decode(["bytes32", "uint256"], raw[4:]) == (
        bytes.fromhex("ab" * 32),
        9000,
    )


def test_warp_chia_to_evm_uses_exact_offer_and_official_handoff() -> None:
    descriptor = {
        "adapterId": "warp-base-v1",
        "kind": "WARP_CAT",
        "recordId": RECORD_ID,
        "solsAssetId": SOLS_ASSET_ID,
        "chiaMessageTollMojos": "1000000000",
        "officialHandoffUrlTemplate": (
            "https://warp.green/bridge?destination={destination}"
            "&amount={amountMojos}&asset={assetId}"
        ),
        "explorerUrlTemplate": "https://warp.green/explorer/{operationId}",
    }
    result = build_warp_bridge_intent(
        descriptor=descriptor,
        direction="CHIA_TO_EVM",
        amount_mojos="2000",
        destination=ACCOUNT,
    )

    assert result["executionMode"] == "OFFICIAL_WARP_OFFER"
    assert result["walletOffer"]["offer"] == [
        {"assetId": SOLS_ASSET_ID, "amount": "2000"},
        {"assetId": None, "amount": "1000000000"},
    ]
    assert ACCOUNT in result["handoffUrl"]


def test_aerodrome_add_binds_router_pair_and_exact_amounts() -> None:
    descriptor = {
        "adapterId": "aerodrome-base-v1",
        "kind": "AERODROME_V1",
        "recordId": RECORD_ID,
        "evmChainId": 8453,
        "router": ROUTER,
        "factory": FACTORY,
        "pool": POOL,
        "tokenA": TOKEN_A,
        "tokenB": TOKEN_B,
        "stable": True,
    }
    result = build_aerodrome_liquidity_intent(
        descriptor=descriptor,
        action="ADD",
        account=ACCOUNT,
        amount_a="1000",
        amount_b="2000",
        liquidity="0",
        min_a="990",
        min_b="1980",
        deadline_seconds=600,
    )
    transactions = result["transactions"]
    add_data = bytes.fromhex(transactions[2]["data"][2:])

    assert [item["to"] for item in transactions] == [TOKEN_A, TOKEN_B, ROUTER]
    assert add_data[:4] == _selector(
        "addLiquidity(address,address,bool,uint256,uint256,uint256,uint256,address,uint256)"
    )
    decoded = abi_decode(
        [
            "address",
            "address",
            "bool",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "address",
            "uint256",
        ],
        add_data[4:],
    )
    assert decoded[:8] == (
        TOKEN_A,
        TOKEN_B,
        True,
        1000,
        2000,
        990,
        1980,
        ACCOUNT,
    )


def test_uniswap_v3_rejects_unaligned_ranges_and_builds_collect() -> None:
    descriptor = {
        "adapterId": "uniswap-base-v3",
        "kind": "UNISWAP_V3",
        "recordId": RECORD_ID,
        "evmChainId": 8453,
        "positionManager": ROUTER,
        "factory": FACTORY,
        "pool": POOL,
        "tokenA": TOKEN_A,
        "tokenB": TOKEN_B,
        "fee": 3000,
        "tickSpacing": 60,
    }
    with pytest.raises(
        SolsCapabilityAdapterError,
        match="tick spacing",
    ):
        build_uniswap_v3_liquidity_intent(
            descriptor=descriptor,
            action="ADD",
            account=ACCOUNT,
            amount_a="1000",
            amount_b="2000",
            liquidity="0",
            min_a="990",
            min_b="1980",
            token_id=None,
            tick_lower=-121,
            tick_upper=120,
            deadline_seconds=600,
        )

    result = build_uniswap_v3_liquidity_intent(
        descriptor=descriptor,
        action="COLLECT",
        account=ACCOUNT,
        amount_a="0",
        amount_b="0",
        liquidity="0",
        min_a="0",
        min_b="0",
        token_id="42",
        tick_lower=None,
        tick_upper=None,
        deadline_seconds=600,
    )
    collect_data = bytes.fromhex(result["transactions"][0]["data"][2:])
    assert collect_data[:4] == _selector(
        "collect((uint256,address,uint128,uint128))"
    )


def test_uniswap_v3_remove_sorts_display_minimums_into_token_order() -> None:
    descriptor = {
        "adapterId": "uniswap-base-v3",
        "kind": "UNISWAP_V3",
        "recordId": RECORD_ID,
        "evmChainId": 8453,
        "positionManager": ROUTER,
        "factory": FACTORY,
        "pool": POOL,
        "tokenA": TOKEN_B,
        "tokenB": TOKEN_A,
        "fee": 3000,
        "tickSpacing": 60,
    }
    result = build_uniswap_v3_liquidity_intent(
        descriptor=descriptor,
        action="REMOVE",
        account=ACCOUNT,
        amount_a="0",
        amount_b="0",
        liquidity="5000",
        min_a="900",
        min_b="1900",
        token_id="42",
        tick_lower=None,
        tick_upper=None,
        deadline_seconds=600,
    )
    decrease_data = bytes.fromhex(result["transactions"][0]["data"][2:])
    decoded = abi_decode(
        ["(uint256,uint128,uint256,uint256,uint256)"],
        decrease_data[4:],
    )[0]

    assert decrease_data[:4] == _selector(
        "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))"
    )
    assert decoded[:4] == (42, 5000, 1900, 900)


def test_tibetswap_offer_never_accepts_client_endpoint_or_pair() -> None:
    descriptor = {
        "adapterId": "tibetswap-mainnet-v2",
        "kind": "TIBETSWAP_V2",
        "recordId": RECORD_ID,
        "pairLauncherId": "0x" + "21" * 32,
        "tokenA": SOLS_ASSET_ID,
        "liquidityAssetId": "0x" + "22" * 32,
        "officialApiOrigin": "https://api.v2.tibetswap.io",
    }
    result = build_tibetswap_liquidity_intent(
        descriptor=descriptor,
        action="REMOVE",
        amount_xch_mojos="3000",
        amount_cat_mojos="4000",
        liquidity_mojos="5000",
    )

    assert result["executionMode"] == "CHIA_WALLET_OFFER"
    assert result["submission"]["url"].endswith("21" * 32)
    assert result["submission"]["action"] == "REMOVE_LIQUIDITY"
    assert descriptor_for_record([descriptor], record_id=RECORD_ID) is descriptor


def test_adapter_inputs_fail_closed_on_noncanonical_amounts() -> None:
    descriptor = {
        "adapterId": "warp-base-v1",
        "kind": "WARP_CAT",
        "recordId": RECORD_ID,
        "evmChainId": 8453,
        "wrappedCat": TOKEN_A,
        "messageTollWei": "1",
        "explorerUrlTemplate": "https://warp.green/explorer/{operationId}",
    }
    with pytest.raises(SolsCapabilityAdapterError, match="canonical decimal"):
        build_warp_bridge_intent(
            descriptor=descriptor,
            direction="EVM_TO_CHIA",
            amount_mojos="09000",
            destination="0x" + "ab" * 32,
        )
