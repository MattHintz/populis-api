from __future__ import annotations

import pytest
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.genesis_funding import (
    FUNDING_NAMES,
    GENESIS_BRIDGE_BATCH_FUNDING_AMOUNT,
    plan_genesis_funding_fanout,
)


def _source(amount: int = 2_000_000) -> Coin:
    return Coin(bytes32(b"p" * 32), bytes32(b"f" * 32), uint64(amount))


def test_funding_plan_derives_nine_distinct_confirmable_coin_ids() -> None:
    source = _source()
    result = plan_genesis_funding_fanout(
        source_coin=source,
        faucet_puzzle_hash=source.puzzle_hash,
        network="testnet11",
    )
    outputs = result.plan["outputs"]
    assert result.plan["schemaVersion"] == 3
    assert result.plan["protocolVersion"] == "solslot-v2-rc22"
    assert [item["name"] for item in outputs] == list(FUNDING_NAMES)
    assert "statutes" in result.plan["fundingCoinIds"]
    assert "navRegistry" not in result.plan["fundingCoinIds"]
    assert len({item["amount"] for item in outputs}) == 9
    assert len({item["coinId"] for item in outputs}) == 9
    assert outputs[0]["amount"] == 1_000_000
    bridge_batch = next(item for item in outputs if item["name"] == "bridgeBatch")
    assert bridge_batch["amount"] == GENESIS_BRIDGE_BATCH_FUNDING_AMOUNT == 529
    assert result.plan["fundingCoinIds"]["bridgeBatch"] == bridge_batch["coinId"]
    assert result.digest.startswith("0x") and len(result.digest) == 66


def test_funding_plan_rejects_embedded_fee_padding() -> None:
    source = _source()
    with pytest.raises(ValueError, match="separate fee till"):
        plan_genesis_funding_fanout(
            source_coin=source,
            faucet_puzzle_hash=source.puzzle_hash,
            network="testnet11",
            fee=1,
        )


def test_funding_plan_rejects_wrong_network_or_insufficient_source() -> None:
    source = _source(10)
    with pytest.raises(ValueError, match="restricted"):
        plan_genesis_funding_fanout(
            source_coin=source,
            faucet_puzzle_hash=source.puzzle_hash,
            network="mainnet",
        )
    with pytest.raises(ValueError, match="fan-out needs"):
        plan_genesis_funding_fanout(
            source_coin=source,
            faucet_puzzle_hash=source.puzzle_hash,
            network="testnet11",
        )
