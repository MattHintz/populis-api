from __future__ import annotations

import pytest
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.genesis_funding import FUNDING_NAMES, plan_genesis_funding_fanout


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
    assert [item["name"] for item in outputs] == list(FUNDING_NAMES)
    assert len({item["amount"] for item in outputs}) == 9
    assert len({item["coinId"] for item in outputs}) == 9
    assert outputs[0]["amount"] == 1_000_000
    assert result.plan["fundingCoinIds"]["bridgeBatch"]
    assert result.digest.startswith("0x") and len(result.digest) == 66


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
