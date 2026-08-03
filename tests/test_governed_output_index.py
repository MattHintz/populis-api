from __future__ import annotations

import pytest
from chia.types.blockchain_format.coin import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.governed_output_index import (
    BLOCKED,
    CONFIRMED,
    GovernedOutputConflict,
    GovernedOutputExpectation,
    GovernedOutputIndex,
    reconcile_governed_delivery,
)


def _hex(seed: int) -> str:
    return "0x" + (bytes([seed]) * 32).hex()


def _coin(parent: int, puzzle: int, amount: int = 1) -> Coin:
    return Coin(
        bytes32(bytes([parent]) * 32),
        bytes32(bytes([puzzle]) * 32),
        uint64(amount),
    )


def _record(coin: Coin, *, confirmed: int, spent: int = 0) -> dict:
    return {
        "coin": {
            "parent_coin_info": "0x" + coin.parent_coin_info.hex(),
            "puzzle_hash": "0x" + coin.puzzle_hash.hex(),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": confirmed,
        "spent_block_index": spent,
    }


class FakeProvider:
    def __init__(self, records: dict[str, dict | None]):
        self.records = records

    async def get_coin_record_by_name(self, coin_id: str):
        return self.records.get(coin_id)


def _expectation(ordinal: int, coin: Coin, launcher: int) -> GovernedOutputExpectation:
    return GovernedOutputExpectation(
        ordinal=ordinal,
        coin_id="0x" + coin.name().hex(),
        parent_coin_id="0x" + coin.parent_coin_info.hex(),
        puzzle_hash="0x" + coin.puzzle_hash.hex(),
        amount=int(coin.amount),
        deed_launcher_id=_hex(launcher),
    )


@pytest.mark.asyncio
async def test_indexes_and_confirms_every_atomic_smartdeed_output(tmp_path) -> None:
    index = GovernedOutputIndex(str(tmp_path / "purchases.db"))
    first = _coin(21, 31)
    second = _coin(22, 32)
    input_one = _coin(11, 41)
    input_two = _coin(12, 42)
    prepared = index.prepare(
        purchase_id=_hex(1),
        artifact_hash=_hex(2),
        rail="chia_xch",
        delivery_kind="smartdeed",
        quantity=2,
        input_coin_ids=(
            "0x" + input_one.name().hex(),
            "0x" + input_two.name().hex(),
        ),
        protocol_bundle_id=_hex(3),
        outputs=(
            _expectation(0, first, 51),
            _expectation(1, second, 52),
        ),
        now=100,
    )
    assert prepared.state == "PREPARED"
    index.bind_submission(
        _hex(1),
        spend_bundle_id=_hex(4),
        input_coin_ids=prepared.input_coin_ids,
        mempool_observed_at="2026-08-02T20:00:00Z",
        now=101,
    )
    provider = FakeProvider(
        {
            "0x" + first.name().hex(): _record(first, confirmed=500),
            "0x" + second.name().hex(): _record(second, confirmed=500),
            "0x" + input_one.name().hex(): _record(
                input_one, confirmed=400, spent=500
            ),
            "0x" + input_two.name().hex(): _record(
                input_two, confirmed=401, spent=500
            ),
        }
    )
    confirmed = await reconcile_governed_delivery(index, provider, _hex(1))
    assert confirmed.state == CONFIRMED
    assert confirmed.confirmation_height == 500
    outputs = index.outputs(_hex(1))
    assert [item.deed_launcher_id for item in outputs] == [_hex(51), _hex(52)]
    assert [item.confirmation_height for item in outputs] == [500, 500]


@pytest.mark.asyncio
async def test_partial_or_altered_output_fails_closed(tmp_path) -> None:
    index = GovernedOutputIndex(str(tmp_path / "partial.db"))
    first = _coin(21, 31)
    second = _coin(22, 32)
    input_coin = _coin(11, 41)
    index.prepare(
        purchase_id=_hex(1),
        artifact_hash=_hex(2),
        rail="stripe",
        delivery_kind="smartdeed",
        quantity=2,
        input_coin_ids=("0x" + input_coin.name().hex(),),
        protocol_bundle_id=_hex(3),
        outputs=(
            _expectation(0, first, 51),
            _expectation(1, second, 52),
        ),
    )
    partial = await reconcile_governed_delivery(
        index,
        FakeProvider(
            {
                "0x" + first.name().hex(): _record(first, confirmed=500),
                "0x" + second.name().hex(): None,
                "0x" + input_coin.name().hex(): _record(
                    input_coin, confirmed=400, spent=500
                ),
            }
        ),
        _hex(1),
    )
    assert partial.state == BLOCKED
    assert "only part" in str(partial.last_error)

    complete_records = {
        "0x" + first.name().hex(): _record(first, confirmed=500),
        "0x" + second.name().hex(): _record(second, confirmed=500),
        "0x" + input_coin.name().hex(): _record(
            input_coin, confirmed=400, spent=500
        ),
    }
    still_blocked = await reconcile_governed_delivery(
        index,
        FakeProvider(complete_records),
        _hex(1),
    )
    assert still_blocked.state == BLOCKED


@pytest.mark.asyncio
async def test_altered_coin_record_is_terminally_blocked(tmp_path) -> None:
    index = GovernedOutputIndex(str(tmp_path / "altered.db"))
    output = _coin(21, 31)
    input_coin = _coin(11, 41)
    index.prepare(
        purchase_id=_hex(1),
        artifact_hash=_hex(2),
        rail="stripe",
        delivery_kind="smartdeed",
        quantity=1,
        input_coin_ids=("0x" + input_coin.name().hex(),),
        protocol_bundle_id=_hex(3),
        outputs=(_expectation(0, output, 51),),
    )
    altered = _coin(21, 99)
    blocked = await reconcile_governed_delivery(
        index,
        FakeProvider(
            {
                "0x" + output.name().hex(): _record(altered, confirmed=500),
                "0x" + input_coin.name().hex(): _record(
                    input_coin, confirmed=400, spent=500
                ),
            }
        ),
        _hex(1),
    )
    assert blocked.state == BLOCKED
    assert "differs" in str(blocked.last_error)
    with pytest.raises(
        GovernedOutputConflict,
        match="blocked governed delivery cannot be changed",
    ):
        index.record_confirmed(_hex(1), confirmation_height=500)


def test_manifest_is_immutable_and_sgt_is_one_aggregate_output(tmp_path) -> None:
    index = GovernedOutputIndex(str(tmp_path / "immutable.db"))
    sgt = _coin(21, 31, amount=25)
    index.prepare(
        purchase_id=_hex(1),
        artifact_hash=_hex(2),
        rail="base_usdc",
        delivery_kind="sgt",
        quantity=25,
        input_coin_ids=(_hex(10),),
        protocol_bundle_id=_hex(3),
        outputs=(
            GovernedOutputExpectation(
                ordinal=0,
                coin_id="0x" + sgt.name().hex(),
                parent_coin_id="0x" + sgt.parent_coin_info.hex(),
                puzzle_hash="0x" + sgt.puzzle_hash.hex(),
                amount=25,
            ),
        ),
    )
    with pytest.raises(GovernedOutputConflict, match="another governed output"):
        index.prepare(
            purchase_id=_hex(1),
            artifact_hash=_hex(2),
            rail="base_usdc",
            delivery_kind="sgt",
            quantity=25,
            input_coin_ids=(_hex(10),),
            protocol_bundle_id=_hex(3),
            outputs=(
                GovernedOutputExpectation(
                    ordinal=0,
                    coin_id=_hex(99),
                    parent_coin_id="0x" + sgt.parent_coin_info.hex(),
                    puzzle_hash="0x" + sgt.puzzle_hash.hex(),
                    amount=25,
                ),
            ),
        )
