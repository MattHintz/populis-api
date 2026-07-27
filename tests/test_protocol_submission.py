from __future__ import annotations

from typing import Any

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.faucet import Faucet
from solslot_api.config import Settings, validate_server_hardening_at_startup
from solslot_api.protocol_submission import (
    ProtocolBundleSubmitter,
    ProtocolFeePolicy,
    ProtocolSubmissionError,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def coin_record(coin: Coin) -> dict[str, Any]:
    return {
        "coin": {
            "parent_coin_info": "0x" + coin.parent_coin_info.hex(),
            "puzzle_hash": "0x" + coin.puzzle_hash.hex(),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": 10,
        "spent_block_index": 0,
    }


def protocol_bundle() -> SpendBundle:
    coin = Coin(b32(1), b32(2), uint64(10))
    output = b32(3)
    puzzle = Program.to((1, [[51, output, 10]]))
    return SpendBundle(
        [make_spend(coin, puzzle, Program.to(0))],
        G2Element(),
    )


class FakeProvider:
    def __init__(
        self,
        *,
        fee_coin: Coin,
        base_fee: int = 4,
        aggregate_fee: int = 7,
        pending: bool = False,
    ) -> None:
        self.fee_coin = fee_coin
        self.base_fee = base_fee
        self.aggregate_fee = aggregate_fee
        self.pending = pending
        self.estimates: list[dict[str, Any]] = []
        self.submitted: dict[str, Any] | None = None

    async def get_fee_estimate(
        self,
        *,
        target_times: list[int],
        spend_bundle: dict[str, Any],
        require_primary: bool,
    ) -> dict[str, Any]:
        self.estimates.append(spend_bundle)
        count = len(spend_bundle["coin_spends"])
        estimate = self.base_fee if count == 1 else self.aggregate_fee
        return {"target_times": target_times, "estimates": [estimate]}

    async def get_coin_records_by_puzzle_hash(
        self, puzzle_hash: str, *, include_spent: bool
    ) -> list[dict[str, Any]]:
        return [coin_record(self.fee_coin)]

    async def get_mempool_items_by_coin_name(
        self, coin_id: str
    ) -> list[dict[str, Any]]:
        return [{"name": "pending"}] if self.pending else []

    async def push_tx_confirmed_in_primary_mempool(
        self,
        spend_bundle_json: dict[str, Any],
        *,
        required_coin_id: str,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> dict[str, Any]:
        self.submitted = spend_bundle_json
        return {
            "provider": "local-full-node",
            "observed_at": "2026-07-27T12:00:00+00:00",
            "ambiguous_push": False,
        }


def submitter(
    provider: FakeProvider,
    faucet: Faucet,
    **updates: Any,
) -> ProtocolBundleSubmitter:
    values = {
        "enabled": True,
        "target_seconds": 300,
        "minimum_mojos": 1,
        "maximum_mojos": 100,
        "maximum_funding_coin_mojos": 1000,
        "mempool_timeout_seconds": 2,
        "mempool_poll_seconds": 0.1,
    }
    values.update(updates)
    return ProtocolBundleSubmitter(
        provider=provider,  # type: ignore[arg-type]
        faucet=faucet,
        policy=ProtocolFeePolicy(**values),
    )


@pytest.mark.asyncio
async def test_medium_fee_is_added_from_till_without_changing_protocol_outputs() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(4), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    original = protocol_bundle()

    receipt = await submitter(provider, faucet).submit(original.to_json_dict())

    assert receipt["status"] == "MEMPOOL"
    assert receipt["feeMojos"] == "7"
    assert receipt["feeTargetSeconds"] == 300
    assert receipt["submissionProvider"] == "local-full-node"
    assert provider.submitted is not None
    final = SpendBundle.from_json_dict(provider.submitted)
    assert len(final.coin_spends) == 2
    assert sum(int(coin.amount) for coin in final.removals()) - sum(
        int(coin.amount) for coin in final.additions()
    ) == 7
    assert compute_additions(final.coin_spends[0]) == compute_additions(
        original.coin_spends[0]
    )
    fee_additions = compute_additions(final.coin_spends[1])
    assert len(fee_additions) == 1
    assert fee_additions[0].puzzle_hash == faucet.address_puzzle_hash
    assert int(fee_additions[0].amount) == 93


@pytest.mark.asyncio
async def test_fee_above_cap_fails_before_submission() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    provider = FakeProvider(
        fee_coin=Coin(b32(5), faucet.address_puzzle_hash, uint64(100)),
        base_fee=101,
        aggregate_fee=101,
    )

    with pytest.raises(ProtocolSubmissionError, match="exceeds configured cap"):
        await submitter(provider, faucet).submit(protocol_bundle().to_json_dict())

    assert provider.submitted is None


@pytest.mark.asyncio
async def test_pending_or_insufficient_till_coin_fails_closed() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    pending = FakeProvider(
        fee_coin=Coin(b32(6), faucet.address_puzzle_hash, uint64(100)),
        pending=True,
    )
    with pytest.raises(ProtocolSubmissionError, match="no eligible"):
        await submitter(pending, faucet).submit(protocol_bundle().to_json_dict())

    small = FakeProvider(
        fee_coin=Coin(b32(7), faucet.address_puzzle_hash, uint64(3)),
        base_fee=4,
    )
    with pytest.raises(ProtocolSubmissionError, match="no eligible"):
        await submitter(small, faucet).submit(protocol_bundle().to_json_dict())


@pytest.mark.asyncio
async def test_fee_coin_cannot_duplicate_a_protocol_input() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    shared_coin = Coin(b32(70), faucet.address_puzzle_hash, uint64(100))
    protocol_spend = SpendBundle(
        [
            make_spend(
                shared_coin,
                Program.to((1, [[51, b32(71), 100]])),
                Program.to(0),
            )
        ],
        G2Element(),
    )
    provider = FakeProvider(fee_coin=shared_coin)

    with pytest.raises(ProtocolSubmissionError, match="no eligible"):
        await submitter(provider, faucet).submit(protocol_spend.to_json_dict())

    assert provider.submitted is None


@pytest.mark.asyncio
async def test_protocol_fee_funding_is_fail_closed_by_default() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    provider = FakeProvider(
        fee_coin=Coin(b32(8), faucet.address_puzzle_hash, uint64(100))
    )
    service = ProtocolBundleSubmitter(
        provider=provider,  # type: ignore[arg-type]
        faucet=faucet,
        policy=ProtocolFeePolicy(),
    )

    with pytest.raises(ProtocolSubmissionError, match="disabled"):
        await service.submit(protocol_bundle().to_json_dict())


@pytest.mark.asyncio
async def test_existing_user_fee_is_rejected_instead_of_double_charged() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    provider = FakeProvider(
        fee_coin=Coin(b32(9), faucet.address_puzzle_hash, uint64(100))
    )
    base_coin = Coin(b32(10), b32(11), uint64(10))
    fee_bearing = SpendBundle(
        [
            make_spend(
                base_coin,
                Program.to((1, [[51, b32(12), 9], [52, 1]])),
                Program.to(0),
            )
        ],
        G2Element(),
    )

    with pytest.raises(ProtocolSubmissionError, match="user-funded fee"):
        await submitter(provider, faucet).submit(fee_bearing.to_json_dict())

    assert provider.submitted is None


def test_fee_till_configuration_requires_local_node_and_existing_key() -> None:
    with pytest.raises(RuntimeError, match="SOLSLOT_CHIA_PRIMARY_URL"):
        validate_server_hardening_at_startup(
            Settings(protocol_fee_funding_enabled=True)
        )

    with pytest.raises(RuntimeError, match="SOLSLOT_FAUCET"):
        validate_server_hardening_at_startup(
            Settings(
                protocol_fee_funding_enabled=True,
                chia_primary_url="https://127.0.0.1:18555",
            )
        )

    validate_server_hardening_at_startup(
        Settings(
            runtime_environment="test",
            protocol_fee_funding_enabled=True,
            chia_primary_url="https://127.0.0.1:18555",
            faucet_seed_hex="01" * 32,
        )
    )
