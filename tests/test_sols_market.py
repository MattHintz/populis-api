from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_puzzles.pool_economics_v2 import PoolEconomicState

from solslot_api.public_artifact import PublicArtifactMissing
from solslot_api.sols_market import (
    POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
    _apply_pool_transition,
    _reader,
    _singleton_child,
    router,
)


class _Reader:
    def __init__(self, snapshot: dict | Exception) -> None:
        self._snapshot = snapshot

    async def snapshot(self) -> dict:
        if isinstance(self._snapshot, Exception):
            raise self._snapshot
        return self._snapshot


def _client(reader: _Reader) -> TestClient:
    api = FastAPI()
    api.include_router(router)
    api.dependency_overrides[_reader] = lambda: reader
    return TestClient(api)


def test_specific_deed_swap_moves_principal_into_reserve() -> None:
    previous = PoolEconomicState(
        total_nav_locked_mojos=1_000_000,
        deed_count=10,
        total_pool_token_supply=1_000_000,
        treasury_reserve_tokens=100_000,
    )
    params = [
        # Case 6 reads share_ppm from index 6 and collection NAV from index 7.
        *([0] * 6),
        100_000,
        1_000_000,
        *([0] * 16),
    ]

    status, current = _apply_pool_transition(
        previous,
        pool_status=1,
        fp_scale=1_000,
        spend_case=POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
        params=[_int_program(value) for value in params],
    )

    assert status == 1
    assert current.total_nav_locked_mojos == 900_000
    assert current.deed_count == 9
    assert current.total_pool_token_supply == 1_000_000
    assert current.treasury_reserve_tokens == 190_000


def _int_program(value: int):
    from chia.types.blockchain_format.program import Program

    return Program.to(value)


def test_singleton_continuation_ignores_other_created_coins() -> None:
    child = _singleton_child(
        [
            _coin_record(2, 3, 90_000),
            _coin_record(2, 4, 1),
            _coin_record(2, 5, 900),
        ],
        expected_amount=1,
    )

    assert child.amount == 1
    assert child.puzzle_hash == "0x" + "04" * 32


def test_singleton_continuation_fails_closed_on_ambiguity() -> None:
    with pytest.raises(ValueError, match="missing or ambiguous"):
        _singleton_child(
            [_coin_record(2, 4, 1), _coin_record(2, 5, 1)],
            expected_amount=1,
        )


def _coin_record(parent: int, puzzle: int, amount: int) -> dict:
    return {
        "coin": {
            "parent_coin_info": "0x" + f"{parent:02x}" * 32,
            "puzzle_hash": "0x" + f"{puzzle:02x}" * 32,
            "amount": amount,
        },
        "confirmed_block_index": 100,
        "spent_block_index": 0,
    }


def test_public_market_returns_only_reader_verified_inventory() -> None:
    payload = {
        "schemaVersion": 1,
        "network": "testnet11",
        "outcome": "READY",
        "title": "1 SmartDeed swap available",
        "body": "Chain verified.",
        "opportunities": [
            {
                "deedId": "EASTMORELAND-001",
                "totalSolsMojos": "101000",
                "chainVerified": True,
            }
        ],
        "verifiedOpportunityCount": 1,
        "rejectedCandidateCount": 2,
    }
    response = _client(_Reader(payload)).get("/sols/market")

    assert response.status_code == 200
    assert response.json() == payload


def test_missing_genesis_artifact_locks_market_without_inventory() -> None:
    response = _client(_Reader(PublicArtifactMissing("missing"))).get(
        "/sols/market"
    )

    assert response.status_code == 200
    assert response.json()["outcome"] == "LOCKED"
    assert response.json()["opportunities"] == []
    assert response.json()["verifiedOpportunityCount"] == 0
