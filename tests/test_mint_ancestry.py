from __future__ import annotations

import pytest
from fastapi import HTTPException

from solslot_api.mint_endpoints import _require_coin_ancestry


def _record(parent: str) -> dict:
    return {"coin": {"parent_coin_info": parent}}


class FakeCoinset:
    def __init__(self, records: dict[str, dict]) -> None:
        self.records = records
        self.requests: list[str] = []

    async def get_coin_record_by_name(self, coin_id: str):
        self.requests.append(coin_id)
        return self.records.get(coin_id)


@pytest.mark.asyncio
async def test_property_registry_lineage_accepts_launcher_child_and_descendant() -> None:
    launcher = "0x" + "11" * 32
    first = "0x" + "22" * 32
    coinset = FakeCoinset({first: _record(launcher)})

    await _require_coin_ancestry(
        coinset,
        record=_record(launcher),
        ancestor_coin_id=launcher,
    )
    assert coinset.requests == []

    await _require_coin_ancestry(
        coinset,
        record=_record(first),
        ancestor_coin_id=launcher,
    )
    assert coinset.requests == [first]


@pytest.mark.asyncio
async def test_property_registry_lineage_rejects_missing_or_cyclic_parent() -> None:
    launcher = "0x" + "11" * 32
    first = "0x" + "22" * 32
    coinset = FakeCoinset({first: _record(first)})

    with pytest.raises(HTTPException, match="does not descend") as cycle:
        await _require_coin_ancestry(
            coinset,
            record=_record(first),
            ancestor_coin_id=launcher,
        )
    assert cycle.value.status_code == 409

    with pytest.raises(HTTPException, match="lineage is incomplete") as missing:
        await _require_coin_ancestry(
            FakeCoinset({}),
            record=_record(first),
            ancestor_coin_id=launcher,
        )
    assert missing.value.status_code == 409
