from types import SimpleNamespace

import pytest

from solslot_api.sols_journey import _vault_sgt_balance


class _Provider:
    def __init__(self) -> None:
        self.requested_puzzle_hash = None
        self.include_spent = None

    async def get_coin_records_by_puzzle_hash(
        self,
        puzzle_hash: str,
        *,
        include_spent: bool,
    ):
        self.requested_puzzle_hash = puzzle_hash
        self.include_spent = include_spent
        return [
            {
                "coin": {"amount": 125},
                "confirmed_block_index": 10,
                "spent_block_index": 0,
                "spent": False,
            },
            {
                "coin": {"amount": 75},
                "confirmed_block_index": 11,
                "spent_block_index": 0,
                "spent": False,
            },
            {
                "coin": {"amount": 999},
                "confirmed_block_index": 8,
                "spent_block_index": 12,
                "spent": True,
            },
        ]


@pytest.mark.asyncio
async def test_vault_sgt_balance_uses_canonical_vault_bound_cat_puzzle():
    provider = _Provider()
    artifact = {
        "genesisPlan": {
            "launcherIds": {"governance": "0x" + "11" * 32},
            "permanentRules": {"sgtTailHash": "0x" + "22" * 32},
        }
    }

    balance = await _vault_sgt_balance(
        SimpleNamespace(provider=provider),
        artifact,
        "0x" + "33" * 32,
    )

    assert balance == 200
    assert provider.include_spent is False
    assert provider.requested_puzzle_hash.startswith("0x")
    assert len(provider.requested_puzzle_hash) == 66
