from __future__ import annotations

import json

import pytest
from chia.types.blockchain_format.coin import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api import app as app_module
from solslot_api.admin import _build_single_coin_create_bundle
from solslot_api.config import Settings
from solslot_api.faucet import Faucet, FaucetSelectionRestricted
from solslot_api.faucet_worker import FaucetConsolidationWorker


class PendingGenesisStore:
    def pending_exact_fee_coin_ids(self) -> set[str]:
        return {"0x" + "ab" * 32}


def test_restart_with_pending_genesis_keeps_faucet_exclusive_when_flags_are_off(
    tmp_path,
    monkeypatch,
) -> None:
    database_path = tmp_path / "existing-genesis.db"
    database_path.touch()
    settings = Settings(
        genesis_db_path=str(database_path),
        ceremony_mode_enabled=False,
        protocol_fee_funding_enabled=False,
    )
    store = PendingGenesisStore()
    monkeypatch.setattr(app_module, "get_genesis_store", lambda _settings: store)

    loaded = app_module._load_genesis_store_for_runtime(settings)
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    pending = app_module._enforce_genesis_faucet_isolation(
        settings=settings,
        faucet=faucet,
        genesis_store=loaded,
    )

    assert loaded is store
    assert pending == {"0x" + "ab" * 32}
    with pytest.raises(FaucetSelectionRestricted, match="reserved for genesis"):
        faucet.select_coin([], 1)
    assert faucet.select_coin([], 1, purpose="genesis") is None


@pytest.mark.asyncio
async def test_faucet_selection_restriction_maps_to_clean_503() -> None:
    response = await app_module.faucet_selection_restricted_handler(
        None,  # type: ignore[arg-type]
        FaucetSelectionRestricted("reserved"),
    )

    assert response.status_code == 503
    assert json.loads(response.body) == {
        "detail": (
            "Faucet coin selection is temporarily reserved while the "
            "genesis transaction is reconciled."
        )
    }


@pytest.mark.asyncio
async def test_consolidation_cannot_bypass_genesis_exclusivity() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    faucet.restrict_coin_selection_to("genesis")

    class ForbiddenCoinset:
        async def get_coin_records_by_puzzle_hash(self, *_args, **_kwargs):
            pytest.fail("restricted consolidation must not fetch or spend coins")

    worker = FaucetConsolidationWorker(
        faucet=faucet,
        coinset=ForbiddenCoinset(),  # type: ignore[arg-type]
    )

    with pytest.raises(FaucetSelectionRestricted, match="reserved for genesis"):
        await worker.maybe_consolidate()


def test_bridge_top_up_signer_cannot_bypass_genesis_exclusivity() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    faucet.restrict_coin_selection_to("genesis")
    source = Coin(
        bytes32(bytes.fromhex("11" * 32)),
        faucet.address_puzzle_hash,
        uint64(10),
    )

    with pytest.raises(FaucetSelectionRestricted, match="reserved for genesis"):
        _build_single_coin_create_bundle(
            faucet=faucet,
            source_coin=source,
            outputs=[(faucet.address_puzzle_hash, 1)],
            change_puzzle_hash=faucet.address_puzzle_hash,
            fee=0,
        )
