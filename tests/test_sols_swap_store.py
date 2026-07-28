from __future__ import annotations

import pytest

from solslot_api.sols_swap_store import SolsSwapStore


def _hex(seed: int) -> str:
    return "0x" + f"{seed:02x}" * 32


def test_swap_store_is_idempotent_and_resumable() -> None:
    store = SolsSwapStore(":memory:")
    prepared = store.record_prepared(
        operation_hash=_hex(1),
        direction="SOLS_TO_DEED",
        vault_launcher_id=_hex(2),
        deed_launcher_id=_hex(3),
        quote_expires_at=1_900_000_000,
        pool_input_coin_id=_hex(4),
        expected_pool_output_coin_id=_hex(5),
    )
    duplicate = store.record_prepared(
        operation_hash=_hex(1),
        direction="SOLS_TO_DEED",
        vault_launcher_id=_hex(2),
        deed_launcher_id=_hex(3),
        quote_expires_at=1_900_000_000,
        pool_input_coin_id=_hex(4),
        expected_pool_output_coin_id=_hex(5),
    )

    assert prepared.status == "PREPARED"
    assert duplicate == prepared

    submitted = store.mark_submitted(
        _hex(1),
        transaction_id=_hex(6),
        fee_mojos="42",
        fee_target_seconds=300,
        submission_provider="primary",
        mempool_observed_at="2026-07-27T12:00:00+00:00",
    )
    repeated = store.mark_submitted(
        _hex(1),
        transaction_id=_hex(6),
        fee_mojos="42",
        fee_target_seconds=300,
        submission_provider="primary",
        mempool_observed_at="2026-07-27T12:00:00+00:00",
    )

    assert submitted.status == "SUBMITTED"
    assert repeated.transaction_id == _hex(6)
    assert store.list_for_vault(_hex(2)) == (repeated,)
    assert store.mark_confirmed(_hex(1)).status == "CONFIRMED"


def test_swap_store_rejects_operation_hash_rebinding() -> None:
    store = SolsSwapStore(":memory:")
    store.record_prepared(
        operation_hash=_hex(1),
        direction="SOLS_TO_DEED",
        vault_launcher_id=_hex(2),
        deed_launcher_id=_hex(3),
        quote_expires_at=1_900_000_000,
        pool_input_coin_id=_hex(4),
        expected_pool_output_coin_id=_hex(5),
    )

    with pytest.raises(ValueError, match="another swap"):
        store.record_prepared(
            operation_hash=_hex(1),
            direction="SOLS_TO_DEED",
            vault_launcher_id=_hex(2),
            deed_launcher_id=_hex(9),
            quote_expires_at=1_900_000_000,
            pool_input_coin_id=_hex(4),
            expected_pool_output_coin_id=_hex(5),
        )
