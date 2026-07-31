from __future__ import annotations

import pytest

from solslot_api.validator_ledger import (
    SCHEMA_VERSION,
    ValidatorLedger,
    ValidatorLedgerConflict,
)


def _record(ledger: ValidatorLedger, *, claim: str = "01", nullifier: str = "02") -> str:
    return ledger.record_or_recover(
        claim_hash="0x" + claim * 32,
        canonical_claim='{"claim":"' + claim + '"}',
        scoped_nullifier="0x" + nullifier * 32,
        bridge_coin_id="0x" + "03" * 32,
        vault_action="0xvault:0xcoin:0xroot:update_identity",
        evm_transaction_hash="0x" + "04" * 32,
        signature="0x" + "05" * 96,
    )


def test_exact_claim_retry_recovers_the_original_signature() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        first = _record(ledger)
        second = _record(ledger)
    finally:
        ledger.close()
    assert first == second


def test_reused_nullifier_bridge_event_or_vault_action_fails_closed() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        _record(ledger)
        with pytest.raises(ValidatorLedgerConflict, match="already signed"):
            _record(ledger, claim="06", nullifier="07")
    finally:
        ledger.close()


def test_validator_ledger_uses_wal_and_passes_integrity_check(tmp_path) -> None:
    ledger = ValidatorLedger(tmp_path / "signatures.db")
    try:
        assert ledger.healthcheck() is True
        journal_mode = ledger._conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        ledger.close()
    assert journal_mode.lower() == "wal"


def test_validator_ledger_migrates_current_signature_schema() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        version = ledger._conn.execute("PRAGMA user_version").fetchone()[0]
        table = ledger._conn.execute(
            "SELECT name FROM sqlite_master WHERE name = 'voucher_series_phase_signatures'"
        ).fetchone()
        reservation_table = ledger._conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE name = 'inventory_reservation_signatures'"
        ).fetchone()
        extension_table = ledger._conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE name = 'inventory_extension_signatures'"
        ).fetchone()
        release_table = ledger._conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE name = 'inventory_release_signatures'"
        ).fetchone()
        columns = {
            row[1]
            for row in ledger._conn.execute(
                "PRAGMA table_info(voucher_transition_signatures)"
            ).fetchall()
        }
        stripe_columns = {
            row[1]
            for row in ledger._conn.execute(
                "PRAGMA table_info(stripe_settlement_signatures)"
            ).fetchall()
        }
    finally:
        ledger.close()
    assert version == SCHEMA_VERSION == 11
    assert table is not None
    assert reservation_table is not None
    assert extension_table is not None
    assert release_table is not None
    assert "deed_coin_id" in columns
    assert "expected_deed_output_coin_id" in stripe_columns


def test_primary_purchase_retry_recovers_the_original_signature() -> None:
    ledger = ValidatorLedger(":memory:")
    kwargs = {
        "claim_hash": "0x" + "11" * 32,
        "canonical_claim": '{"purchase":"one"}',
        "purchase_id": "0x" + "12" * 32,
        "deed_coin_id": "0x" + "13" * 32,
        "signature": "0x" + "14" * 96,
    }
    try:
        first = ledger.record_primary_purchase_or_recover(**kwargs)
        second = ledger.record_primary_purchase_or_recover(**kwargs)
    finally:
        ledger.close()
    assert first == second


def test_validator_will_not_sign_one_deed_for_two_primary_purchases() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        ledger.record_primary_purchase_or_recover(
            claim_hash="0x" + "21" * 32,
            canonical_claim='{"purchase":"one"}',
            purchase_id="0x" + "22" * 32,
            deed_coin_id="0x" + "23" * 32,
            signature="0x" + "24" * 96,
        )
        with pytest.raises(ValidatorLedgerConflict, match="already authorized"):
            ledger.record_primary_purchase_or_recover(
                claim_hash="0x" + "25" * 32,
                canonical_claim='{"purchase":"two"}',
                purchase_id="0x" + "26" * 32,
                deed_coin_id="0x" + "23" * 32,
                signature="0x" + "27" * 96,
            )
    finally:
        ledger.close()


def _inventory_reservation_record(
    ledger: ValidatorLedger,
    *,
    claim: str = "61",
    purchase: str = "62",
    artifact: str = "63",
    available: str = "64",
    reserved: str = "65",
    expires_at: int = 2_000,
) -> str:
    return ledger.record_inventory_reservation_or_recover(
        claim_hash="0x" + claim * 32,
        canonical_claim='{"reservation":"' + claim + '"}',
        purchase_id="0x" + purchase * 32,
        artifact_hash="0x" + artifact * 32,
        available_coin_id="0x" + available * 32,
        reserved_coin_id="0x" + reserved * 32,
        reservation_expires_at=expires_at,
        signature="0x" + "66" * 96,
    )


def test_inventory_reservation_is_idempotent_and_exclusive(
    monkeypatch,
) -> None:
    monkeypatch.setattr("solslot_api.validator_ledger.time.time", lambda: 1_000)
    ledger = ValidatorLedger(":memory:")
    try:
        first = _inventory_reservation_record(ledger)
        assert _inventory_reservation_record(ledger) == first
        with pytest.raises(ValidatorLedgerConflict, match="live reservation"):
            _inventory_reservation_record(
                ledger,
                claim="67",
                purchase="68",
                artifact="69",
                available="64",
                reserved="6a",
            )
    finally:
        ledger.close()


def test_expired_off_chain_reservation_can_be_replaced(monkeypatch) -> None:
    now = 1_000
    monkeypatch.setattr(
        "solslot_api.validator_ledger.time.time",
        lambda: now,
    )
    ledger = ValidatorLedger(":memory:")
    try:
        _inventory_reservation_record(ledger, expires_at=1_001)
        now = 1_001
        replacement = _inventory_reservation_record(
            ledger,
            claim="67",
            purchase="68",
            artifact="69",
            available="64",
            reserved="6a",
            expires_at=2_000,
        )
    finally:
        ledger.close()
    assert replacement == "0x" + "66" * 96


def _voucher_transition_record(
    ledger: ValidatorLedger,
    *,
    claim: str = "31",
    payment_id: str = "32",
    series_coin: str = "33",
    voucher_coin: str = "34",
    payment_coin: str = "35",
    deed_coin: str | None = None,
) -> str:
    return ledger.record_voucher_transition_or_recover(
        claim_hash="0x" + claim * 32,
        canonical_claim='{"transition":"' + claim + '"}',
        global_payment_id="0x" + payment_id * 32,
        series_coin_id="0x" + series_coin * 32,
        voucher_coin_id="0x" + voucher_coin * 32,
        payment_coin_id="0x" + payment_coin * 32,
        deed_coin_id=("0x" + deed_coin * 32 if deed_coin else None),
        signature="0x" + "36" * 96,
    )


def test_voucher_transition_retry_recovers_original_signature() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        first = _voucher_transition_record(ledger)
        second = _voucher_transition_record(ledger)
    finally:
        ledger.close()
    assert first == second


def test_voucher_transition_rejects_reused_governed_deed() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        _voucher_transition_record(ledger, deed_coin="37")
        with pytest.raises(ValidatorLedgerConflict, match="already settled"):
            _voucher_transition_record(
                ledger,
                claim="38",
                payment_id="39",
                series_coin="3a",
                voucher_coin="3b",
                payment_coin="3c",
                deed_coin="37",
            )
    finally:
        ledger.close()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("payment_id", "41"),
        ("series_coin", "42"),
        ("voucher_coin", "43"),
        ("payment_coin", "44"),
    ],
)
def test_voucher_transition_rejects_reused_terminal_evidence(
    field: str,
    replacement: str,
) -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        _voucher_transition_record(ledger)
        kwargs = {
            "claim": "45",
            "payment_id": "32",
            "series_coin": "33",
            "voucher_coin": "34",
            "payment_coin": "35",
            field: replacement,
        }
        with pytest.raises(ValidatorLedgerConflict, match="already settled"):
            _voucher_transition_record(ledger, **kwargs)
    finally:
        ledger.close()


def test_series_phase_retry_recovers_and_reused_coin_fails_closed() -> None:
    ledger = ValidatorLedger(":memory:")
    kwargs = {
        "claim_hash": "0x" + "51" * 32,
        "canonical_claim": '{"phase":"launch"}',
        "series_coin_id": "0x" + "52" * 32,
        "transition": 2,
        "signature": "0x" + "53" * 96,
    }
    try:
        first = ledger.record_voucher_series_phase_or_recover(**kwargs)
        second = ledger.record_voucher_series_phase_or_recover(**kwargs)
        assert first == second
        with pytest.raises(ValidatorLedgerConflict, match="already authorized"):
            ledger.record_voucher_series_phase_or_recover(
                **{
                    **kwargs,
                    "claim_hash": "0x" + "54" * 32,
                    "canonical_claim": '{"phase":"cancel"}',
                    "transition": 3,
                }
            )
    finally:
        ledger.close()
