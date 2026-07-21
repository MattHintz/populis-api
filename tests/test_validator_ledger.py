from __future__ import annotations

import pytest

from solslot_api.validator_ledger import ValidatorLedger, ValidatorLedgerConflict


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
