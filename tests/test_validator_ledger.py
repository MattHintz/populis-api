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
