from __future__ import annotations

import sqlite3

import pytest
from fastapi import HTTPException
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia_rs import AugSchemeMPL, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.config import Settings
from solslot_api.funded_redemption_store import FundedRedemptionStore
from solslot_api.funded_redemptions import (
    _funding_bundle_output,
    _require_funded_redemptions,
    _wusdc_amount,
)
from solslot_api.governance_queue import GovernanceQueueStore


def b32(value: int) -> bytes32:
    return bytes32(value.to_bytes(32, "big"))


def funding_bundle(
    *,
    asset_id: bytes32,
    recipient_inner_hash: bytes32,
    payment_amount: int,
    change_amount: int = 250,
) -> SpendBundle:
    wallet_inner = Program.to(1)
    wallet_cat_hash = construct_cat_puzzle(
        CAT_MOD, asset_id, wallet_inner
    ).get_tree_hash()
    parent_coin = Coin(
        b32(79),
        wallet_cat_hash,
        uint64(payment_amount + change_amount),
    )
    wallet_coin = Coin(
        parent_coin.name(),
        wallet_cat_hash,
        uint64(payment_amount + change_amount),
    )
    conditions: list[list[object]] = [
        [51, recipient_inner_hash, payment_amount],
    ]
    if change_amount:
        conditions.append([51, b32(81), change_amount])
    unsigned = unsigned_spend_bundle_for_spendable_cats(
        CAT_MOD,
        [
            SpendableCAT(
                wallet_coin,
                asset_id,
                wallet_inner,
                Program.to(conditions),
                lineage_proof=LineageProof(
                    parent_name=parent_coin.parent_coin_info,
                    inner_puzzle_hash=wallet_inner.get_tree_hash(),
                    amount=parent_coin.amount,
                ),
            )
        ],
    )
    key = AugSchemeMPL.key_gen(bytes([82]) * 32)
    return SpendBundle(
        list(unsigned.coin_spends),
        AugSchemeMPL.sign(key, b"funded-redemption-test"),
    )


def test_wusdc_amount_uses_exact_three_decimal_units() -> None:
    assert _wusdc_amount("1") == 1_000
    assert _wusdc_amount("1234.567") == 1_234_567
    for invalid in ("0", "-1", "1.0001", "nan", "inf", "1e2"):
        with pytest.raises(ValueError):
            _wusdc_amount(invalid)


def test_customer_redemption_gate_fails_closed() -> None:
    with pytest.raises(HTTPException) as disabled:
        _require_funded_redemptions(Settings(funded_redemptions_enabled=False))
    assert disabled.value.status_code == 503

    _require_funded_redemptions(Settings(funded_redemptions_enabled=True))


def test_funding_bundle_is_exact_trusted_cat_with_one_change() -> None:
    asset_id = b32(10)
    recipient_inner = b32(11)
    recipient_full = construct_cat_puzzle(
        CAT_MOD, asset_id, recipient_inner
    ).get_tree_hash_precalc(recipient_inner)
    bundle = funding_bundle(
        asset_id=asset_id,
        recipient_inner_hash=recipient_inner,
        payment_amount=125_000,
    )
    output = _funding_bundle_output(
        bundle,
        payment_asset_id=asset_id,
        treasury_puzzle_hash=bytes32(recipient_full),
        payment_amount=125_000,
    )
    assert output.puzzle_hash == recipient_full
    assert int(output.amount) == 125_000


def test_funding_bundle_rejects_wrong_cat_or_amount() -> None:
    asset_id = b32(20)
    recipient_inner = b32(21)
    recipient_full = construct_cat_puzzle(
        CAT_MOD, asset_id, recipient_inner
    ).get_tree_hash_precalc(recipient_inner)
    bundle = funding_bundle(
        asset_id=asset_id,
        recipient_inner_hash=recipient_inner,
        payment_amount=200_000,
    )
    with pytest.raises(ValueError, match="trusted wUSDC.b"):
        _funding_bundle_output(
            bundle,
            payment_asset_id=b32(22),
            treasury_puzzle_hash=bytes32(recipient_full),
            payment_amount=200_000,
        )
    with pytest.raises(ValueError, match="exact governed"):
        _funding_bundle_output(
            bundle,
            payment_asset_id=asset_id,
            treasury_puzzle_hash=bytes32(recipient_full),
            payment_amount=200_001,
        )


def test_redemption_operation_is_idempotent_and_immutable(tmp_path) -> None:
    store = FundedRedemptionStore(str(tmp_path / "admin.db"))
    values = {
        "operation_hash": "0x" + "11" * 32,
        "settlement_id": "0x" + "22" * 32,
        "deed_launcher_id": "0x" + "33" * 32,
        "vault_launcher_id": "0x" + "44" * 32,
        "payment_amount": "125000",
        "funding_coin_id": "0x" + "55" * 32,
        "expected_payment_coin_id": "0x" + "66" * 32,
        "transaction_id": "0x" + "77" * 32,
        "fee_mojos": "42",
        "fee_target_seconds": 120,
        "submission_provider": "primary",
        "mempool_observed_at": "2026-08-03T12:00:00Z",
    }
    first = store.record_submitted(**values)
    second = store.record_submitted(**values)
    assert first == second
    assert first.status == "SUBMITTED"

    with pytest.raises(ValueError, match="different evidence"):
        store.record_submitted(**{**values, "payment_amount": "125001"})

    confirmed = store.mark_confirmed(values["operation_hash"], 7_654_321)
    assert confirmed.status == "CONFIRMED"
    assert confirmed.confirmed_height == 7_654_321
    store.close()


def test_funding_submission_persists_exact_signed_bundle_atomically(tmp_path) -> None:
    store = FundedRedemptionStore(str(tmp_path / "admin.db"))
    unsigned = {"coin_spends": [], "aggregated_signature": "0x" + "c0" * 96}
    signed = {"coin_spends": [], "aggregated_signature": "0x" + "a1" * 96}
    values = {
        "proposal_id": "proposal-1",
        "operation_hash": "0x" + "11" * 32,
        "settlement_id": "0x" + "22" * 32,
        "payment_asset_id": "0x" + "33" * 32,
        "payment_amount": "125000",
        "recipient_inner_puzzle_hash": "0x" + "44" * 32,
        "expected_funding_coin_id": "0x" + "55" * 32,
        "unsigned_bundle": unsigned,
        "signed_bundle": signed,
        "input_coin_ids": ("0x" + "66" * 32, "0x" + "77" * 32),
        "created_by": "owner",
    }

    first = store.prepare_funding_submission(**values)
    second = store.prepare_funding_submission(**values)
    assert first == second
    assert first.status == "SUBMITTING"
    assert first.signed_bundle_json is not None
    assert first.input_coin_ids == values["input_coin_ids"]

    with pytest.raises(ValueError, match="different funding intent"):
        store.prepare_funding_submission(
            **{**values, "signed_bundle": {**signed, "aggregated_signature": "0x" + "b2" * 96}}
        )
    store.close()


def test_governance_queue_migrates_old_kind_constraint_with_indexes(tmp_path) -> None:
    path = tmp_path / "queue.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE governance_proposal_queue (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL CHECK (kind IN ('SGT_SALE','SGT_GRANT')),
            state TEXT NOT NULL CHECK (state IN ('DRAFT','READY','ACTIVE','EXECUTED','FAILED','CANCELED')),
            title TEXT NOT NULL,
            bill_json TEXT NOT NULL,
            bill_clvm_hex TEXT NOT NULL,
            proposal_hash TEXT NOT NULL UNIQUE,
            revision INTEGER NOT NULL,
            queue_position INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            activated_at INTEGER,
            completed_at INTEGER
        );
        CREATE UNIQUE INDEX idx_governance_one_active
            ON governance_proposal_queue(state) WHERE state='ACTIVE';
        CREATE INDEX idx_governance_queue_order
            ON governance_proposal_queue(state, queue_position, created_at);
        CREATE TABLE governance_queue_signatures (
            proposal_id TEXT NOT NULL,
            action_id TEXT NOT NULL,
            signer_slot INTEGER NOT NULL,
            signer_public_key TEXT NOT NULL,
            message_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            signed_by TEXT NOT NULL,
            signed_at INTEGER NOT NULL,
            PRIMARY KEY (proposal_id, action_id)
        );
        """
    )
    connection.execute(
        "INSERT INTO governance_proposal_queue VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "existing", "SGT_GRANT", "DRAFT", "Existing", "{}", "0x80",
            "0x" + "01" * 32, 1, 1, "owner", 1, 1, None, None,
        ),
    )
    connection.commit()
    connection.close()

    store = GovernanceQueueStore(str(path))
    assert store.get("existing") is not None
    created = store.create(
        kind="FUNDED_REDEMPTION",
        title="Fund collection",
        bill={"settlementId": "0x" + "02" * 32},
        bill_clvm_hex="0x80",
        proposal_hash="0x" + "03" * 32,
        actor="owner",
    )
    assert created.kind == "FUNDED_REDEMPTION"
    indexes = {
        row[1]
        for row in store._conn.execute("PRAGMA index_list(governance_proposal_queue)")
    }
    assert "idx_governance_one_active" in indexes
    assert "idx_governance_queue_order" in indexes
    store.close()
