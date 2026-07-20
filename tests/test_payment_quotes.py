from __future__ import annotations

import json
import time

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32

from solslot_api.config import Settings
from solslot_api.payment_quotes import (
    PaymentQuoteError,
    SNAPSHOT_SCHEMA,
    load_authorized_oracle_round,
)
from solslot_puzzles.payment_artifacts_v2 import (
    OracleObservationV1,
    build_oracle_round,
    oracle_operator_set_root,
    oracle_round_signature_message,
    oracle_round_to_json,
)


def _snapshot(now: int):
    keys = tuple(
        AugSchemeMPL.key_gen(bytes([seed]) * 32)
        for seed in (71, 72, 73)
    )
    pubkeys = tuple(bytes(key.get_g1()) for key in keys)
    observations = tuple(
        OracleObservationV1(
            source_id=bytes32(bytes([index]) * 32),
            asset_id=bytes32.zeros,
            asset_decimals=12,
            price_usd_minor_per_asset=price,
            observed_at=now - (10 - index),
            valid_until=now + 300 + index,
            evidence_hash=bytes32(bytes([index + 10]) * 32),
        )
        for index, price in enumerate((2100, 2125, 2150), start=1)
    )
    round_ = build_oracle_round(
        network="testnet11",
        sequence=101,
        asset_id=bytes32.zeros,
        asset_decimals=12,
        operator_set_root=oracle_operator_set_root(pubkeys),
        observations=observations,
    )
    message = oracle_round_signature_message(round_.round_hash)
    signatures = [
        {
            "signerIndex": index,
            "signature": "0x"
            + bytes(AugSchemeMPL.sign(keys[index], message)).hex(),
        }
        for index in (0, 1)
    ]
    return keys, round_, {
        "schema": SNAPSHOT_SCHEMA,
        "generatedAt": now,
        "rounds": [{"round": oracle_round_to_json(round_), "signatures": signatures}],
    }


def test_loads_latest_quorum_authorized_h_system_round(tmp_path) -> None:
    now = int(time.time())
    keys, round_, snapshot = _snapshot(now)
    path = tmp_path / "payment-oracle.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    settings = Settings(
        _env_file=None,
        payment_oracle_rounds_path=str(path),
        payment_oracle_operator_pubkeys=[
            "0x" + bytes(key.get_g1()).hex() for key in keys
        ],
    )

    authorized = load_authorized_oracle_round(
        settings,
        asset_id=bytes32.zeros,
        now=now,
    )
    assert authorized.round == round_
    assert [value["signerIndex"] for value in authorized.signatures] == [0, 1]


def test_rejects_one_signer_and_tampered_round(tmp_path) -> None:
    now = int(time.time())
    keys, _round, snapshot = _snapshot(now)
    snapshot["rounds"][0]["signatures"].pop()
    path = tmp_path / "payment-oracle.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    settings = Settings(
        _env_file=None,
        payment_oracle_rounds_path=str(path),
        payment_oracle_operator_pubkeys=[
            "0x" + bytes(key.get_g1()).hex() for key in keys
        ],
    )
    with pytest.raises(PaymentQuoteError, match="two independent"):
        load_authorized_oracle_round(
            settings,
            asset_id=bytes32.zeros,
            now=now,
        )

    _keys, _round, snapshot = _snapshot(now)
    snapshot["rounds"][0]["round"]["priceUsdMinorPerAsset"] += 1
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(PaymentQuoteError, match="round is invalid"):
        load_authorized_oracle_round(
            settings,
            asset_id=bytes32.zeros,
            now=now,
        )
