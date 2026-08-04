from __future__ import annotations

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_api.kos_exact_execution import (
    ExactExecutionAction,
    ExactExecutionOutput,
    exact_execution_digest,
)


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _i32(value: int) -> bytes32:
    return bytes32(value.to_bytes(32, "big"))


def test_exact_execution_digest_matches_key_of_solomon_v2_vector() -> None:
    digest = exact_execution_digest(
        operation_reference="0xrc24",
        action=ExactExecutionAction.DELIVER,
        purchase_id=_b32(1),
        artifact_hash=_b32(2),
        claim_hash=_b32(3),
        spend_bundle_id=_b32(4),
        required_input_coin_ids=(_b32(5), _b32(6)),
        expected_outputs=(
            ExactExecutionOutput(_b32(7), _b32(8), 25),
            ExactExecutionOutput(_b32(9), _b32(10), 1),
        ),
        fee_mojos=123,
    )
    assert (
        digest.hex()
        == "c51aecb306ae7449de45f6ac2d1742b9fbd065ec8e65916c2774aa45abfe13bf"
    )


def test_voucher_terminal_digest_matches_key_of_solomon_v2_vector() -> None:
    digest = exact_execution_digest(
        operation_reference="0x" + bytes(_b32(1)).hex(),
        action=ExactExecutionAction.VOUCHER_TERMINAL,
        purchase_id=_b32(1),
        artifact_hash=_b32(2),
        claim_hash=_b32(3),
        spend_bundle_id=_b32(4),
        required_input_coin_ids=(_b32(5), _b32(6)),
        expected_outputs=(
            ExactExecutionOutput(_b32(7), _b32(8), 25),
            ExactExecutionOutput(_b32(9), _b32(10), 1),
        ),
        fee_mojos=123,
    )
    assert (
        digest.hex()
        == "9449aadfb93483c62b1503456f2bac327fd75720261cefa23d19f12636fb4fb9"
    )


def test_exact_execution_digest_binds_quantity_and_canonical_order() -> None:
    common = {
        "operation_reference": "purchase-quantity",
        "action": ExactExecutionAction.DELIVER,
        "purchase_id": _b32(1),
        "artifact_hash": _b32(2),
        "claim_hash": _b32(3),
        "spend_bundle_id": _b32(4),
        "required_input_coin_ids": (_b32(5),),
        "fee_mojos": 7,
    }
    one = exact_execution_digest(
        **common,
        expected_outputs=(ExactExecutionOutput(_b32(7), _b32(8), 1),),
    )
    many = exact_execution_digest(
        **common,
        expected_outputs=(ExactExecutionOutput(_b32(7), _b32(8), 30_000),),
    )
    assert one != many
    with pytest.raises(ValueError, match="canonical"):
        exact_execution_digest(
            **common,
            expected_outputs=(
                ExactExecutionOutput(_b32(9), _b32(10), 1),
                ExactExecutionOutput(_b32(7), _b32(8), 1),
            ),
        )


def test_exact_execution_accepts_full_hundred_deed_delivery_shape() -> None:
    common = {
        "operation_reference": "purchase-100-deeds",
        "action": ExactExecutionAction.DELIVER,
        "purchase_id": _b32(1),
        "artifact_hash": _b32(2),
        "claim_hash": _b32(3),
        "spend_bundle_id": _b32(4),
        "fee_mojos": 7,
    }
    inputs = tuple(_i32(value) for value in range(1, 103))
    outputs = tuple(
        ExactExecutionOutput(_i32(value), _i32(value + 1_000), 1)
        for value in range(201, 401)
    )
    assert len(exact_execution_digest(
        **common,
        required_input_coin_ids=inputs,
        expected_outputs=outputs,
    )) == 32

    with pytest.raises(ValueError, match="1..102"):
        exact_execution_digest(
            **common,
            required_input_coin_ids=(*inputs, _i32(103)),
            expected_outputs=outputs,
        )
    with pytest.raises(ValueError, match="1..200"):
        exact_execution_digest(
            **common,
            required_input_coin_ids=inputs,
            expected_outputs=(
                *outputs,
                ExactExecutionOutput(_i32(401), _i32(1_401), 1),
            ),
        )
