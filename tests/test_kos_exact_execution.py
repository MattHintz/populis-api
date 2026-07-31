from __future__ import annotations

from chia_rs.sized_bytes import bytes32

from solslot_api.kos_exact_execution import (
    ExactExecutionAction,
    exact_execution_digest,
)


def _b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def test_exact_execution_digest_matches_key_of_solomon_vector() -> None:
    digest = exact_execution_digest(
        operation_reference="0xrc24",
        action=ExactExecutionAction.DELIVER,
        purchase_id=_b32(1),
        artifact_hash=_b32(2),
        claim_hash=_b32(3),
        spend_bundle_id=_b32(4),
        required_input_coin_ids=(_b32(5), _b32(6)),
        expected_output_coin_id=_b32(7),
        expected_output_puzzle_hash=_b32(8),
        fee_mojos=123,
    )
    assert (
        digest.hex()
        == "b603a50cf9a5b61332029344bd25f6e4441ed0935f374dd110a22e44ed8876b9"
    )
