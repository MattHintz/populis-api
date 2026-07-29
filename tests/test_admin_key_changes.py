from __future__ import annotations

import json
from pathlib import Path

from chia_rs import AugSchemeMPL

from solslot_api.admin_key_changes import (
    AdminKeyChangeIntentV1,
    hash_admin_key_change_intent,
    prepare_key_change_calldata,
    recovery_intent_bls_digest,
    verify_lost_recovery_bls_signature,
)


FIXTURE = (
    Path(__file__).parent / "fixtures" / "admin_key_change_intent_v1.json"
)


def test_python_matches_authority_v3_solidity_intent_fixture() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    intent = AdminKeyChangeIntentV1.model_validate(fixture["intent"])
    expected = fixture["expected"]
    intent_hash = hash_admin_key_change_intent(intent)
    calldata = prepare_key_change_calldata(intent)

    assert intent_hash == expected["intentHash"]
    assert calldata[:10] == expected["prepareRoutineSelector"]
    assert (len(calldata) - 2) // 2 == expected["prepareRoutineCalldataBytes"]
    assert (
        "0x" + recovery_intent_bls_digest(intent_hash).hex()
        == expected["recoveryBlsDigest"]
    )


def test_lost_key_bls_proof_is_bound_to_the_exact_intent() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw = dict(fixture["intent"])
    raw["kind"] = "LOST"
    intent = AdminKeyChangeIntentV1.model_validate(raw)
    secret_key = AugSchemeMPL.key_gen(b"authority v3 recovery proof seed")
    digest = recovery_intent_bls_digest(
        hash_admin_key_change_intent(intent)
    )
    signature = AugSchemeMPL.sign(secret_key, digest)

    verify_lost_recovery_bls_signature(
        intent=intent,
        recovery_bls_pubkey="0x" + bytes(secret_key.get_g1()).hex(),
        signature="0x" + bytes(signature).hex(),
    )

    altered = intent.model_copy(update={"nonce": intent.nonce + 1})
    try:
        verify_lost_recovery_bls_signature(
            intent=altered,
            recovery_bls_pubkey="0x" + bytes(secret_key.get_g1()).hex(),
            signature="0x" + bytes(signature).hex(),
        )
    except ValueError as exc:
        assert "invalid" in str(exc)
    else:
        raise AssertionError("altered recovery intent accepted the old signature")
