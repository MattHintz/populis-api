"""Fail-closed checks for the isolated KoS MINT co-signer client."""
from __future__ import annotations

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32

from solslot_api.kos_mint_execute_signer import (
    KosMintExecuteSignerError,
    _request_payload,
    _verified_response_signature,
    request_hash,
)
from solslot_api.mint_chain_validation import CanonicalKosMintExecution


def _execution() -> tuple[CanonicalKosMintExecution, object]:
    private_key = AugSchemeMPL.key_gen(b"KoS signer response verification test v1")
    execution = CanonicalKosMintExecution(
        governance_coin_id=bytes32(b"g" * 32),
        proposal_hash=bytes32(b"p" * 32),
        cosigner_pubkey=bytes(private_key.get_g1()),
        visible_message=b"kos-visible-message-v1",
        signing_message=b"kos-full-agg-sig-me-message-v1",
    )
    return execution, private_key


def _response(
    execution: CanonicalKosMintExecution,
    private_key: object,
    expected_request_hash: str,
) -> dict[str, str]:
    signature = AugSchemeMPL.sign(private_key, execution.signing_message)
    return {
        "requestHash": expected_request_hash,
        "mintExecuteCosignerPubkey": "0x" + execution.cosigner_pubkey.hex(),
        "signature": "0x" + bytes(signature).hex(),
    }


def test_request_payload_and_audit_hash_bind_the_exact_execution() -> None:
    execution, _ = _execution()
    payload = _request_payload(
        execution=execution,
        artifact_hash="0x" + "ab" * 32,
        proposal_id="mp_20260720_001",
        network="testnet11",
    )

    assert payload == {
        "capability": "governance-mint-execute-v1",
        "network": "testnet11",
        "artifactHash": "0x" + "ab" * 32,
        "proposalId": "mp_20260720_001",
        "proposalHash": "0x" + "70" * 32,
        "governanceCoinId": "0x" + "67" * 32,
        "mintExecuteCosignerPubkey": "0x" + execution.cosigner_pubkey.hex(),
        "visibleMessage": "0x" + execution.visible_message.hex(),
        "signingMessage": "0x" + execution.signing_message.hex(),
    }
    assert request_hash(payload) == request_hash(dict(reversed(payload.items())))

    altered = dict(payload)
    altered["governanceCoinId"] = "0x" + "00" * 32
    assert request_hash(altered) != request_hash(payload)


def test_verified_response_accepts_only_the_artifact_bound_signature() -> None:
    execution, private_key = _execution()
    payload = _request_payload(
        execution=execution,
        artifact_hash="0x" + "cd" * 32,
        proposal_id="mp_20260720_002",
        network="testnet11",
    )
    expected_request_hash = request_hash(payload)
    response = _response(execution, private_key, expected_request_hash)

    signature = _verified_response_signature(
        body=response,
        execution=execution,
        expected_request_hash=expected_request_hash,
    )
    assert AugSchemeMPL.verify(
        private_key.get_g1(), execution.signing_message, signature
    )


@pytest.mark.parametrize("mutation", ["request_hash", "public_key", "signature"])
def test_verified_response_rejects_replayed_or_substituted_values(mutation: str) -> None:
    execution, private_key = _execution()
    expected_request_hash = "0x" + "ef" * 32
    response = _response(execution, private_key, expected_request_hash)
    if mutation == "request_hash":
        response["requestHash"] = "0x" + "00" * 32
    elif mutation == "public_key":
        other_key = AugSchemeMPL.key_gen(b"different KoS key used for rejection test v1")
        response["mintExecuteCosignerPubkey"] = "0x" + bytes(other_key.get_g1()).hex()
    else:
        other_key = AugSchemeMPL.key_gen(
            b"different KoS signature used for rejection test v1"
        )
        response["signature"] = "0x" + bytes(
            AugSchemeMPL.sign(other_key, execution.signing_message)
        ).hex()

    with pytest.raises(KosMintExecuteSignerError):
        _verified_response_signature(
            body=response,
            execution=execution,
            expected_request_hash=expected_request_hash,
        )
