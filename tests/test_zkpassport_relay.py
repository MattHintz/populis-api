from __future__ import annotations

import pytest
from eth_abi import encode as abi_encode
from web3 import Web3

from solslot_api.zkpassport_relay import (
    _decode_enrollment_calldata,
    _simulate_forwarded_inner_call,
)


FORWARDER = "0x" + "11" * 20
EMITTER = "0x" + "22" * 20
SIGNER = "0x" + "33" * 20


class _RevertingEth:
    def __init__(self) -> None:
        self.transaction = None

    def call(self, transaction):
        self.transaction = transaction
        raise RuntimeError("execution reverted: 0xa54999ed")


class _FakeWeb3:
    def __init__(self) -> None:
        self.eth = _RevertingEth()


def test_forwarded_inner_simulation_appends_original_signer_and_decodes_revert():
    w3 = _FakeWeb3()

    detail = _simulate_forwarded_inner_call(
        w3,
        forwarder_address=FORWARDER,
        emitter_address=EMITTER,
        signer_address=SIGNER,
        data=b"\x12\x34",
    )

    assert "ScopeMismatch" in detail
    assert w3.eth.transaction == {
        "from": FORWARDER,
        "to": EMITTER,
        "value": 0,
        "data": b"\x12\x34" + bytes.fromhex("33" * 20),
    }


def _calldata(binding_type: str, binding: tuple, proof: bytes = b"proof") -> bytes:
    signature = f"verifyAndEmit({binding_type},bytes)"
    return bytes(Web3.keccak(text=signature)[:4]) + abi_encode(
        [binding_type, "bytes"],
        [binding, proof],
    )


def test_decodes_only_canonical_v2_enrollment_binding():
    data = _calldata(
        "(bytes32,bytes32,uint64)",
        (bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), 1),
    )

    assert _decode_enrollment_calldata(data) == (
        "0x" + "11" * 32,
        "0x" + "22" * 32,
        1,
    )


def test_rejects_retired_caller_supplied_attestation_tuple():
    retired_type = (
        "(bytes32,bytes32,uint16,bytes32,bytes32,uint64,bytes32,bytes32,"
        "bytes32,uint64,bytes32,bytes32)"
    )
    data = _calldata(
        retired_type,
        (
            bytes.fromhex("11" * 32),
            bytes.fromhex("12" * 32),
            1,
            bytes.fromhex("13" * 32),
            bytes.fromhex("14" * 32),
            1_900_000_000,
            bytes.fromhex("15" * 32),
            bytes.fromhex("16" * 32),
            bytes.fromhex("22" * 32),
            1,
            bytes.fromhex("17" * 32),
            bytes.fromhex("18" * 32),
        ),
    )

    with pytest.raises(ValueError, match="selector"):
        _decode_enrollment_calldata(data)


@pytest.mark.parametrize(
    ("binding", "message"),
    [
        ((bytes(32), bytes.fromhex("22" * 32), 1), "vaultLauncherId"),
        ((bytes.fromhex("11" * 32), bytes(32), 1), "bridgeParentId"),
        ((bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), 0), "bridgeAmount"),
    ],
)
def test_rejects_empty_enrollment_binding_fields(binding, message):
    data = _calldata("(bytes32,bytes32,uint64)", binding)

    with pytest.raises(ValueError, match=message):
        _decode_enrollment_calldata(data)
