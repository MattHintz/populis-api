from __future__ import annotations

from populis_api.zkpassport_relay import _simulate_forwarded_inner_call


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
