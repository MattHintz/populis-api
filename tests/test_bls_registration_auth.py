from __future__ import annotations

from chia_rs import AugSchemeMPL

from solslot_api.evm_auth import (
    registration_bls_message,
    registration_bls_signing_digest,
)


NONCE = "0x" + "11" * 32
POOL = "0x" + "22" * 32


def test_bls_registration_is_a_chip0002_signature_over_v2_binding() -> None:
    secret_key = AugSchemeMPL.key_gen(bytes.fromhex("33" * 32))
    message = registration_bls_message(NONCE, POOL, "chia_bls", "testnet11")
    digest = registration_bls_signing_digest(NONCE, POOL, "chia_bls", "testnet11")
    signature = AugSchemeMPL.sign(secret_key, digest)

    assert len(message) == 32
    assert AugSchemeMPL.verify(secret_key.get_g1(), digest, signature)
    assert not AugSchemeMPL.verify(
        secret_key.get_g1(),
        bytes.fromhex(NONCE.removeprefix("0x")),
        signature,
    )


def test_bls_registration_cannot_replay_across_pool_or_network() -> None:
    expected = registration_bls_signing_digest(NONCE, POOL, "chia_bls", "testnet11")

    assert expected != registration_bls_signing_digest(
        NONCE,
        "0x" + "44" * 32,
        "chia_bls",
        "testnet11",
    )
    assert expected != registration_bls_signing_digest(
        NONCE,
        POOL,
        "chia_bls",
        "mainnet",
    )
