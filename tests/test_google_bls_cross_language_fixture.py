"""Cross-check the Google Vault TypeScript BLS vectors with chia_rs."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path

from chia.types.blockchain_format.program import Program
from chia_rs import AugSchemeMPL, G1Element, G2Element


FIXTURE = Path(__file__).parent / "fixtures" / "google-bls-testnet11-v1.json"


def test_google_vault_bls_fixture_matches_python_chia_primitives() -> None:
    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert vector["schema"] == "solslot-google-vault-bls-v1"
    assert vector["network"] == "testnet11"
    assert vector["derivation"] == {
        "scheme": "chia-all-unhardened",
        "path": [12381, 8444, 2, 0],
        "syntheticKeyVersion": 1,
    }

    seed = hashlib.pbkdf2_hmac(
        "sha512",
        unicodedata.normalize("NFKD", vector["mnemonic"]).encode("utf-8"),
        b"mnemonic",
        2048,
        dklen=64,
    )
    secret_key = AugSchemeMPL.key_gen(seed)
    for segment in vector["derivation"]["path"]:
        secret_key = secret_key.derive_unhardened(segment)
    assert bytes(secret_key.public_key()).hex() == vector["registration"]["publicKey"]

    message = bytes.fromhex(vector["registration"]["message"])
    digest = bytes(Program.to(("Chia Signed Message", message)).get_tree_hash())
    assert digest.hex() == vector["registration"]["digest"]
    registration_signature = G2Element.from_bytes(bytes.fromhex(vector["registration"]["signature"]))
    assert AugSchemeMPL.verify(secret_key.public_key(), digest, registration_signature)

    standard_key = secret_key.public_key()
    synthetic_key = G1Element.from_bytes(bytes.fromhex(vector["registration"]["syntheticPublicKey"]))
    public_keys = [
        synthetic_key if kind == "puzzle" else standard_key for kind in vector["aggSig"]
    ]
    messages = [bytes.fromhex(value) for value in vector["aggSig"].values()]
    aggregate_signature = G2Element.from_bytes(bytes.fromhex(vector["aggregateSignature"]))
    assert AugSchemeMPL.aggregate_verify(public_keys, messages, aggregate_signature)
