"""End-to-end tests for the isolated, one-capability KoS signer."""
from __future__ import annotations

import pytest
from chia_rs import AugSchemeMPL, Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi.testclient import TestClient

from solslot_api.config import Settings
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.kos_mint_execute_app import create_kos_mint_execute_app
from solslot_api.kos_mint_execute_ledger import KosMintExecuteLedger
from solslot_api.kos_mint_execute_signer import request_kos_mint_execute_signature
from solslot_api.kos_mint_execute_service import (
    KosMintExecuteClaim,
    KosMintExecuteEvidenceError,
    load_kos_mint_execute_private_key,
    sign_kos_mint_execute_claim,
)
from solslot_api.kos_mint_execute_settings import KosMintExecuteSignerSettings
from solslot_api.mint_chain_validation import CanonicalKosMintExecution
from solslot_api.release_metadata import ReleaseMetadata
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import (
    kos_mint_execute_message,
    kos_mint_execute_signing_message,
)


def _fixture(tmp_path, monkeypatch):
    private_key = AugSchemeMPL.key_gen(b"KoS isolated signer application test key v1")
    private_key_file = tmp_path / "kos-mint-execute.key"
    private_key_file.write_text("0x" + bytes(private_key).hex() + "\n", encoding="ascii")
    private_key_file.chmod(0o600)
    launcher = bytes32(b"l" * 32)
    governance_full_puzzle_hash = bytes32(b"h" * 32)
    governance_coin = Coin(bytes32(b"p" * 32), governance_full_puzzle_hash, uint64(1))
    artifact = {
        "artifactHash": "0x" + "a1" * 32,
        "network": "testnet11",
        "sourceShas": {"api": "a" * 40, "protocol": "b" * 40},
        "launcherIds": {"governance": "0x" + bytes(launcher).hex()},
        "puzzleHashes": {
            "governanceFullPuzzleHash": "0x" + bytes(governance_full_puzzle_hash).hex()
        },
        "governanceStruct": {
            "mintExecuteCosignerPubkey": "0x" + bytes(private_key.get_g1()).hex()
        },
    }
    release = ReleaseMetadata(
        apiCommit="a" * 40,
        protocolCommit="b" * 40,
        builtAtUtc="2026-07-20T00:00:00Z",
        packageName="solslot-api-test.tgz",
        appModule="solslot_api.kos_mint_execute_app:app",
    )
    settings = KosMintExecuteSignerSettings(
        private_key_file=str(private_key_file),
        ledger_db_path=str(tmp_path / "kos-ledger.db"),
        public_artifact_path=str(tmp_path / "artifact.json"),
        release_metadata_path=str(tmp_path / "release.json"),
        coinset_base_url="https://coinset.example.invalid",
    )
    monkeypatch.setattr(
        "solslot_api.kos_mint_execute_service.verify_signed_public_artifact_file",
        lambda _path: artifact,
    )
    monkeypatch.setattr(
        "solslot_api.kos_mint_execute_service.load_release_metadata",
        lambda _path: release,
    )
    monkeypatch.setattr(
        "solslot_api.kos_mint_execute_service._fetch_unspent_governance_coin",
        lambda _settings, _coin_id: governance_coin,
    )
    return settings, private_key, artifact, launcher, governance_coin


def _claim(artifact, launcher, governance_coin, proposal_hash: bytes32) -> KosMintExecuteClaim:
    visible = kos_mint_execute_message(
        governance_singleton_struct=singleton_struct(launcher),
        governance_coin_id=bytes32(governance_coin.name()),
        proposal_hash=proposal_hash,
    )
    signing = kos_mint_execute_signing_message(
        governance_singleton_struct=singleton_struct(launcher),
        governance_coin_id=bytes32(governance_coin.name()),
        proposal_hash=proposal_hash,
        agg_sig_me_additional_data=bytes32(AGG_SIG_ME_DATA["testnet11"]),
    )
    return KosMintExecuteClaim(
        capability="governance-mint-execute-v1",
        network="testnet11",
        artifactHash=artifact["artifactHash"],
        proposalId="mp_test_001",
        proposalHash="0x" + bytes(proposal_hash).hex(),
        governanceCoinId="0x" + bytes(governance_coin.name()).hex(),
        mintExecuteCosignerPubkey=artifact["governanceStruct"]["mintExecuteCosignerPubkey"],
        visibleMessage="0x" + visible.hex(),
        signingMessage="0x" + signing.hex(),
    )


def test_signer_app_signs_exact_claim_and_recovers_only_exact_retry(tmp_path, monkeypatch) -> None:
    settings, private_key, artifact, launcher, governance_coin = _fixture(tmp_path, monkeypatch)
    claim = _claim(artifact, launcher, governance_coin, bytes32(b"q" * 32))
    ledger = KosMintExecuteLedger(":memory:")
    app = create_kos_mint_execute_app(settings=settings, ledger=ledger)
    try:
        with TestClient(app) as client:
            health = client.get("/health")
            assert health.status_code == 200, health.text
            assert health.json()["mintExecuteCosignerPubkey"] == (
                "0x" + bytes(private_key.get_g1()).hex()
            )
            assert client.get("/openapi.json").status_code == 404

            first = client.post("/v1/governance/mint-execute/sign", json=claim.model_dump())
            second = client.post("/v1/governance/mint-execute/sign", json=claim.model_dump())
            assert first.status_code == second.status_code == 200
            assert first.json() == second.json()
            assert first.json()["requestHash"] == claim.request_hash()

            other = _claim(artifact, launcher, governance_coin, bytes32(b"r" * 32))
            rejected = client.post(
                "/v1/governance/mint-execute/sign", json=other.model_dump()
            )
            assert rejected.status_code == 409
            assert "different request for this governance coin" in rejected.json()["detail"]
    finally:
        ledger.close()


def test_tampered_claim_cannot_obtain_a_signature(tmp_path, monkeypatch) -> None:
    settings, _private_key, artifact, launcher, governance_coin = _fixture(tmp_path, monkeypatch)
    claim = _claim(artifact, launcher, governance_coin, bytes32(b"q" * 32))
    tampered = claim.model_copy(
        update={"visibleMessage": "0x" + "00" * 32}
    )
    ledger = KosMintExecuteLedger(":memory:")
    try:
        with pytest.raises(KosMintExecuteEvidenceError, match="visible message"):
            sign_kos_mint_execute_claim(settings, ledger, tampered)
    finally:
        ledger.close()


def test_group_readable_signer_key_is_rejected(tmp_path, monkeypatch) -> None:
    settings, _private_key, _artifact, _launcher, _coin = _fixture(tmp_path, monkeypatch)
    key_path = tmp_path / "kos-mint-execute.key"
    key_path.chmod(0o640)

    with pytest.raises(KosMintExecuteEvidenceError, match="group/other"):
        load_kos_mint_execute_private_key(settings)


def test_mtls_listener_configuration_is_mandatory(tmp_path, monkeypatch) -> None:
    settings, _private_key, _artifact, _launcher, _coin = _fixture(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError, match="requires TLS certificate"):
        settings.require_mtls_listener()


@pytest.mark.asyncio
async def test_coordinator_client_and_isolated_signer_share_one_wire_contract(
    tmp_path, monkeypatch
) -> None:
    signer_settings, private_key, artifact, launcher, governance_coin = _fixture(
        tmp_path, monkeypatch
    )
    claim = _claim(artifact, launcher, governance_coin, bytes32(b"q" * 32))
    ledger = KosMintExecuteLedger(":memory:")
    app = create_kos_mint_execute_app(settings=signer_settings, ledger=ledger)
    requests: list[dict] = []

    class LoopbackResponse:
        def __init__(self, response) -> None:
            self.response = response

        def raise_for_status(self) -> None:
            if self.response.status_code >= 400:
                raise RuntimeError(self.response.text)

        def json(self):
            return self.response.json()

    class LoopbackAsyncClient:
        def __init__(self, **_kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def post(self, url: str, *, json: dict) -> LoopbackResponse:
            requests.append(json)
            path = "/" + url.split("/", 3)[3]
            return LoopbackResponse(client.post(path, json=json))

    coordinator_settings = Settings(
        runtime_environment="test",
        network="testnet11",
        kos_mint_execute_signer_enabled=True,
        kos_mint_execute_signer_url="https://kos.testnet.internal",
        kos_mint_execute_signer_mtls_ca_path="/not-used-in-loopback",
        kos_mint_execute_signer_mtls_cert_path="/not-used-in-loopback",
        kos_mint_execute_signer_mtls_key_path="/not-used-in-loopback",
    )
    execution = CanonicalKosMintExecution(
        governance_coin_id=bytes32(governance_coin.name()),
        proposal_hash=bytes32(b"q" * 32),
        cosigner_pubkey=bytes(private_key.get_g1()),
        visible_message=bytes.fromhex(claim.visibleMessage[2:]),
        signing_message=bytes.fromhex(claim.signingMessage[2:]),
    )
    monkeypatch.setattr(
        "solslot_api.kos_mint_execute_signer._mtls_context", lambda _settings: object()
    )
    monkeypatch.setattr(
        "solslot_api.kos_mint_execute_signer.httpx.AsyncClient", LoopbackAsyncClient
    )
    try:
        with TestClient(app) as client:
            signature, audit_hash = await request_kos_mint_execute_signature(
                settings=coordinator_settings,
                execution=execution,
                artifact_hash=artifact["artifactHash"],
                proposal_id=claim.proposalId,
            )
    finally:
        ledger.close()

    assert requests == [claim.canonical_payload()]
    assert audit_hash == claim.request_hash()
    assert AugSchemeMPL.verify(private_key.get_g1(), execution.signing_message, signature)
