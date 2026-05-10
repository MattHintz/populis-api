from __future__ import annotations

import json

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from populis_api import admin_auth, admin_bootstrap
from populis_api.admin_bootstrap import BOOTSTRAP_COOKIE_NAME, BOOTSTRAP_COOKIE_PATH
from populis_api.config import get_settings


@pytest.fixture(autouse=True)
def _reset_state():
    get_settings.cache_clear()
    admin_bootstrap.reset_bootstrap_state_for_tests()
    admin_auth.reset_admin_state_for_tests()
    yield
    get_settings.cache_clear()
    admin_bootstrap.reset_bootstrap_state_for_tests()
    admin_auth.reset_admin_state_for_tests()


@pytest.fixture
def bootstrap_env(monkeypatch, tmp_path):
    manifest_path = tmp_path / "bootstrap_manifest.json"
    deployment_manifest_path = tmp_path / "deployment_manifest.json"
    monkeypatch.setenv("POPULIS_ADMIN_TOKEN", "bootstrap-secret")
    monkeypatch.setenv("POPULIS_BOOTSTRAP_MANIFEST_PATH", str(manifest_path))
    monkeypatch.setenv("POPULIS_DEPLOYMENT_MANIFEST_PATH", str(deployment_manifest_path))
    monkeypatch.setenv("POPULIS_BOOTSTRAP_SESSION_SECRET", "b" * 64)
    monkeypatch.setenv("POPULIS_BOOTSTRAP_SESSION_TTL_SECONDS", "60")
    monkeypatch.setenv("POPULIS_BOOTSTRAP_COOKIE_SECURE", "false")
    monkeypatch.setenv(
        "POPULIS_ADMIN_PUBKEY_ALLOWLIST",
        "0x1111111111111111111111111111111111111111",
    )
    monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "j" * 64)
    get_settings.cache_clear()
    return manifest_path


@pytest.fixture
def client(bootstrap_env) -> TestClient:
    app = FastAPI()
    app.include_router(admin_bootstrap.router)
    app.include_router(admin_auth.router)
    return TestClient(app)


H = lambda byte: "0x" + byte * 32


def deployment_manifest() -> dict:
    return {
        "network": "testnet11",
        "params": {"quorum_bps": 5000},
        "faucet_inner_puzhash": H("01"),
        "pgt_genesis_coin_id": H("02"),
        "pool_genesis_coin_id": H("03"),
        "did_genesis_coin_id": H("04"),
        "gov_genesis_coin_id": H("05"),
        "pool_launcher_id": H("11"),
        "did_launcher_id": H("22"),
        "tracker_launcher_id": H("33"),
        "pgt_tail_hash": H("44"),
        "pgt_full_puzhash": H("45"),
        "pool_token_tail_hash": H("55"),
        "pool_inner_puzhash": H("56"),
        "pool_full_puzhash": H("66"),
        "did_inner_puzhash": H("67"),
        "did_full_puzhash": H("68"),
        "tracker_inner_puzhash": H("69"),
        "tracker_full_puzhash": H("77"),
    }


def admin_records() -> dict:
    return {
        "version": 1,
        "launcher_id": H("88"),
        "admin_records": [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    {
                        "kind": "eip712_member",
                        "leaf_hash": H("99"),
                        "evm_address": "0x" + "aa" * 20,
                        "secp256k1_pubkey": "0x02" + "bb" * 32,
                        "type_hash": H("cc"),
                        "prefix_and_domain_separator": "0x1901" + "dd" * 32,
                    }
                ],
            }
        ],
    }


def finalize_payload() -> dict:
    return {
        "admin_records": admin_records(),
        "admin_authority_launcher_id": H("88"),
        "admins_hash": H("ab"),
        "mips_root": H("cd"),
        "read_only_api_url": "https://api.populis.example",
        "read_only_coinset_url": "https://coinset.example",
    }


def write_deployment_manifest(bootstrap_manifest_path) -> None:
    bootstrap_manifest_path.with_name("deployment_manifest.json").write_text(
        json.dumps(deployment_manifest()),
        encoding="utf-8",
    )


def test_bootstrap_challenge_rejects_bad_token(client: TestClient) -> None:
    resp = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer wrong"},
    )

    assert resp.status_code == 403
    assert BOOTSTRAP_COOKIE_NAME not in resp.headers.get("set-cookie", "")


def test_bootstrap_challenge_rejects_locked_bootstrapper(
    client: TestClient,
    bootstrap_env,
) -> None:
    bootstrap_env.write_text('{"locked": true}', encoding="utf-8")

    resp = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )

    assert resp.status_code == 410
    assert "locked" in resp.json()["detail"].lower()


def test_bootstrap_challenge_issues_scoped_short_lived_cookie(client: TestClient) -> None:
    resp = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["unlocked"] is True
    assert body["expires_at"] > 0

    set_cookie = resp.headers["set-cookie"]
    assert f"{BOOTSTRAP_COOKIE_NAME}=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert f"Path={BOOTSTRAP_COOKIE_PATH}" in set_cookie
    assert "Max-Age=60" in set_cookie
    assert "SameSite=strict" in set_cookie

    status = client.get("/admin/bootstrap/status")
    assert status.status_code == 200
    assert status.json()["locked"] is False
    assert status.json()["authenticated"] is True
    assert status.json()["expires_at"] == body["expires_at"]
    assert "bootstrap_manifest_path" not in status.json()


def test_bootstrap_status_locks_after_manifest_exists(client: TestClient, bootstrap_env) -> None:
    ok = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert ok.status_code == 200
    bootstrap_env.write_text('{"locked": true}', encoding="utf-8")

    status = client.get("/admin/bootstrap/status")

    assert status.status_code == 200
    assert status.json()["locked"] is True
    assert status.json()["authenticated"] is False


def test_bootstrap_cookie_does_not_authorize_normal_admin_auth(client: TestClient) -> None:
    challenge = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert challenge.status_code == 200
    bootstrap_token = client.cookies.get(BOOTSTRAP_COOKIE_NAME)
    assert bootstrap_token

    cookie_only = client.post("/admin/auth/refresh")
    assert cookie_only.status_code == 401

    bearer_replay = client.post(
        "/admin/auth/refresh",
        headers={"Authorization": f"Bearer {bootstrap_token}"},
    )
    assert bearer_replay.status_code == 403


def test_bootstrap_finalize_requires_bootstrap_session(
    client: TestClient,
    bootstrap_env,
) -> None:
    write_deployment_manifest(bootstrap_env)
    admin_jwt, _ = admin_auth.issue_jwt(
        sub="0x1111111111111111111111111111111111111111",
        auth_type="evm",
        settings=get_settings(),
    )

    resp = client.post(
        "/admin/bootstrap/finalize",
        json=finalize_payload(),
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )

    assert resp.status_code == 401
    assert "bootstrap session cookie" in resp.json()["detail"].lower()
    assert not bootstrap_env.exists()


def test_bootstrap_finalize_rejects_expired_bootstrap_session(
    client: TestClient,
    bootstrap_env,
) -> None:
    write_deployment_manifest(bootstrap_env)
    settings = get_settings()
    expired = pyjwt.encode(
        {"scope": "bootstrap", "iat": 1, "exp": 1},
        admin_bootstrap.get_bootstrap_secret(settings),
        algorithm="HS256",
    )

    resp = client.post(
        "/admin/bootstrap/finalize",
        json=finalize_payload(),
        headers={"Cookie": f"{BOOTSTRAP_COOKIE_NAME}={expired}"},
    )

    assert resp.status_code == 403
    assert "expired" in resp.json()["detail"].lower()
    assert not bootstrap_env.exists()


def test_bootstrap_finalize_persists_public_artifacts_and_locks(
    client: TestClient,
    bootstrap_env,
) -> None:
    write_deployment_manifest(bootstrap_env)
    challenge = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert challenge.status_code == 200

    resp = client.post("/admin/bootstrap/finalize", json=finalize_payload())

    assert resp.status_code == 200
    body = resp.json()
    assert body["locked"] is True
    assert body["bootstrap_manifest"]["admin_authority_v2"] == {
        "launcher_id": H("88"),
        "admins_hash": H("ab"),
        "mips_root": H("cd"),
    }
    admin_records_path = bootstrap_env.with_name("admin_records.json")
    runtime_path = bootstrap_env.with_name("portal_runtime_config.json")
    assert json.loads(admin_records_path.read_text()) == admin_records()
    assert json.loads(runtime_path.read_text()) == body["portal_runtime_config"]
    assert json.loads(bootstrap_env.read_text()) == body["bootstrap_manifest"]
    assert body["portal_runtime_config"]["read_only_api_url"] == "https://api.populis.example"
    emitted = json.dumps(body).lower()
    for forbidden in (
        "populis_admin_token",
        "bootstrap-secret",
        "populis_bootstrap_session",
        "bearer",
        "jwt_secret",
        "signature",
        "nonce",
        "private_key",
    ):
        assert forbidden not in emitted

    status = client.get("/admin/bootstrap/status")
    assert status.status_code == 200
    assert status.json() == {"locked": True, "authenticated": False, "expires_at": None}


def test_bootstrap_finalize_fails_closed_after_lock(
    client: TestClient,
    bootstrap_env,
) -> None:
    write_deployment_manifest(bootstrap_env)
    challenge = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert challenge.status_code == 200
    ok = client.post("/admin/bootstrap/finalize", json=finalize_payload())
    assert ok.status_code == 200

    second = client.post("/admin/bootstrap/finalize", json=finalize_payload())

    assert second.status_code == 410
    assert "locked" in second.json()["detail"].lower()


def test_bootstrap_finalize_requires_protocol_deployment_manifest(
    client: TestClient,
) -> None:
    challenge = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert challenge.status_code == 200

    resp = client.post("/admin/bootstrap/finalize", json=finalize_payload())

    assert resp.status_code == 409
    assert "deployment manifest is required" in resp.json()["detail"].lower()
