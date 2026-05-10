from __future__ import annotations

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
    monkeypatch.setenv("POPULIS_ADMIN_TOKEN", "bootstrap-secret")
    monkeypatch.setenv("POPULIS_BOOTSTRAP_MANIFEST_PATH", str(manifest_path))
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
