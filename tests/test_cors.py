from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from solslot_api.config import Settings
from solslot_api.cors import cors_middleware_options


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        **cors_middleware_options(
            Settings(
                runtime_environment="development",
                cors_origins="http://localhost:4200,http://localhost:5173",
            ),
        ),
    )

    @app.post("/admin/bootstrap/challenge")
    async def bootstrap_challenge_stub() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/admin/auth/refresh")
    async def admin_refresh_stub() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


def _preflight(origin: str, path: str = "/admin/bootstrap/challenge"):
    with _client() as client:
        return client.options(
            path,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )


def test_configured_origin_gets_credentialed_bootstrap_preflight() -> None:
    resp = _preflight("http://localhost:4200")

    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "http://localhost:4200"
    assert resp.headers["access-control-allow-credentials"] == "true"
    assert "authorization" in resp.headers["access-control-allow-headers"].lower()


def test_localhost_dev_regex_gets_credentialed_preflight() -> None:
    resp = _preflight("http://127.0.0.1:49152")

    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "http://127.0.0.1:49152"
    assert resp.headers["access-control-allow-credentials"] == "true"


def test_unknown_origin_is_not_allowed_for_credentialed_preflight() -> None:
    resp = _preflight("https://evil.example")

    assert resp.status_code == 400
    assert "access-control-allow-origin" not in resp.headers
    assert resp.headers["access-control-allow-credentials"] == "true"


def test_cors_credentials_are_not_wildcarded() -> None:
    with _client() as client:
        resp = client.options(
            "/admin/auth/refresh",
            headers={
                "Origin": "http://localhost:4200",
                "Access-Control-Request-Method": "POST",
            },
        )

    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "http://localhost:4200"
    assert resp.headers["access-control-allow-credentials"] == "true"
    assert resp.headers["access-control-allow-origin"] != "*"


def test_cors_options_keep_existing_method_and_header_policy() -> None:
    opts = cors_middleware_options(Settings(runtime_environment="development"))

    assert opts["allow_credentials"] is True
    assert opts["allow_methods"] == ["GET", "POST", "OPTIONS"]
    assert "Authorization" in opts["allow_headers"]
    assert "Content-Type" in opts["allow_headers"]
    assert "http://localhost:4200" in opts["allow_origins"]


def test_staging_does_not_enable_localhost_regex() -> None:
    opts = cors_middleware_options(
        Settings(
            runtime_environment="staging",
            cors_origins="https://staging.solslot.com",
        )
    )

    assert opts["allow_origin_regex"] is None
    assert opts["allow_origins"] == ["https://staging.solslot.com"]
