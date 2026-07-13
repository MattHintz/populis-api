from __future__ import annotations

import asyncio

import pytest
import httpx
from fastapi import FastAPI, Request

from solslot_api.config import Settings, validate_server_hardening_at_startup
from solslot_api.server_hardening import (
    ServerHardeningMiddleware,
    documentation_urls,
)


def _app(settings: Settings) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(ServerHardeningMiddleware, settings=settings)

    @app.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, bool]:
        await request.body()
        return {"ok": True}

    @app.get("/slow")
    async def slow() -> dict[str, bool]:
        await asyncio.sleep(0.05)
        return {"ok": True}

    return app


def _staging(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "runtime_environment": "staging",
        "api_docs_enabled": False,
        "bootstrap_cookie_secure": True,
        "security_headers_enabled": True,
        "hsts_enabled": True,
        "cors_origins": "https://staging.solslot.com",
    }
    values.update(overrides)
    return Settings(**values)


def test_staging_posture_passes_with_exact_https_origin() -> None:
    validate_server_hardening_at_startup(_staging())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("bootstrap_cookie_secure", False, "COOKIE_SECURE"),
        ("api_docs_enabled", True, "API_DOCS_ENABLED"),
        ("security_headers_enabled", False, "Security headers"),
        ("hsts_enabled", False, "Security headers"),
        ("cors_origins", "http://localhost:4200", "CORS origins"),
        ("cors_origins", "*", "CORS origins"),
    ],
)
def test_staging_rejects_insecure_server_posture(
    field: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        validate_server_hardening_at_startup(_staging(**{field: value}))


@pytest.mark.asyncio
async def test_security_headers_cover_success_and_error_responses() -> None:
    transport = httpx.ASGITransport(app=_app(_staging()))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        success = await client.get("/ok")
        missing = await client.get("/missing")

    for response in (success, missing):
        assert response.headers["strict-transport-security"].startswith("max-age=31536000")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_request_body_over_limit_is_rejected_before_routing() -> None:
    settings = _staging(max_request_body_bytes=16)
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        response = await client.post("/echo", content=b"x" * 17)

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body exceeds the configured limit."}
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_chunked_request_body_cannot_bypass_limit() -> None:
    async def body_chunks():
        yield b"x" * 8
        yield b"y" * 9

    settings = _staging(max_request_body_bytes=16)
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        response = await client.post("/echo", content=body_chunks())

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body exceeds the configured limit."}


@pytest.mark.asyncio
async def test_request_timeout_returns_bounded_gateway_timeout() -> None:
    settings = _staging(request_timeout_seconds=0.01)
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        response = await client.get("/slow")

    assert response.status_code == 504
    assert response.json() == {"detail": "Request processing timed out."}
    assert response.headers["x-content-type-options"] == "nosniff"


def test_development_may_opt_into_http_cookie_and_docs() -> None:
    validate_server_hardening_at_startup(
        Settings(
            runtime_environment="development",
            bootstrap_cookie_secure=False,
            api_docs_enabled=True,
            cors_origins="http://localhost:4200",
        )
    )


def test_documentation_urls_are_disabled_when_not_explicitly_enabled() -> None:
    assert documentation_urls(Settings(api_docs_enabled=False)) == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }
    assert documentation_urls(_staging()) == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }


def test_development_documentation_requires_explicit_opt_in() -> None:
    assert documentation_urls(
        Settings(runtime_environment="development", api_docs_enabled=True)
    ) == {
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json",
    }
