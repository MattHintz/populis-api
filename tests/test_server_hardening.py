from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest
import httpx
from fastapi import FastAPI, Request
from pydantic import BaseModel

from solslot_api.config import Settings, validate_server_hardening_at_startup
from solslot_api.challenges import RequestRateLimiter, preflight_challenge_storage
from solslot_api.server_hardening import (
    ServerHardeningMiddleware,
    documentation_urls,
    trusted_client_ip,
)


class ChallengeBody(BaseModel):
    address: str


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

    @app.post("/auth/challenge")
    async def challenge(body: ChallengeBody) -> dict[str, str]:
        return {"address": body.address}

    return app


def _staging(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "runtime_environment": "staging",
        "api_docs_enabled": False,
        "bootstrap_cookie_secure": True,
        "security_headers_enabled": True,
        "hsts_enabled": True,
        "trusted_proxy_cidrs": "203.0.113.0/24,2001:db8:1234::/48",
        "cors_origins": "https://staging.solslot.com",
        "alpha_writes_enabled": False,
        "vault_session_jwt_secret": "v" * 32,
        "minting_enabled": False,
        "zkpassport_validator_urls": [
            "https://validator-0.internal",
            "https://validator-1.internal",
            "https://validator-2.internal",
        ],
        "zkpassport_validator_pubkeys": [
            "0x" + "11" * 48,
            "0x" + "22" * 48,
            "0x" + "33" * 48,
        ],
        "zkpassport_validator_mtls_ca_path": "/run/secrets/validator-ca.pem",
        "zkpassport_validator_mtls_cert_path": "/run/secrets/coordinator-cert.pem",
        "zkpassport_validator_mtls_key_path": "/run/secrets/coordinator-key.pem",
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
        ("vault_session_cookie_secure", False, "VAULT_SESSION_COOKIE_SECURE"),
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


def test_staging_write_mode_rejects_single_validator_policy() -> None:
    with pytest.raises(RuntimeError, match="VALIDATOR_THRESHOLD"):
        validate_server_hardening_at_startup(
            _staging(
                alpha_writes_enabled=True,
                zkpassport_validator_threshold=1,
            )
        )


def test_read_only_staging_accepts_single_validator_default() -> None:
    validate_server_hardening_at_startup(
        _staging(alpha_writes_enabled=False, zkpassport_validator_threshold=1)
    )


def test_http_posture_does_not_accept_mutable_authority_coordinates() -> None:
    validate_server_hardening_at_startup(
        _staging(
            alpha_writes_enabled=True,
            zkpassport_validator_threshold=2,
        )
    )


def test_ceremony_mode_requires_locked_minting_token_and_same_origin() -> None:
    validate_server_hardening_at_startup(
        _staging(
            alpha_writes_enabled=True,
            ceremony_mode_enabled=True,
            zkpassport_validator_threshold=2,
            admin_token="one-time-token",
            cors_origins="",
        )
    )

    with pytest.raises(RuntimeError, match="cannot configure CORS"):
        validate_server_hardening_at_startup(
            _staging(
                alpha_writes_enabled=True,
                ceremony_mode_enabled=True,
                zkpassport_validator_threshold=2,
                admin_token="one-time-token",
            )
        )


def test_minting_cannot_be_enabled_while_alpha_writes_are_locked() -> None:
    with pytest.raises(RuntimeError, match="MINTING_ENABLED"):
        validate_server_hardening_at_startup(
            _staging(minting_enabled=True, alpha_writes_enabled=False)
        )


@pytest.mark.asyncio
async def test_challenge_limiter_counts_valid_and_invalid_requests() -> None:
    settings = Settings(
        runtime_environment="test",
        challenge_per_ip_per_minute=3,
    )
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        invalid = await client.post("/auth/challenge", json={})
        valid_one = await client.post(
            "/auth/challenge",
            json={"address": "0x1111111111111111111111111111111111111111"},
        )
        valid_two = await client.post(
            "/auth/challenge",
            json={"address": "0x2222222222222222222222222222222222222222"},
        )
        limited = await client.post("/auth/challenge", json={})

    assert invalid.status_code == 422
    assert valid_one.status_code == 200
    assert valid_two.status_code == 200
    assert limited.status_code == 429
    assert limited.json() == {"detail": "Too many challenge requests. Try again later."}
    assert limited.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_challenge_limiter_ignores_spoofed_forwarding_headers() -> None:
    settings = Settings(
        runtime_environment="test",
        challenge_per_ip_per_minute=1,
    )
    transport = httpx.ASGITransport(app=_app(settings), client=("203.0.113.9", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        first = await client.post(
            "/auth/challenge",
            json={"address": "first"},
            headers={"X-Forwarded-For": "198.51.100.1"},
        )
        second = await client.post(
            "/auth/challenge",
            json={"address": "second"},
            headers={"X-Forwarded-For": "198.51.100.2"},
        )

    assert first.status_code == 200
    assert second.status_code == 429


def test_persistent_challenge_limiter_is_atomic_across_workers(tmp_path) -> None:
    path = tmp_path / "shared" / "challenges.db"
    workers = [
        RequestRateLimiter(25, db_path=path),
        RequestRateLimiter(25, db_path=path),
    ]

    def attempt(index: int) -> bool:
        return workers[index % len(workers)].allow("198.51.100.44")

    with ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(attempt, range(200)))

    assert sum(results) == 25
    assert results.count(False) == 175


def test_deployed_challenge_store_requires_absolute_shared_path(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="absolute shared-state path"):
        preflight_challenge_storage(
            _staging(challenge_store_path="./state/challenges_v2.db")
        )

    absolute_path = tmp_path / "shared" / "challenges_v2.db"
    preflight_challenge_storage(
        _staging(challenge_store_path=str(absolute_path))
    )
    assert absolute_path.is_file()


def test_client_ip_accepts_cloudflare_header_only_from_trusted_peer() -> None:
    settings = Settings(trusted_proxy_cidrs="203.0.113.0/24")
    trusted_scope = {
        "client": ("203.0.113.9", 443),
        "headers": [(b"cf-connecting-ip", b"198.51.100.44")],
    }
    direct_scope = {
        "client": ("192.0.2.9", 443),
        "headers": [(b"cf-connecting-ip", b"198.51.100.44")],
    }
    assert trusted_client_ip(trusted_scope, settings) == "198.51.100.44"
    assert trusted_client_ip(direct_scope, settings) == "192.0.2.9"


@pytest.mark.parametrize(
    "headers",
    [
        [(b"cf-connecting-ip", b"not-an-ip")],
        [
            (b"cf-connecting-ip", b"198.51.100.1"),
            (b"cf-connecting-ip", b"198.51.100.2"),
        ],
    ],
)
def test_client_ip_falls_back_to_proxy_for_ambiguous_header(headers) -> None:
    settings = Settings(trusted_proxy_cidrs="203.0.113.0/24")
    assert (
        trusted_client_ip(
            {"client": ("203.0.113.9", 443), "headers": headers}, settings
        )
        == "203.0.113.9"
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("eip712_chain_id", 1, "SOLSLOT_EIP712_CHAIN_ID"),
        (
            "zkpassport_evm_chain_id",
            1,
            "SOLSLOT_ZKPASSPORT_EVM_CHAIN_ID",
        ),
    ],
)
def test_testnet11_rejects_mainnet_evm_chain_ids(
    field: str,
    value: int,
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        validate_server_hardening_at_startup(_staging(**{field: value}))


def test_mainnet_rejects_sepolia_eip712_domain() -> None:
    with pytest.raises(RuntimeError, match="SOLSLOT_EIP712_CHAIN_ID"):
        validate_server_hardening_at_startup(
            _staging(
                runtime_environment="production",
                network="mainnet",
                zkpassport_validator_threshold=2,
                zkpassport_evm_chain_id=1,
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
