"""Unit + endpoint tests for ``populis_api.admin_auth``.

Three concentric layers:

  * pure helpers (issue_jwt / verify_jwt / typed_data) — exercised
    without spinning up FastAPI,
  * a self-contained mini-app that mounts only the admin_auth router
    so endpoint behaviour can be tested without dragging in the full
    ``populis_api.app`` (which carries chia_rs LazyNode threading
    edge cases unrelated to this module),
  * full-flow happy path that signs a real EIP-712 envelope with
    ``eth_account`` so the recovery + allowlist check are exercised
    end-to-end.
"""
from __future__ import annotations

import time
from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
from fastapi.testclient import TestClient

from populis_api import admin_auth
from populis_api.admin_auth import (
    ADMIN_LOGIN_PRIMARY_TYPE,
    AdminClaims,
    JWTVerifyError,
    admin_login_typed_data,
    issue_jwt,
    reset_admin_state_for_tests,
    verify_jwt,
)
from populis_api.config import Settings, get_settings


# ── Fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _reset_admin_state():
    """Clear the cached challenge store + JWT secret around every test."""
    reset_admin_state_for_tests()
    get_settings.cache_clear()
    yield
    reset_admin_state_for_tests()
    get_settings.cache_clear()


@pytest.fixture
def settings_with_admin(monkeypatch) -> Settings:
    """Settings with the admin desk fully configured + a fresh JWT secret."""
    # Use a deterministic test pubkey so allowlist checks succeed when
    # we sign with ``Account.from_key(_TEST_PRIVKEY_HEX)``.
    monkeypatch.setenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", _TEST_ADDRESS_LOWER)
    monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "x" * 64)
    monkeypatch.setenv("POPULIS_ADMIN_JWT_TTL_SECONDS", "900")
    monkeypatch.setenv("POPULIS_ADMIN_LOGIN_PER_IP_PER_MINUTE", "100")
    get_settings.cache_clear()
    s = get_settings()
    return s


@pytest.fixture
def app_under_test(settings_with_admin) -> FastAPI:
    """Mini FastAPI app that mounts only the admin_auth router."""
    app = FastAPI()
    app.include_router(admin_auth.router)
    return app


@pytest.fixture
def client(app_under_test) -> TestClient:
    return TestClient(app_under_test)


# ── Test fixtures: deterministic key + address ──────────────────────────────
# Hard-coded keypair used across the tests.  NOT used outside tests.
_TEST_PRIVKEY_HEX = (
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)
_TEST_ACCT = Account.from_key(_TEST_PRIVKEY_HEX)
_TEST_ADDRESS = _TEST_ACCT.address                  # checksummed
_TEST_ADDRESS_LOWER = _TEST_ADDRESS.lower()         # matches allowlist normalization


# ── Pure helpers (no FastAPI) ───────────────────────────────────────────────
class TestTypedData:
    def test_envelope_has_canonical_primary_type(self, settings_with_admin):
        td = admin_login_typed_data(
            owner_address=_TEST_ADDRESS,
            nonce_hex="0x" + "11" * 32,
            issued_at=1_000_000_000,
            settings=settings_with_admin,
        )
        assert td["primaryType"] == ADMIN_LOGIN_PRIMARY_TYPE
        assert td["domain"]["name"] == "Populis Protocol"
        assert td["message"]["owner"] == _TEST_ADDRESS
        assert td["message"]["nonce"].startswith("0x")
        assert td["message"]["issuedAt"] == 1_000_000_000

    def test_envelope_distinct_from_registration_typehash(self, settings_with_admin):
        # Sanity: PopulisVaultRegister envelope and PopulisAdminLogin
        # envelope must not collide.
        td = admin_login_typed_data(
            owner_address=_TEST_ADDRESS,
            nonce_hex="0x" + "22" * 32,
            issued_at=1_000_000_000,
            settings=settings_with_admin,
        )
        assert td["primaryType"] == "PopulisAdminLogin"
        # Different fields than the registration envelope.
        register_only = {"poolLauncherId", "authType", "chiaNetwork"}
        assert register_only.isdisjoint(td["message"].keys())


class TestJWTRoundtrip:
    def test_issue_then_verify(self, settings_with_admin):
        token, exp = issue_jwt(
            sub=_TEST_ADDRESS_LOWER,
            auth_type="evm",
            settings=settings_with_admin,
        )
        assert isinstance(token, str)
        assert exp > int(time.time())

        claims = verify_jwt(token, settings_with_admin)
        assert isinstance(claims, AdminClaims)
        assert claims.sub == _TEST_ADDRESS_LOWER
        assert claims.auth_type == "evm"
        assert claims.exp == exp

    def test_verify_rejects_tampered_token(self, settings_with_admin):
        token, _ = issue_jwt(
            sub=_TEST_ADDRESS_LOWER,
            auth_type="evm",
            settings=settings_with_admin,
        )
        # Flip a character in the signature segment (last segment after the
        # second '.').  Any change should invalidate HS256.
        tampered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
        with pytest.raises(JWTVerifyError):
            verify_jwt(tampered, settings_with_admin)

    def test_verify_rejects_expired_token(self, monkeypatch, settings_with_admin):
        # Issue a token with TTL=1s, then wait it out.
        monkeypatch.setenv("POPULIS_ADMIN_JWT_TTL_SECONDS", "1")
        get_settings.cache_clear()
        s = get_settings()
        token, _ = issue_jwt(sub=_TEST_ADDRESS_LOWER, auth_type="evm", settings=s)
        time.sleep(1.5)
        with pytest.raises(JWTVerifyError, match="expired"):
            verify_jwt(token, s)

    def test_verify_rejects_wrong_scope(self, settings_with_admin):
        # Hand-mint a token with scope='other'.
        import jwt as pyjwt
        secret = admin_auth.get_jwt_secret(settings_with_admin)
        bad = pyjwt.encode(
            {"sub": _TEST_ADDRESS_LOWER, "auth_type": "evm",
             "iat": int(time.time()), "exp": int(time.time()) + 60,
             "scope": "other"},
            secret, algorithm="HS256",
        )
        with pytest.raises(JWTVerifyError, match="scope"):
            verify_jwt(bad, settings_with_admin)

    def test_verify_rejects_wrong_secret(self, monkeypatch):
        """A token signed under one secret must not verify under another."""
        # Issue a token with secret A.
        monkeypatch.setenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", _TEST_ADDRESS_LOWER)
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "a" * 64)
        get_settings.cache_clear()
        reset_admin_state_for_tests()
        s_a = get_settings()
        token, _ = issue_jwt(
            sub=_TEST_ADDRESS_LOWER, auth_type="evm", settings=s_a,
        )

        # Switch the configured secret to B (simulating an operator
        # rotating POPULIS_ADMIN_JWT_SECRET) and verify the old token
        # is rejected.
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "b" * 64)
        get_settings.cache_clear()
        reset_admin_state_for_tests()
        s_b = get_settings()
        with pytest.raises(JWTVerifyError):
            verify_jwt(token, s_b)


class TestJWTSecretCaching:
    def test_random_secret_when_unset(self, monkeypatch):
        monkeypatch.delenv("POPULIS_ADMIN_JWT_SECRET", raising=False)
        get_settings.cache_clear()
        s = get_settings()
        secret1 = admin_auth.get_jwt_secret(s)
        secret2 = admin_auth.get_jwt_secret(s)
        # Same call twice in the same process → same secret.
        assert secret1 == secret2
        # Random secret is at least 32 bytes of hex (64 chars).
        assert len(secret1) >= 64

    def test_explicit_secret_used_when_set(self, monkeypatch):
        explicit = "abc123" * 11           # arbitrary, deterministic
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", explicit)
        get_settings.cache_clear()
        s = get_settings()
        assert admin_auth.get_jwt_secret(s) == explicit


# ── Endpoints ────────────────────────────────────────────────────────────────
class TestChallenge:
    def test_503_when_allowlist_empty(self, monkeypatch):
        monkeypatch.delenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", raising=False)
        get_settings.cache_clear()
        app = FastAPI()
        app.include_router(admin_auth.router)
        client = TestClient(app)
        resp = client.post(
            "/admin/auth/challenge",
            json={"owner": _TEST_ADDRESS, "auth_type": "evm"},
        )
        assert resp.status_code == 503

    def test_returns_nonce_and_typed_data(self, client):
        resp = client.post(
            "/admin/auth/challenge",
            json={"owner": _TEST_ADDRESS, "auth_type": "evm"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["nonce"].startswith("0x")
        assert len(body["nonce"]) == 2 + 64
        assert body["expires_at"] > int(time.time())
        assert body["typed_data"]["primaryType"] == ADMIN_LOGIN_PRIMARY_TYPE

    def test_chia_bls_returns_minimal_envelope(self, client):
        resp = client.post(
            "/admin/auth/challenge",
            json={"owner": "0x" + "33" * 48, "auth_type": "chia_bls"},
        )
        assert resp.status_code == 200
        body = resp.json()
        # The BLS envelope is a dict but doesn't include the EVM types schema.
        assert body["typed_data"]["primaryType"] == ADMIN_LOGIN_PRIMARY_TYPE
        assert body["typed_data"]["message"]["owner"].startswith("0x")

    def test_rate_limit_kicks_in(self, monkeypatch, client):
        # Override the cap to 2/min so the third call is rejected.
        monkeypatch.setenv("POPULIS_ADMIN_LOGIN_PER_IP_PER_MINUTE", "2")
        get_settings.cache_clear()
        reset_admin_state_for_tests()
        app = FastAPI()
        app.include_router(admin_auth.router)
        c = TestClient(app)

        for _ in range(2):
            r = c.post(
                "/admin/auth/challenge",
                json={"owner": _TEST_ADDRESS, "auth_type": "evm"},
            )
            assert r.status_code == 200

        r3 = c.post(
            "/admin/auth/challenge",
            json={"owner": _TEST_ADDRESS, "auth_type": "evm"},
        )
        assert r3.status_code == 429


class TestLogin:
    def _challenge_and_sign(self, client, *, owner: str = _TEST_ADDRESS) -> dict[str, Any]:
        """Issue a challenge for ``owner`` and sign it with the test key.

        Returns the body to pass to /admin/auth/login.
        """
        ch = client.post(
            "/admin/auth/challenge",
            json={"owner": owner, "auth_type": "evm"},
        ).json()
        typed_data = ch["typed_data"]
        # eth_account accepts the same shape we issue.
        signable = encode_typed_data(full_message=typed_data)
        signed = _TEST_ACCT.sign_message(signable)
        return {
            "owner": owner,
            "nonce": ch["nonce"],
            "signature": "0x" + signed.signature.hex().replace("0x", ""),
            "auth_type": "evm",
        }

    def test_happy_path(self, client):
        body = self._challenge_and_sign(client)
        resp = client.post("/admin/auth/login", json=body)
        assert resp.status_code == 200, resp.text
        out = resp.json()
        assert out["jwt"].count(".") == 2
        assert out["expires_at"] > int(time.time())
        assert out["owner"] == _TEST_ADDRESS_LOWER

    def test_returned_jwt_verifies(self, client, settings_with_admin):
        body = self._challenge_and_sign(client)
        out = client.post("/admin/auth/login", json=body).json()
        claims = verify_jwt(out["jwt"], settings_with_admin)
        assert claims.sub == _TEST_ADDRESS_LOWER
        assert claims.auth_type == "evm"

    def test_unknown_nonce_404(self, client):
        body = self._challenge_and_sign(client)
        body["nonce"] = "0x" + "ff" * 32
        resp = client.post("/admin/auth/login", json=body)
        assert resp.status_code == 404

    def test_consumed_nonce_404(self, client):
        body = self._challenge_and_sign(client)
        first = client.post("/admin/auth/login", json=body)
        assert first.status_code == 200
        # Second use of the same nonce must fail.
        again = client.post("/admin/auth/login", json=body)
        assert again.status_code == 404

    def test_wrong_signature_401(self, client):
        body = self._challenge_and_sign(client)
        # Mangle the signature.  The trailing v byte is significant; flip it.
        sig = body["signature"]
        body["signature"] = sig[:-2] + ("a0" if sig[-2:] != "a0" else "b0")
        resp = client.post("/admin/auth/login", json=body)
        assert resp.status_code == 401

    def test_address_mismatch_401(self, client):
        # Sign with the test key but declare a DIFFERENT owner.  The
        # challenge is bound to the declared owner so the EIP-712
        # message has the wrong owner; recovered address won't match.
        ch = client.post(
            "/admin/auth/challenge",
            json={"owner": "0x000000000000000000000000000000000000DEAD",
                  "auth_type": "evm"},
        ).json()
        typed_data = ch["typed_data"]
        signable = encode_typed_data(full_message=typed_data)
        signed = _TEST_ACCT.sign_message(signable)
        resp = client.post(
            "/admin/auth/login",
            json={
                "owner": "0x000000000000000000000000000000000000DEAD",
                "nonce": ch["nonce"],
                "signature": "0x" + signed.signature.hex().replace("0x", ""),
                "auth_type": "evm",
            },
        )
        # The challenge was issued for 0xDEAD but signed by _TEST_ACCT;
        # recovered address is _TEST_ADDRESS, which does not match.
        assert resp.status_code == 401

    def test_not_in_allowlist_403(self, monkeypatch):
        # Reconfigure with a different allowlist that doesn't include
        # the test signer.
        monkeypatch.setenv(
            "POPULIS_ADMIN_PUBKEY_ALLOWLIST",
            "0x000000000000000000000000000000000000DEAD",
        )
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "y" * 64)
        get_settings.cache_clear()
        reset_admin_state_for_tests()
        app = FastAPI()
        app.include_router(admin_auth.router)
        c = TestClient(app)

        body = TestLogin()._challenge_and_sign(c)
        resp = c.post("/admin/auth/login", json=body)
        assert resp.status_code == 403

    def test_chia_bls_not_implemented(self, client):
        resp = client.post(
            "/admin/auth/login",
            json={
                "owner": "0x" + "33" * 48,
                "nonce": "0x" + "11" * 32,
                "signature": "0x" + "00" * 96,
                "auth_type": "chia_bls",
            },
        )
        assert resp.status_code == 501


class TestRefresh:
    def _login(self, client) -> tuple[str, int]:
        body = TestLogin()._challenge_and_sign(client)
        out = client.post("/admin/auth/login", json=body).json()
        return out["jwt"], out["expires_at"]

    def test_refresh_returns_new_token(self, client, settings_with_admin):
        token, original_exp = self._login(client)
        # Sleep 1s so the freshly-minted JWT has a strictly-greater
        # iat/exp pair than the original, making the byte string
        # different.  HS256 is deterministic, so without a delay the
        # encoded token would be identical.
        time.sleep(1.1)
        resp = client.post(
            "/admin/auth/refresh",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        out = resp.json()
        assert out["jwt"] != token, "refresh should mint a fresh token"
        assert out["expires_at"] > original_exp
        # The new token must verify under the same secret.
        claims = verify_jwt(out["jwt"], settings_with_admin)
        assert claims.sub == _TEST_ADDRESS_LOWER

    def test_missing_header_returns_401(self, client):
        resp = client.post("/admin/auth/refresh")
        assert resp.status_code == 401

    def test_malformed_header_returns_401(self, client):
        resp = client.post(
            "/admin/auth/refresh",
            headers={"Authorization": "Token xxx"},
        )
        assert resp.status_code == 401

    def test_invalid_token_returns_403(self, client):
        resp = client.post(
            "/admin/auth/refresh",
            headers={"Authorization": "Bearer not-a-jwt"},
        )
        assert resp.status_code == 403

    def test_503_when_allowlist_empty(self, monkeypatch):
        # Logged-in token, but allowlist subsequently cleared → 503.
        # (The refresh dependency reads the allowlist on every call.)
        monkeypatch.setenv(
            "POPULIS_ADMIN_PUBKEY_ALLOWLIST", _TEST_ADDRESS_LOWER,
        )
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "z" * 64)
        get_settings.cache_clear()
        reset_admin_state_for_tests()
        app = FastAPI()
        app.include_router(admin_auth.router)
        c = TestClient(app)
        token, _ = self._login(c)

        # Now clear the allowlist and recreate the dependency cache.
        monkeypatch.setenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", "")
        get_settings.cache_clear()

        resp = c.post(
            "/admin/auth/refresh",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 503
