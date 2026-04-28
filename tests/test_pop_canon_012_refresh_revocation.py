"""Regression test for POP-CANON-012: refresh-without-revocation.

Boundary: ``populis_api/populis_api/admin_auth.py:require_admin_jwt`` —
the dependency that gates every /admin/* endpoint must re-check live
allowlist membership on each authenticated request.  Without this
re-check, an admin removed from ``POPULIS_ADMIN_PUBKEY_ALLOWLIST``
retains full authority for as long as their JWT signature verifies
(which is the entire process lifetime, since the secret doesn't
change on a config-only rotation).

Threat: an admin pubkey is compromised; the operator removes it from
``POPULIS_ADMIN_PUBKEY_ALLOWLIST`` (config reload, no restart); the
compromised holder calls ``/admin/auth/refresh`` every <15 min
indefinitely and retains money authority over /admin/mint/*.

Outcome before the fix: refresh returns 200 with a freshly-minted
JWT for the now-revoked subject.  This test failed.

Outcome after the fix: refresh returns 403 because ``claims.sub`` is
no longer in ``settings.admin_pubkey_allowlist_set()``.  This test
passes.

Origin: derived from the Stage-1 falsifier in
``populis-canon-audit/active/poc/test_admin_refresh_revocation_bypass.py``
documented in
``research/CANON_POPULIS_ADMIN_DESK_AUDIT_2026_04_28.md``.
"""
from __future__ import annotations

import time

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
from fastapi.testclient import TestClient

from populis_api import admin_auth
from populis_api.admin_auth import reset_admin_state_for_tests, verify_jwt
from populis_api.config import Settings, get_settings


# ── Two distinct test keys: one to be revoked, one to stay valid ────────────
_REVOKED_PRIVKEY = (
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)
_REPLACEMENT_PRIVKEY = (
    "0x4646464646464646464646464646464646464646464646464646464646464646"
)
_REVOKED_ACCT = Account.from_key(_REVOKED_PRIVKEY)
_REPLACEMENT_ACCT = Account.from_key(_REPLACEMENT_PRIVKEY)
_REVOKED_ADDR_LOWER = _REVOKED_ACCT.address.lower()
_REPLACEMENT_ADDR_LOWER = _REPLACEMENT_ACCT.address.lower()


@pytest.fixture(autouse=True)
def _reset_admin_state():
    reset_admin_state_for_tests()
    get_settings.cache_clear()
    yield
    reset_admin_state_for_tests()
    get_settings.cache_clear()


def _make_client_with_allowlist(monkeypatch, allowlist: str) -> TestClient:
    """Build a fresh FastAPI test client with a specific allowlist value.

    The allowlist string is whatever value would land in
    ``POPULIS_ADMIN_PUBKEY_ALLOWLIST`` env var.  The JWT secret is
    pinned across rotations so JWTs issued before the rotation can
    still be verified after — this matches how operators actually
    rotate (they edit the allowlist env, restart the env loader, but
    keep the JWT secret stable).
    """
    monkeypatch.setenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", allowlist)
    monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "x" * 64)
    monkeypatch.setenv("POPULIS_ADMIN_JWT_TTL_SECONDS", "900")
    monkeypatch.setenv("POPULIS_ADMIN_LOGIN_PER_IP_PER_MINUTE", "100")
    get_settings.cache_clear()
    app = FastAPI()
    app.include_router(admin_auth.router)
    return TestClient(app)


def _login_as(client: TestClient, acct) -> str:
    """Run the full challenge → sign → login flow and return the JWT."""
    ch = client.post(
        "/admin/auth/challenge",
        json={"owner": acct.address, "auth_type": "evm"},
    )
    assert ch.status_code == 200, ch.text
    typed_data = ch.json()["typed_data"]

    signable = encode_typed_data(full_message=typed_data)
    signed = acct.sign_message(signable)

    body = {
        "owner": acct.address,
        "nonce": ch.json()["nonce"],
        "signature": "0x" + signed.signature.hex().replace("0x", ""),
        "auth_type": "evm",
    }
    login = client.post("/admin/auth/login", json=body)
    assert login.status_code == 200, login.text
    return login.json()["jwt"]


# ════════════════════════════════════════════════════════════════════════════
# B-2: Refresh-without-revocation
# ════════════════════════════════════════════════════════════════════════════

class TestRefreshAfterSelectiveRevocation:
    """Selective revocation (removing a specific admin, keeping list non-empty)
    must terminate the revoked admin's session.
    """

    def test_revoked_admin_cannot_refresh_after_allowlist_rotation(
        self, monkeypatch
    ):
        # ── Phase 1 — admin is allowlisted, logs in, gets JWT ────────────
        client = _make_client_with_allowlist(monkeypatch, _REVOKED_ADDR_LOWER)
        token = _login_as(client, _REVOKED_ACCT)

        # Sanity: the JWT verifies and refresh works while still allowlisted.
        sane = client.post(
            "/admin/auth/refresh",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert sane.status_code == 200, "baseline refresh must succeed"

        # ── Phase 2 — operator detects compromise; rotates allowlist ─────
        # The operator removes the revoked address and adds a replacement.
        # The JWT secret is unchanged so existing JWTs remain
        # cryptographically valid (the operator deliberately did NOT
        # restart the API to avoid a service-disruption event).
        monkeypatch.setenv(
            "POPULIS_ADMIN_PUBKEY_ALLOWLIST", _REPLACEMENT_ADDR_LOWER
        )
        get_settings.cache_clear()

        # ── Phase 3 — revoked admin tries to refresh (the attack) ───────
        attack = client.post(
            "/admin/auth/refresh",
            headers={"Authorization": f"Bearer {token}"},
        )

        # FIX expectation: 403, because claims.sub (_REVOKED_ADDR_LOWER) is
        # no longer in settings.admin_pubkey_allowlist_set().
        #
        # Currently observed: 200, because admin_refresh() never checks
        # the allowlist — it trusts the existing JWT and re-mints a new
        # one for the same subject.  The new token verifies under the
        # unchanged JWT secret, so the revoked admin retains full
        # /admin/mint/* authority for another 15 minutes.
        assert attack.status_code == 403, (
            f"BUG: revoked admin {_REVOKED_ADDR_LOWER} successfully refreshed "
            f"their JWT after being removed from the allowlist. "
            f"Response: {attack.status_code} {attack.text}"
        )

    def test_refresh_indefinite_loop_until_process_restart(self, monkeypatch):
        """Worst-case: revoked admin can chain refreshes indefinitely, each
        producing a new JWT that lasts another full TTL.

        Without the fix, the revoked admin's effective session length is
        bounded only by API process uptime, not by the JWT TTL.
        """
        client = _make_client_with_allowlist(monkeypatch, _REVOKED_ADDR_LOWER)
        token = _login_as(client, _REVOKED_ACCT)

        # Rotate the allowlist (revoke).
        monkeypatch.setenv(
            "POPULIS_ADMIN_PUBKEY_ALLOWLIST", _REPLACEMENT_ADDR_LOWER
        )
        get_settings.cache_clear()

        # Demonstrate three back-to-back refreshes by the revoked admin.
        # Each returned token is itself usable for the next refresh, so
        # the loop is open-ended.
        for i in range(3):
            time.sleep(1.1)  # ensure iat differs across refreshes
            r = client.post(
                "/admin/auth/refresh",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 403, (
                f"BUG: revoked admin chained refresh #{i + 1} after "
                f"allowlist rotation. Response: {r.status_code} {r.text}"
            )
            # If the bug existed, the new token would be the input to
            # the next refresh.  Capture it to make the chain explicit:
            if r.status_code == 200:
                token = r.json()["jwt"]


class TestRefreshAfterCompleteAllowlistClear:
    """Sanity: clearing the allowlist entirely DOES return 503, because
    ``require_admin_jwt`` short-circuits when the allowlist is empty.

    This test exists to clarify the scope of B-2: the bug is
    *selective* revocation (list non-empty after removal), not
    *complete* revocation.  The complete-clear case is already covered
    by ``test_admin_auth.py::TestRefresh::test_503_when_allowlist_empty``.
    """

    def test_complete_clear_already_blocks_refresh(self, monkeypatch):
        client = _make_client_with_allowlist(monkeypatch, _REVOKED_ADDR_LOWER)
        token = _login_as(client, _REVOKED_ACCT)

        # Clear the allowlist completely.
        monkeypatch.setenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", "")
        get_settings.cache_clear()

        r = client.post(
            "/admin/auth/refresh",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 503, (
            f"complete-clear path should return 503 (admin desk disabled); "
            f"got {r.status_code} {r.text}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Adjunct: confirm the JWT itself remains cryptographically valid
# (this is the primitive the bug rests on — the JWT is still verifiable
# under the unchanged secret, so verify_jwt() never raises)
# ════════════════════════════════════════════════════════════════════════════

class TestJWTRemainsValidPostRevocation:
    """Pure-helper test: ``verify_jwt`` succeeds for a JWT issued before the
    allowlist rotation, because the JWT secret didn't change.  This
    confirms the underlying mechanism: the dependency layer of
    ``require_admin_jwt`` accepts the JWT, and only the missing
    allowlist re-check in ``admin_refresh`` lets the request proceed.
    """

    def test_pre_rotation_jwt_still_verifies(self, monkeypatch):
        client = _make_client_with_allowlist(monkeypatch, _REVOKED_ADDR_LOWER)
        token = _login_as(client, _REVOKED_ACCT)
        s_before = get_settings()
        claims_before = verify_jwt(token, s_before)
        assert claims_before.sub == _REVOKED_ADDR_LOWER

        # Rotate allowlist (same secret).
        monkeypatch.setenv(
            "POPULIS_ADMIN_PUBKEY_ALLOWLIST", _REPLACEMENT_ADDR_LOWER
        )
        get_settings.cache_clear()
        s_after = get_settings()

        # The JWT still verifies cryptographically — only the
        # allowlist-membership invariant has changed, not the signature.
        claims_after = verify_jwt(token, s_after)
        assert claims_after.sub == _REVOKED_ADDR_LOWER

        # And the live allowlist no longer contains the revoked sub.
        assert claims_after.sub not in s_after.admin_pubkey_allowlist_set()
