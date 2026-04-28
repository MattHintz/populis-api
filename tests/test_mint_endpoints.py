"""Endpoint tests for ``populis_api.mint_endpoints``.

Mounts only the admin_auth + mint_endpoints routers on a self-contained
FastAPI app to avoid the chia_rs LazyNode threading edges that affect
the full ``populis_api.app`` import.

The login flow is exercised end-to-end via eth_account so the JWT used
in subsequent /admin/mint/* calls is genuinely signed by a real wallet
and the authorization plumbing is validated as a side-effect.
"""
from __future__ import annotations

from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
from fastapi.testclient import TestClient

from populis_api import admin_auth, mint_endpoints
from populis_api.config import get_settings


# ── Test fixtures: deterministic key + address ──────────────────────────────
_TEST_PRIVKEY_HEX = (
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)
_TEST_ACCT = Account.from_key(_TEST_PRIVKEY_HEX)
_TEST_ADDRESS = _TEST_ACCT.address
_TEST_ADDRESS_LOWER = _TEST_ADDRESS.lower()

# A second key for "other operator" tests — derived from a different
# privkey so the recovered address is a known, deterministic value.
_OTHER_PRIVKEY_HEX = (
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
)
_OTHER_ACCT = Account.from_key(_OTHER_PRIVKEY_HEX)
_OTHER_ADDRESS = _OTHER_ACCT.address
_OTHER_ADDRESS_LOWER = _OTHER_ADDRESS.lower()


# ── Fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _reset_module_state():
    admin_auth.reset_admin_state_for_tests()
    mint_endpoints.reset_mint_store_for_tests()
    get_settings.cache_clear()
    yield
    admin_auth.reset_admin_state_for_tests()
    mint_endpoints.reset_mint_store_for_tests()
    get_settings.cache_clear()


@pytest.fixture
def settings_for_admin(monkeypatch, tmp_path):
    # Allow both test operators in the allowlist so we can exercise
    # multi-operator scenarios.
    monkeypatch.setenv(
        "POPULIS_ADMIN_PUBKEY_ALLOWLIST",
        f"{_TEST_ADDRESS_LOWER},{_OTHER_ADDRESS_LOWER}",
    )
    monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "k" * 64)
    monkeypatch.setenv("POPULIS_ADMIN_JWT_TTL_SECONDS", "900")
    monkeypatch.setenv("POPULIS_ADMIN_LOGIN_PER_IP_PER_MINUTE", "100")
    monkeypatch.setenv(
        "POPULIS_ADMIN_DB_PATH",
        str(tmp_path / "admin_proposals.db"),
    )
    get_settings.cache_clear()
    return get_settings()


@pytest.fixture
def app(settings_for_admin) -> FastAPI:
    a = FastAPI()
    a.include_router(admin_auth.router)
    a.include_router(mint_endpoints.router)
    return a


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


# ── Helpers ─────────────────────────────────────────────────────────────────
def _login(client: TestClient, account=_TEST_ACCT) -> str:
    """Perform the full /auth/challenge → /auth/login flow; return the JWT."""
    address = account.address
    ch = client.post(
        "/admin/auth/challenge",
        json={"owner": address, "auth_type": "evm"},
    ).json()
    typed_data = ch["typed_data"]
    signable = encode_typed_data(full_message=typed_data)
    signed = account.sign_message(signable)
    sig = "0x" + signed.signature.hex().replace("0x", "")
    out = client.post(
        "/admin/auth/login",
        json={
            "owner": address, "nonce": ch["nonce"],
            "signature": sig, "auth_type": "evm",
        },
    ).json()
    return out["jwt"]


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _propose_body(*, suffix: int = 0) -> dict[str, Any]:
    return {
        "par_value": 1_000_000_000 + suffix,
        "asset_class": "RWA-RE-RES",
        "property_id": f"US-TX-Travis-{suffix:04d}",
        "jurisdiction": "US-TX-Travis",
        "royalty_puzhash": "0x" + "aa" * 32,
        "royalty_bps": 200,
        "quorum_required": 500_000,
        "off_chain_metadata": {"address": "123 Main St"},
    }


# ── Auth gating ─────────────────────────────────────────────────────────────
class TestAuthGating:
    @pytest.mark.parametrize("path,method", [
        ("/admin/mint",                "GET"),
        ("/admin/mint/anything",       "GET"),
        ("/admin/mint/propose",        "POST"),
        ("/admin/mint/anything/cancel", "POST"),
        ("/admin/mint/anything/publish", "POST"),
        ("/admin/mint/anything/execute", "POST"),
    ])
    def test_admin_paths_require_auth(self, client, path, method):
        # No allowlist member is configured → 503; with allowlist set
        # but no token → 401.  The fixture sets the allowlist, so we
        # expect 401 here.
        resp = client.request(method, path, json={})
        assert resp.status_code in (401, 422), resp.text  # 422 if path-param mismatch

    def test_bad_token_returns_403(self, client):
        resp = client.get("/admin/mint", headers={"Authorization": "Bearer not.a.jwt"})
        assert resp.status_code == 403

    @pytest.mark.parametrize("path,method,expected", [
        # POP-CANON-013: committee endpoints are intentionally public.
        # /committee/proposals is a 200 read; /committee/vote is a 501
        # stub but reachable without admin JWT.
        ("/admin/committee/proposals", "GET",  200),
        ("/admin/committee/vote",      "POST", 501),
    ])
    def test_committee_paths_do_not_require_admin_auth(
        self, client, path, method, expected,
    ):
        resp = client.request(method, path, json={})
        assert resp.status_code == expected, resp.text


# ── Propose ─────────────────────────────────────────────────────────────────
class TestPropose:
    def test_happy_path(self, client):
        token = _login(client)
        resp = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=1),
            headers=_auth_header(token),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["state"] == "DRAFT"
        assert body["par_value"] == 1_000_000_001
        assert body["owner_pubkey"] == _TEST_ADDRESS_LOWER
        # POP-CANON-014: stored property_id is the canonical (upper, stripped) form.
        assert body["property_id"] == "US-TX-TRAVIS-0001"
        # All four computed hashes are None at DRAFT.
        for k in ("smart_deed_inner_puzhash", "eve_inner_puzhash",
                  "deed_full_puzhash", "proposal_hash"):
            assert body["computed"][k] is None

    def test_owner_is_jwt_subject_not_request_body(self, client):
        # The endpoint MUST stamp owner_pubkey from the authenticated
        # JWT, NOT trust any field in the request body.  A.k.a. the
        # frontend should never need to pass it.
        token = _login(client)
        resp = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=2),
            headers=_auth_header(token),
        )
        assert resp.json()["owner_pubkey"] == _TEST_ADDRESS_LOWER

    def test_invalid_royalty_puzhash_400(self, client):
        token = _login(client)
        bad = _propose_body(suffix=3)
        bad["royalty_puzhash"] = "0xaa"  # too short
        resp = client.post(
            "/admin/mint/propose",
            json=bad,
            headers=_auth_header(token),
        )
        assert resp.status_code == 400
        assert "royalty_puzhash" in resp.json()["detail"]

    def test_negative_par_value_rejected(self, client):
        token = _login(client)
        bad = _propose_body(suffix=4)
        bad["par_value"] = 0
        resp = client.post(
            "/admin/mint/propose",
            json=bad,
            headers=_auth_header(token),
        )
        # Pydantic rejects ge=0 violations as 422 before reaching the handler.
        assert resp.status_code == 422

    def test_duplicate_active_property_409(self, client):
        token = _login(client)
        first = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=10),
            headers=_auth_header(token),
        )
        assert first.status_code == 200
        # Same property_id → blocked because the first is still in DRAFT.
        second = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=10),
            headers=_auth_header(token),
        )
        assert second.status_code == 409
        assert "active proposal" in second.json()["detail"]


# ── List + Detail ───────────────────────────────────────────────────────────
class TestListAndDetail:
    def test_list_empty(self, client):
        token = _login(client)
        resp = client.get("/admin/mint", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json() == {"proposals": [], "count": 0}

    def test_list_returns_created(self, client):
        token = _login(client)
        for i in range(3):
            client.post(
                "/admin/mint/propose",
                json=_propose_body(suffix=20 + i),
                headers=_auth_header(token),
            )
        resp = client.get("/admin/mint", headers=_auth_header(token))
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 3
        assert len(body["proposals"]) == 3
        ids = {p["id"] for p in body["proposals"]}
        assert len(ids) == 3

    def test_filter_by_owner(self, client):
        # Operator 1 creates 2, operator 2 creates 1.
        t1 = _login(client, _TEST_ACCT)
        t2 = _login(client, _OTHER_ACCT)
        client.post("/admin/mint/propose", json=_propose_body(suffix=30),
                    headers=_auth_header(t1))
        client.post("/admin/mint/propose", json=_propose_body(suffix=31),
                    headers=_auth_header(t1))
        client.post("/admin/mint/propose", json=_propose_body(suffix=32),
                    headers=_auth_header(t2))

        # ?owner=<addr> must filter to that operator's proposals only.
        resp = client.get(
            f"/admin/mint?owner={_TEST_ADDRESS_LOWER}",
            headers=_auth_header(t1),
        )
        body = resp.json()
        assert all(p["owner_pubkey"] == _TEST_ADDRESS_LOWER for p in body["proposals"])
        assert len(body["proposals"]) == 2

    def test_filter_by_state(self, client):
        token = _login(client)
        client.post("/admin/mint/propose", json=_propose_body(suffix=40),
                    headers=_auth_header(token))
        # All proposals are DRAFT until publish; PROPOSED filter returns 0.
        resp = client.get("/admin/mint?state=PROPOSED", headers=_auth_header(token))
        body = resp.json()
        assert body["count"] == 0

    def test_get_by_id(self, client):
        token = _login(client)
        created = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=50),
            headers=_auth_header(token),
        ).json()
        resp = client.get(f"/admin/mint/{created['id']}", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["id"] == created["id"]

    def test_get_unknown_id_404(self, client):
        token = _login(client)
        resp = client.get("/admin/mint/mp_doesnotexist", headers=_auth_header(token))
        assert resp.status_code == 404

    def test_list_pagination(self, client):
        token = _login(client)
        for i in range(5):
            client.post("/admin/mint/propose",
                        json=_propose_body(suffix=60 + i),
                        headers=_auth_header(token))
        page = client.get("/admin/mint?limit=2&offset=0", headers=_auth_header(token))
        body = page.json()
        assert len(body["proposals"]) == 2
        assert body["count"] == 5  # total ignores pagination

    def test_list_invalid_limit_400(self, client):
        token = _login(client)
        resp = client.get("/admin/mint?limit=0", headers=_auth_header(token))
        assert resp.status_code == 400


# ── Cancel ─────────────────────────────────────────────────────────────────
class TestCancel:
    def test_cancel_own_draft(self, client):
        token = _login(client)
        rec = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=70),
            headers=_auth_header(token),
        ).json()
        resp = client.post(
            f"/admin/mint/{rec['id']}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["state"] == "CANCELED"

    def test_cancel_unknown_id_404(self, client):
        token = _login(client)
        resp = client.post(
            "/admin/mint/mp_doesnotexist/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 404

    def test_cancel_other_operator_403(self, client):
        # Operator 1 creates; operator 2 tries to cancel.
        t1 = _login(client, _TEST_ACCT)
        t2 = _login(client, _OTHER_ACCT)
        rec = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=80),
            headers=_auth_header(t1),
        ).json()
        resp = client.post(
            f"/admin/mint/{rec['id']}/cancel",
            json={},
            headers=_auth_header(t2),
        )
        assert resp.status_code == 403
        assert "original proposer" in resp.json()["detail"]

    def test_cancel_releases_property(self, client):
        # After canceling, the same property_id can be re-proposed.
        token = _login(client)
        rec = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=90),
            headers=_auth_header(token),
        ).json()
        client.post(
            f"/admin/mint/{rec['id']}/cancel",
            json={}, headers=_auth_header(token),
        )
        # Now propose again with the same suffix → same property_id.
        # Should succeed.
        resp = client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=90),
            headers=_auth_header(token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["state"] == "DRAFT"
        assert resp.json()["id"] != rec["id"]


# ── 501 stubs ───────────────────────────────────────────────────────────────
class TestStepBStubs:
    def test_publish_returns_501(self, client):
        token = _login(client)
        resp = client.post(
            "/admin/mint/anything/publish",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 501
        assert "Step B" in resp.json()["detail"]

    def test_execute_returns_501(self, client):
        token = _login(client)
        resp = client.post(
            "/admin/mint/anything/execute",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 501

    def test_committee_vote_returns_501(self, client):
        # POP-CANON-013: no admin JWT required.
        resp = client.post("/admin/committee/vote", json={})
        assert resp.status_code == 501


# ── Committee proposal listing ──────────────────────────────────────────────
class TestCommitteeProposals:
    """POP-CANON-013: committee endpoints are public — no admin JWT required."""

    def test_empty_no_auth(self, client):
        # Hits /admin/committee/proposals without any Authorization header.
        resp = client.get("/admin/committee/proposals")
        assert resp.status_code == 200
        assert resp.json() == {"proposals": [], "count": 0}

    def test_excludes_drafts_no_auth(self, client):
        # Drafts are NOT visible to the committee — only PROPOSED/VOTING.
        # Step A.2 doesn't have a /publish endpoint, so all proposals
        # stay DRAFT and the committee list stays empty.
        token = _login(client)
        client.post(
            "/admin/mint/propose",
            json=_propose_body(suffix=110),
            headers=_auth_header(token),
        )
        # Read committee list anonymously — no auth header.
        resp = client.get("/admin/committee/proposals")
        body = resp.json()
        assert body["count"] == 0
        assert body["proposals"] == []
