from __future__ import annotations

import json

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from populis_api import admin_auth, admin_bootstrap
from populis_api.admin_bootstrap import BOOTSTRAP_COOKIE_NAME, BOOTSTRAP_COOKIE_PATH
from populis_api.admin_records import load_admin_records_from_mapping
from populis_api.bootstrap_manifest import (
    BOOTSTRAP_RECOVERY_ANCHOR_TAG,
    canonical_json_bytes,
    content_hash,
)
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
                        "evm_address": "0x" + "aa" * 20,
                        "secp256k1_pubkey": "0x02" + "bb" * 32,
                        "type_hash": H("cc"),
                        "prefix_and_domain_separator": "0x1901" + "dd" * 32,
                    }
                ],
            }
        ],
    }


def admins_hash_for_records(records: dict) -> str:
    config = load_admin_records_from_mapping(records)
    return "0x" + config.compute_admins_hash().hex()


def finalize_payload() -> dict:
    records = admin_records()
    return {
        "admin_records": records,
        "admin_authority_launcher_id": H("88"),
        "admins_hash": admins_hash_for_records(records),
        "mips_root": H("cd"),
        "read_only_api_url": "https://api.populis.example",
        "read_only_coinset_url": "https://coinset.example",
    }


def write_deployment_manifest(bootstrap_manifest_path) -> None:
    bootstrap_manifest_path.with_name("deployment_manifest.json").write_text(
        json.dumps(deployment_manifest()),
        encoding="utf-8",
    )


def admin_authorization_header() -> dict[str, str]:
    token, _ = admin_auth.issue_jwt(
        sub="0x1111111111111111111111111111111111111111",
        auth_type="evm",
        settings=get_settings(),
    )
    return {"Authorization": f"Bearer {token}"}


def resolve_schema(openapi: dict, schema: dict) -> dict:
    ref = schema.get("$ref")
    if ref is None:
        return schema
    prefix = "#/components/schemas/"
    assert ref.startswith(prefix)
    return openapi["components"]["schemas"][ref.removeprefix(prefix)]


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


def test_bootstrap_finalize_rejects_admin_records_that_do_not_match_admins_hash(
    client: TestClient,
    bootstrap_env,
) -> None:
    write_deployment_manifest(bootstrap_env)
    challenge = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert challenge.status_code == 200
    payload = finalize_payload()
    payload["admins_hash"] = H("ff")

    resp = client.post("/admin/bootstrap/finalize", json=payload)

    assert resp.status_code == 400
    detail = resp.json()["detail"].lower()
    assert "admin records validation failed" in detail
    assert "drift" in detail
    assert not bootstrap_env.exists()
    assert not bootstrap_env.with_name("admin_records.json").exists()
    assert not bootstrap_env.with_name("portal_runtime_config.json").exists()


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
        "admins_hash": finalize_payload()["admins_hash"],
        "mips_root": H("cd"),
        "authority_version": 1,
    }
    assert body["portal_runtime_config"]["admin_authority_v2"]["authority_version"] == 1
    assert body["bootstrap_recovery_anchor"] == {
        "version": 1,
        "tag": BOOTSTRAP_RECOVERY_ANCHOR_TAG,
        "network": "testnet11",
        "admin_authority_v2_launcher_id": H("88"),
        "authority_version": 1,
        "bootstrap_manifest_hash": content_hash(body["bootstrap_manifest"]),
        "portal_runtime_config_hash": content_hash(body["portal_runtime_config"]),
        "admin_records_hash": content_hash(admin_records()),
    }
    admin_records_path = bootstrap_env.with_name("admin_records.json")
    runtime_path = bootstrap_env.with_name("portal_runtime_config.json")
    recovery_anchor_path = bootstrap_env.with_name("bootstrap_recovery_anchor.json")
    assert json.loads(admin_records_path.read_text()) == admin_records()
    assert json.loads(runtime_path.read_text()) == body["portal_runtime_config"]
    assert json.loads(recovery_anchor_path.read_text()) == body["bootstrap_recovery_anchor"]
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


def test_bootstrap_finalize_openapi_schema_pins_public_artifacts(
    client: TestClient,
) -> None:
    openapi = client.app.openapi()
    response_schema = resolve_schema(
        openapi,
        openapi["paths"]["/admin/bootstrap/finalize"]["post"]["responses"]["200"][
            "content"
        ]["application/json"]["schema"],
    )
    bootstrap_schema = resolve_schema(
        openapi,
        response_schema["properties"]["bootstrap_manifest"],
    )
    runtime_schema = resolve_schema(
        openapi,
        response_schema["properties"]["portal_runtime_config"],
    )
    recovery_anchor_schema = resolve_schema(
        openapi,
        response_schema["properties"]["bootstrap_recovery_anchor"],
    )
    manifest_authority_schema = resolve_schema(
        openapi,
        bootstrap_schema["properties"]["admin_authority_v2"],
    )
    runtime_authority_schema = resolve_schema(
        openapi,
        runtime_schema["properties"]["admin_authority_v2"],
    )

    assert set(response_schema["required"]) == {
        "locked",
        "bootstrap_manifest",
        "portal_runtime_config",
        "bootstrap_recovery_anchor",
    }
    assert {
        "version",
        "network",
        "protocol",
        "admin_authority_v2",
        "artifact_hashes",
    }.issubset(set(bootstrap_schema["required"]))
    assert {
        "version",
        "network",
        "protocol",
        "admin_authority_v2",
    }.issubset(set(runtime_schema["required"]))
    assert {
        "launcher_id",
        "admins_hash",
        "mips_root",
        "authority_version",
    }.issubset(set(manifest_authority_schema["required"]))
    assert {
        "launcher_id",
        "admins_hash",
        "mips_root",
        "authority_version",
        "admin_records_hash",
    }.issubset(set(runtime_authority_schema["required"]))
    assert {
        "version",
        "tag",
        "network",
        "admin_authority_v2_launcher_id",
        "authority_version",
        "bootstrap_manifest_hash",
        "portal_runtime_config_hash",
        "admin_records_hash",
    }.issubset(set(recovery_anchor_schema["required"]))


def test_recovery_anchor_publish_intent_accepts_bootstrap_cookie_after_lock(
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
    assert client.cookies.get(BOOTSTRAP_COOKIE_NAME)

    cookie_auth = client.get("/admin/bootstrap/recovery-anchor/publish-intent")
    static_token = client.get(
        "/admin/bootstrap/recovery-anchor/publish-intent",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    client.cookies.clear()
    missing = client.get("/admin/bootstrap/recovery-anchor/publish-intent")

    assert cookie_auth.status_code == 200
    assert cookie_auth.json()["tag_memo_utf8"] == BOOTSTRAP_RECOVERY_ANCHOR_TAG
    assert missing.status_code == 401
    assert static_token.status_code == 403


def test_recovery_anchor_publish_intent_requires_locked_artifacts(
    client: TestClient,
) -> None:
    resp = client.get(
        "/admin/bootstrap/recovery-anchor/publish-intent",
        headers=admin_authorization_header(),
    )

    assert resp.status_code == 409
    assert "only after bootstrap_manifest.json exists" in resp.json()["detail"]


def test_recovery_anchor_publish_intent_rejects_missing_anchor_after_lock(
    client: TestClient,
    bootstrap_env,
) -> None:
    bootstrap_env.write_text('{"locked": true}', encoding="utf-8")

    resp = client.get(
        "/admin/bootstrap/recovery-anchor/publish-intent",
        headers=admin_authorization_header(),
    )

    assert resp.status_code == 409
    assert "bootstrap_recovery_anchor.json is required" in resp.json()["detail"]


def test_recovery_anchor_publish_intent_returns_json_safe_marker_inputs(
    client: TestClient,
    bootstrap_env,
) -> None:
    write_deployment_manifest(bootstrap_env)
    challenge = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert challenge.status_code == 200
    finalized = client.post("/admin/bootstrap/finalize", json=finalize_payload())
    assert finalized.status_code == 200
    anchor = finalized.json()["bootstrap_recovery_anchor"]
    payload_bytes = canonical_json_bytes(anchor)

    resp = client.get(
        "/admin/bootstrap/recovery-anchor/publish-intent",
        headers=admin_authorization_header(),
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["network"] == "testnet11"
    assert body["marker_coin_amount_mojos"] == 1
    assert body["admin_authority_v2_launcher_id"] == H("88")
    assert body["authority_version"] == 1
    assert body["bootstrap_manifest_hash"] == anchor["bootstrap_manifest_hash"]
    assert body["portal_runtime_config_hash"] == anchor["portal_runtime_config_hash"]
    assert body["admin_records_hash"] == anchor["admin_records_hash"]
    assert body["tag_memo_utf8"] == BOOTSTRAP_RECOVERY_ANCHOR_TAG
    assert body["tag_memo_hex"] == "0x" + BOOTSTRAP_RECOVERY_ANCHOR_TAG.encode(
        "utf-8"
    ).hex()
    assert body["payload_memo_json"] == anchor
    assert body["payload_memo_utf8"] == payload_bytes.decode("utf-8")
    assert body["payload_memo_hex"] == "0x" + payload_bytes.hex()
    assert body["memos_hex"] == [body["tag_memo_hex"], body["payload_memo_hex"]]
    assert body["payload_hash"] == content_hash(anchor)
    emitted = json.dumps(body).lower()
    for forbidden in (
        "bootstrap-secret",
        "populis_bootstrap_session",
        "jwt_secret",
        "private_key",
        "spend_bundle",
        "marker_coin_id",
        "marker_puzzle_hash",
        "parent_coin_id",
        "future_spend",
    ):
        assert forbidden not in emitted


def test_recovery_anchor_publish_intent_openapi_schema_pins_json_safe_handoff(
    client: TestClient,
) -> None:
    openapi = client.app.openapi()
    schema = resolve_schema(
        openapi,
        openapi["paths"]["/admin/bootstrap/recovery-anchor/publish-intent"]["get"][
            "responses"
        ]["200"]["content"]["application/json"]["schema"],
    )

    assert set(schema["required"]) == {
        "network",
        "marker_coin_amount_mojos",
        "admin_authority_v2_launcher_id",
        "authority_version",
        "bootstrap_manifest_hash",
        "portal_runtime_config_hash",
        "admin_records_hash",
        "tag_memo_utf8",
        "tag_memo_hex",
        "payload_memo_json",
        "payload_memo_utf8",
        "payload_memo_hex",
        "memos_hex",
        "payload_hash",
    }
    assert "spend_bundle" not in schema["properties"]
    assert "marker_coin_id" not in schema["properties"]
    assert "marker_puzzle_hash" not in schema["properties"]


def test_recovery_anchor_create_coin_preview_accepts_bootstrap_cookie_after_lock(
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
    assert client.cookies.get(BOOTSTRAP_COOKIE_NAME)

    cookie_auth = client.post(
        "/admin/bootstrap/recovery-anchor/create-coin-preview",
        json={"marker_puzzle_hash": H("ef")},
    )
    static_token = client.post(
        "/admin/bootstrap/recovery-anchor/create-coin-preview",
        json={"marker_puzzle_hash": H("ef")},
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    client.cookies.clear()
    missing = client.post(
        "/admin/bootstrap/recovery-anchor/create-coin-preview",
        json={"marker_puzzle_hash": H("ef")},
    )

    assert cookie_auth.status_code == 200
    assert cookie_auth.json()["condition_opcode"] == 51
    assert missing.status_code == 401
    assert static_token.status_code == 403


def test_recovery_anchor_create_coin_preview_returns_json_safe_condition(
    client: TestClient,
    bootstrap_env,
) -> None:
    write_deployment_manifest(bootstrap_env)
    challenge = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert challenge.status_code == 200
    finalized = client.post("/admin/bootstrap/finalize", json=finalize_payload())
    assert finalized.status_code == 200
    anchor = finalized.json()["bootstrap_recovery_anchor"]
    payload_memo_hex = "0x" + canonical_json_bytes(anchor).hex()
    tag_memo_hex = "0x" + BOOTSTRAP_RECOVERY_ANCHOR_TAG.encode("utf-8").hex()

    resp = client.post(
        "/admin/bootstrap/recovery-anchor/create-coin-preview",
        json={"marker_puzzle_hash": "EF" * 32},
        headers=admin_authorization_header(),
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["condition_opcode"] == 51
    assert body["marker_puzzle_hash"] == H("ef")
    assert body["marker_coin_amount_mojos"] == 1
    assert body["tag_memo_hex"] == tag_memo_hex
    assert body["payload_memo_hex"] == payload_memo_hex
    assert body["memos_hex"] == [tag_memo_hex, payload_memo_hex]
    assert body["condition_hex"] == [51, H("ef"), 1, [tag_memo_hex, payload_memo_hex]]
    assert body["payload_hash"] == content_hash(anchor)
    emitted = json.dumps(body).lower()
    for forbidden in (
        "bootstrap-secret",
        "populis_bootstrap_session",
        "jwt_secret",
        "private_key",
        "spend_bundle",
        "marker_coin_id",
        "parent_coin_id",
        "future_spend",
        "wallet_signature",
    ):
        assert forbidden not in emitted


def test_recovery_anchor_create_coin_preview_rejects_bad_marker_puzzle_hash(
    client: TestClient,
    bootstrap_env,
) -> None:
    write_deployment_manifest(bootstrap_env)
    challenge = client.post(
        "/admin/bootstrap/challenge",
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert challenge.status_code == 200
    finalized = client.post("/admin/bootstrap/finalize", json=finalize_payload())
    assert finalized.status_code == 200

    resp = client.post(
        "/admin/bootstrap/recovery-anchor/create-coin-preview",
        json={"marker_puzzle_hash": "0x1234"},
        headers=admin_authorization_header(),
    )

    assert resp.status_code == 400
    assert "marker_puzzle_hash" in resp.json()["detail"]


def test_recovery_anchor_create_coin_preview_openapi_schema_pins_preview_handoff(
    client: TestClient,
) -> None:
    openapi = client.app.openapi()
    operation = openapi["paths"]["/admin/bootstrap/recovery-anchor/create-coin-preview"][
        "post"
    ]
    request_schema = resolve_schema(
        openapi,
        operation["requestBody"]["content"]["application/json"]["schema"],
    )
    response_schema = resolve_schema(
        openapi,
        operation["responses"]["200"]["content"]["application/json"]["schema"],
    )

    assert set(request_schema["required"]) == {"marker_puzzle_hash"}
    assert set(response_schema["required"]) == {
        "condition_opcode",
        "marker_puzzle_hash",
        "marker_coin_amount_mojos",
        "tag_memo_hex",
        "payload_memo_hex",
        "memos_hex",
        "condition_hex",
        "payload_hash",
    }
    assert "spend_bundle" not in response_schema["properties"]
    assert "marker_coin_id" not in response_schema["properties"]
    assert "parent_coin_id" not in response_schema["properties"]
    assert "future_spend" not in response_schema["properties"]


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
