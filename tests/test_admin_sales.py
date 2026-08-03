from __future__ import annotations

import time
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_api.admin_auth import AdminClaims, require_admin_jwt
from solslot_api.admin_sales import router
from solslot_api.config import (
    Settings,
    get_settings,
    validate_server_hardening_at_startup,
)


def _claims() -> AdminClaims:
    now = int(time.time())
    return AdminClaims(sub="0xowner", auth_type="evm", iat=now, exp=now + 300)


def _client(settings: Settings) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[require_admin_jwt] = _claims
    return TestClient(app)


class _Response:
    status_code = 200

    def json(self):
        return {
            "purchaseOperations": [
                {
                    "id": "pi_admin_1",
                    "deliveryKind": "smartdeed",
                    "governanceProposalId": None,
                    "rail": "stripe",
                    "quantity": 1,
                    "vaultLauncherId": "0x" + "11" * 32,
                    "state": "payment_pending",
                    "artifactHash": "sha256:" + "22" * 32,
                    "purchaseId": "0x" + "33" * 32,
                    "artifact": {"schema": "solslot.purchase-artifact.v3"},
                    "settlementEvidence": {
                        "payment_intent_id": "pi_stripe_test"
                    },
                    "createdAt": "2026-08-01 12:00:00",
                    "updatedAt": "2026-08-01 12:00:01",
                    "expiresAt": "2026-08-01 12:25:00",
                }
            ]
        }


class _AsyncClient:
    request: dict | None = None

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, url, *, params, headers):
        type(self).request = {"url": url, "params": params, "headers": headers}
        return _Response()


def test_admin_sales_proxy_uses_internal_credential(monkeypatch) -> None:
    settings = Settings(
        runtime_environment="test",
        purchase_operations_service_url="http://127.0.0.1:5000",
        purchase_operations_token="t" * 32,
    )
    monkeypatch.setattr("solslot_api.admin_sales.httpx.AsyncClient", _AsyncClient)
    client = _client(settings)
    try:
        response = client.get("/admin/sales/purchases?state=payment_pending&limit=25")
        assert response.status_code == 200
        assert response.json()["purchaseOperations"][0]["id"] == "pi_admin_1"
        assert _AsyncClient.request == {
            "url": "http://127.0.0.1:5000/internal/protocol/purchase-operations",
            "params": {"limit": 25, "state": "payment_pending"},
            "headers": {"Authorization": "Bearer " + "t" * 32},
        }
    finally:
        client.close()


def test_admin_sales_proxy_fails_closed_without_internal_configuration() -> None:
    client = _client(Settings(runtime_environment="test"))
    try:
        response = client.get("/admin/sales/purchases")
        assert response.status_code == 503
    finally:
        client.close()


def test_admin_reconcile_rejects_malformed_purchase_id_before_worker_lookup() -> None:
    client = _client(Settings(runtime_environment="test"))
    try:
        response = client.post("/admin/sales/purchases/not-a-purchase/reconcile")
        assert response.status_code == 422
        assert response.json()["detail"] == "purchase ID is invalid"
    finally:
        client.close()


def test_admin_reconcile_advances_only_the_normalized_stored_purchase(
    monkeypatch,
) -> None:
    purchase_id = "0x" + "AB" * 32

    class _Worker:
        reconciled: list[str] = []

        async def reconcile_once(self, value: str):
            self.reconciled.append(value)
            return SimpleNamespace(purchase_id=value)

    class _OutputIndex:
        requested: list[str] = []

        def outputs(self, value: str):
            self.requested.append(value)
            return (SimpleNamespace(coin_id="0x" + "44" * 32),)

    worker = _Worker()
    output_index = _OutputIndex()
    monkeypatch.setattr("solslot_api.admin_sales.StripeDeliveryWorker", _Worker)
    monkeypatch.setattr(
        "solslot_api.admin_sales.get_governed_output_index",
        lambda _path: output_index,
    )
    monkeypatch.setattr(
        "solslot_api.admin_sales.serialize_stripe_delivery",
        lambda _operation, *, governed_outputs: {
            "purchaseId": purchase_id.lower(),
            "state": "DELIVERY_SUBMITTED",
            "governedDeliveryCoinIds": [
                output.coin_id for output in governed_outputs
            ],
        },
    )
    client = _client(Settings(runtime_environment="test"))
    client.app.state.stripe_delivery_worker = worker
    try:
        response = client.post(
            f"/admin/sales/purchases/{purchase_id}/reconcile",
            json={"destination": "0x" + "ff" * 32},
        )
        assert response.status_code == 200
        assert response.json()["state"] == "DELIVERY_SUBMITTED"
        assert response.json()["governedDeliveryCoinIds"] == [
            "0x" + "44" * 32
        ]
        assert worker.reconciled == [purchase_id.lower()]
        assert output_index.requested == [purchase_id.lower()]
    finally:
        client.close()


def test_purchase_operations_configuration_must_be_complete_and_internal() -> None:
    incomplete = Settings(
        runtime_environment="production",
        purchase_operations_service_url="http://127.0.0.1:5000",
    )
    try:
        validate_server_hardening_at_startup(incomplete)
    except RuntimeError as exc:
        assert "require both" in str(exc)
    else:
        raise AssertionError("partial purchase operations configuration was accepted")

    external_cleartext = Settings(
        runtime_environment="production",
        purchase_operations_service_url="http://backend.example.test",
        purchase_operations_token="t" * 32,
    )
    try:
        validate_server_hardening_at_startup(external_cleartext)
    except RuntimeError as exc:
        assert "loopback-only HTTP" in str(exc)
    else:
        raise AssertionError("external cleartext purchase feed was accepted")
