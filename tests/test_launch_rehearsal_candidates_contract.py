from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException

from solslot_api.config import Settings
from solslot_api.presale_endpoints import router, stripe_rehearsal_candidates


TOKEN = "candidate-token-that-is-at-least-32-characters"
VAULT = "0x" + "11" * 32
COLLECTION = "0x" + "22" * 32


class CandidateStore:
    def __init__(self) -> None:
        self.request: dict | None = None

    def stripe_rehearsal_candidates(
        self,
        *,
        created_after: int,
        vault_launcher_id: str,
        collection_id: str,
    ) -> dict:
        self.request = {
            "created_after": created_after,
            "vault_launcher_id": vault_launcher_id,
            "collection_id": collection_id,
        }
        return {
            "schema": "solslot.stripe-voucher-rehearsal-candidates.v1",
            "createdAfter": created_after,
            "vaultLauncherId": vault_launcher_id,
            "collectionId": collection_id,
            "delivery": [],
            "refund": [],
        }


def application(
    *,
    token: str | None = TOKEN,
) -> tuple[FastAPI, CandidateStore, Settings]:
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        protocol_artifact_api_token=token,
    )
    store = CandidateStore()
    app = FastAPI()
    app.include_router(router)
    return app, store, settings


def invoke(
    store: CandidateStore,
    settings: Settings,
    authorization: str | None,
) -> dict:
    return stripe_rehearsal_candidates(
        created_after=1786118400,
        vault_launcher_id=VAULT,
        collection_id=COLLECTION,
        store=store,  # type: ignore[arg-type]
        settings=settings,
        authorization=authorization,
    )


def test_candidates_route_is_mounted_and_requires_the_shared_bearer_token() -> None:
    app, store, settings = application()
    assert "/presales/stripe-rehearsal/candidates" in app.openapi()["paths"]
    with pytest.raises(HTTPException) as missing:
        invoke(store, settings, None)
    assert missing.value.status_code == 401
    with pytest.raises(HTTPException) as incorrect:
        invoke(store, settings, "Bearer wrong")
    assert incorrect.value.status_code == 403

    response = invoke(store, settings, f"Bearer {TOKEN}")
    assert response == {
        "schema": "solslot.stripe-voucher-rehearsal-candidates.v1",
        "createdAfter": 1786118400,
        "vaultLauncherId": VAULT,
        "collectionId": COLLECTION,
        "delivery": [],
        "refund": [],
    }
    assert store.request == {
        "created_after": 1786118400,
        "vault_launcher_id": VAULT,
        "collection_id": COLLECTION,
    }


def test_candidates_route_fails_closed_without_a_configured_token() -> None:
    _app, store, settings = application(token=None)
    with pytest.raises(HTTPException) as unavailable:
        invoke(store, settings, f"Bearer {TOKEN}")
    assert unavailable.value.status_code == 503
    assert store.request is None
