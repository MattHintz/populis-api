from __future__ import annotations

from fastapi.routing import APIRoute

from solslot_api.app import app


EXPECTED_OWNER_PLUS_ONE = {
    "/admin/zkpassport/bridge-pool/top-up": "bridge.top-up",
    "/admin/collections/{collection_id}/seal": "collection.seal",
    "/admin/collections/{collection_id}/amendments": "collection.amend",
    "/admin/mint/{proposal_id}/cancel": "mint.cancel",
    "/admin/mint/{proposal_id}/publish": "mint.publish",
    "/admin/mint/{proposal_id}/execute": "mint.execute",
    "/admin/committee/propose": "mint.publish",
    "/admin/committee/execute": "mint.execute",
    "/presales": "presale.create",
    "/presales/{terms_hash}/cancel": "presale.cancel",
    "/presales/{terms_hash}/launch": "presale.launch",
}


def _api_routes(routes):
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        included = getattr(route, "original_router", None)
        if included is not None:
            yield from _api_routes(included.routes)


def test_every_consequential_admin_route_keeps_owner_plus_one_dependency() -> None:
    routes = {
        route.path: route
        for route in _api_routes(app.routes)
        if "POST" in route.methods
    }
    assert set(EXPECTED_OWNER_PLUS_ONE).issubset(routes)

    for path, expected_operation in EXPECTED_OWNER_PLUS_ONE.items():
        markers = [
            getattr(dependency.call, "__solslot_admin_operation__", None)
            for dependency in routes[path].dependant.dependencies
        ]
        assert markers.count(expected_operation) == 1, path
