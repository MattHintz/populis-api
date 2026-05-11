from __future__ import annotations

import inspect
from collections.abc import Callable

from fastapi import APIRouter
from fastapi.routing import APIRoute

from populis_api import admin, admin_auth, admin_bootstrap, mint_endpoints
from populis_api.admin import require_admin_token
from populis_api.admin_auth import require_admin_jwt
from populis_api.admin_bootstrap import (
    require_bootstrap_session,
    require_recovery_anchor_handoff_auth,
)


def _api_routes(router: APIRouter) -> list[APIRoute]:
    return [route for route in router.routes if isinstance(route, APIRoute)]


def _route_keys(router: APIRouter) -> set[tuple[str, str]]:
    return {
        (method, route.path)
        for route in _api_routes(router)
        for method in (route.methods or set())
        if method not in {"HEAD", "OPTIONS"}
    }


def _route(router: APIRouter, method: str, path: str) -> APIRoute:
    matches = [
        route
        for route in _api_routes(router)
        if route.path == path and method in (route.methods or set())
    ]
    assert len(matches) == 1
    return matches[0]


def _dependency_calls(route: APIRoute) -> set[Callable[..., object]]:
    calls: set[Callable[..., object]] = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dependant = stack.pop()
        calls.add(dependant.call)
        stack.extend(dependant.dependencies)
    return calls


def test_mint_admin_routes_are_jwt_gated() -> None:
    expected = {
        ("POST", "/admin/mint/propose"),
        ("GET", "/admin/mint"),
        ("GET", "/admin/mint/{proposal_id}"),
        ("POST", "/admin/mint/{proposal_id}/cancel"),
        ("POST", "/admin/mint/{proposal_id}/publish"),
        ("POST", "/admin/mint/{proposal_id}/execute"),
    }

    actual = {
        key
        for key in _route_keys(mint_endpoints.router)
        if key[1].startswith("/admin/mint")
    }

    assert actual == expected
    for method, path in expected:
        calls = _dependency_calls(_route(mint_endpoints.router, method, path))
        assert require_admin_jwt in calls
        assert require_admin_token not in calls


def test_committee_routes_stay_outside_admin_jwt_boundary() -> None:
    expected = {
        ("GET", "/admin/committee/proposals"),
        ("POST", "/admin/committee/vote"),
    }

    actual = {
        key
        for key in _route_keys(mint_endpoints.router)
        if key[1].startswith("/admin/committee")
    }

    assert actual == expected
    for method, path in expected:
        calls = _dependency_calls(_route(mint_endpoints.router, method, path))
        assert require_admin_jwt not in calls
        assert require_admin_token not in calls


def test_admin_auth_refresh_is_the_only_jwt_gated_auth_route() -> None:
    assert _route_keys(admin_auth.router) == {
        ("POST", "/admin/auth/challenge"),
        ("POST", "/admin/auth/login"),
        ("GET", "/admin/auth/authority"),
        ("GET", "/admin/auth/authority_v2"),
        ("POST", "/admin/auth/eip712/compute_leaf_hash"),
        ("POST", "/admin/auth/refresh"),
    }

    jwt_routes = {
        (method, path)
        for method, path in _route_keys(admin_auth.router)
        if require_admin_jwt in _dependency_calls(_route(admin_auth.router, method, path))
    }

    assert jwt_routes == {("POST", "/admin/auth/refresh")}


def test_legacy_protocol_deployment_routes_are_static_token_gated() -> None:
    expected = {
        ("GET", "/admin/deployment"),
        ("POST", "/admin/deploy/protocol"),
    }

    assert _route_keys(admin.router) == expected
    for method, path in expected:
        calls = _dependency_calls(_route(admin.router, method, path))
        assert require_admin_token in calls
        assert require_admin_jwt not in calls


def test_bootstrap_routes_keep_scoped_auth_boundary() -> None:
    assert _route_keys(admin_bootstrap.router) == {
        ("POST", "/admin/bootstrap/challenge"),
        ("GET", "/admin/bootstrap/status"),
        ("POST", "/admin/bootstrap/finalize"),
        ("GET", "/admin/bootstrap/recovery-anchor/publish-intent"),
        ("POST", "/admin/bootstrap/recovery-anchor/create-coin-preview"),
        ("POST", "/admin/bootstrap/recovery-anchor/verify"),
    }

    finalize_calls = _dependency_calls(
        _route(admin_bootstrap.router, "POST", "/admin/bootstrap/finalize")
    )
    assert require_bootstrap_session in finalize_calls
    assert require_admin_jwt not in finalize_calls
    assert require_admin_token not in finalize_calls

    for method, path in {
        ("GET", "/admin/bootstrap/recovery-anchor/publish-intent"),
        ("POST", "/admin/bootstrap/recovery-anchor/create-coin-preview"),
    }:
        calls = _dependency_calls(_route(admin_bootstrap.router, method, path))
        assert require_recovery_anchor_handoff_auth in calls
        assert require_admin_token not in calls

    for method, path in {
        ("GET", "/admin/bootstrap/status"),
        ("POST", "/admin/bootstrap/recovery-anchor/verify"),
    }:
        calls = _dependency_calls(_route(admin_bootstrap.router, method, path))
        assert require_admin_jwt not in calls
        assert require_admin_token not in calls
        assert require_bootstrap_session not in calls

    challenge_source = inspect.getsource(admin_bootstrap.bootstrap_challenge)
    assert "require_admin_token(settings, authorization)" in challenge_source
    assert "require_admin_jwt" not in challenge_source
