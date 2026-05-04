"""Test-suite-wide fixtures for populis_api.

The module-level env masking forces all admin-related env vars to
empty strings (or absent for integer-typed ones) so the operator's
local ``.env`` — which may carry sign-in credentials for portal dev —
doesn't leak into test runs that deliberately exercise the
"admin desk disabled" path.

We mask at module-import time (rather than via an autouse fixture)
because per-test fixtures like ``fresh_settings`` use
``monkeypatch.delenv`` to remove specific keys.  ``delenv`` clears
the env, and Pydantic then falls back to ``.env``.  Pre-emptively
writing empty strings into ``os.environ`` masks ``.env`` even after
``delenv`` runs (because the original value is already empty).

Tests that WANT a specific admin env value still set it via
``monkeypatch.setenv`` — that takes precedence and reverts back to
the empty masked state at test end.
"""
from __future__ import annotations

import os

import pytest


# String-typed admin env vars.  Pre-emptively masked to "" so
# Pydantic ``.env`` fallback can't smuggle a value through any
# combination of ``delenv`` / ``setenv`` per-test setup.
_ADMIN_ENV_STR_KEYS = (
    "POPULIS_ADMIN_PUBKEY_ALLOWLIST",
    "POPULIS_ADMIN_JWT_SECRET",
    "POPULIS_ADMIN_RECORDS_PATH",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_PENDING_OPS_HASH",
)

# Integer-typed admin env vars.  Removed entirely — empty string would
# fail Pydantic int validation, and Pydantic's model defaults are the
# correct "absence" semantics.
_ADMIN_ENV_INT_KEYS = (
    "POPULIS_ADMIN_JWT_TTL_SECONDS",
    "POPULIS_ADMIN_LOGIN_PER_IP_PER_MINUTE",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION",
    "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_VERSION",
)


# ── Module-level env mask (runs once per pytest session) ──────────────
# Apply BEFORE any test imports populis_api.config so the empty values
# baseline persists across monkeypatch save/restore cycles.
for _key in _ADMIN_ENV_STR_KEYS:
    os.environ[_key] = ""
for _key in _ADMIN_ENV_INT_KEYS:
    os.environ.pop(_key, None)


@pytest.fixture(autouse=True)
def _admin_state_reset():
    """Clear cached state between tests so per-test env changes
    actually re-flow through ``get_settings``.

    Without this, a previous test that set
    ``POPULIS_ADMIN_RECORDS_PATH`` (e.g. via monkeypatch) leaves a
    cached Settings instance pointing at the temp file even after
    monkeypatch rolls back — subsequent tests' TestClient lifespan
    sees a stale records_path and fails the boot validator.
    """
    # Clear the @lru_cache around get_settings so the next consumer
    # rebuilds Settings from current env.
    try:
        from populis_api.config import get_settings
        get_settings.cache_clear()
    except ImportError:
        pass

    # Drop the Phase 2.5 mtime-keyed records cache so a temp path
    # from a previous test doesn't survive into the next one.
    try:
        from populis_api.admin_records import clear_admin_records_cache
        clear_admin_records_cache()
    except ImportError:
        pass

    yield

    try:
        from populis_api.config import get_settings
        get_settings.cache_clear()
    except ImportError:
        pass
    try:
        from populis_api.admin_records import clear_admin_records_cache
        clear_admin_records_cache()
    except ImportError:
        pass
