from __future__ import annotations

from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "deploy-staging.yml"
)


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_locked_staging_unit_pins_cloudflare_proxy_ranges() -> None:
    text = _workflow_text()

    assert "CLOUDFLARE_PROXY_CIDRS:" in text
    assert "173.245.48.0/20" in text
    assert "2400:cb00::/32" in text
    assert 'Environment="SOLSLOT_TRUSTED_PROXY_CIDRS=$trusted_proxy_cidrs"' in text
    assert "Environment=SOLSLOT_CORS_ORIGINS=https://staging.solslot.com" in text
    assert "Environment=SOLSLOT_VAULT_SESSION_COOKIE_SECURE=true" in text


def test_coordinator_seed_check_targets_material_not_public_tool_names() -> None:
    text = _workflow_text()

    assert "-iname '*validator*seed*'" not in text
    assert "-iname '*.seed'" in text
    assert "SOLSLOT_VALIDATOR_SEED_(FILE|HEX)" in text


def test_release_verification_is_explicitly_fail_closed() -> None:
    text = _workflow_text()

    assert "wait_for_health || return 1" in text
    assert "require_http_code 404" in text
    assert "require_http_code 503" in text
    assert "Coordinator health check timed out after 30 seconds." in text


def test_deploy_and_rollback_are_two_phase_transactions() -> None:
    text = _workflow_text()

    assert 'touch "$release_dir/.release-local-verified"' in text
    assert 'touch "$release_dir/.release-verified"' in text
    assert "Release $rollback_id never passed runtime verification" in text
    assert "Restore previous release after failed public verification" in text
    assert "Restore pre-rollback release after failed public verification" in text
    assert "wait_for_rollback_health || return 1" in text
    assert 'release["apiCommit"] == api_sha' in text
