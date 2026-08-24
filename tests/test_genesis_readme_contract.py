from pathlib import Path

from solslot_api.config import Settings


ROOT = Path(__file__).resolve().parents[1]
RELEASE_TAG = "solslot-v2-alpha-rc27.35-20260823"
RELEASE_BRANCH = "release/testnet-alpha-rc27.35-20260823"


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_official_release_identity_is_consistent() -> None:
    settings = Settings(_env_file=None)

    assert settings.launch_release_tag == RELEASE_TAG
    assert RELEASE_TAG in _read(".env.example")
    assert RELEASE_TAG in _read("GENESIS_README.md")
    assert RELEASE_BRANCH in _read("GENESIS_README.md")
    assert RELEASE_TAG in _read("docs/AUTHORITY_V3_INDEPENDENT_REVIEW.md")
    assert RELEASE_BRANCH in _read("docs/AUTHORITY_V3_INDEPENDENT_REVIEW.md")


def test_genesis_runbook_pins_breaking_v2_contract() -> None:
    text = _read("GENESIS_README.md")
    for required in (
        'schemaVersion: 4',
        'sourceManifestVersion: 4',
        'protocolVersion: "solslot-v2-rc23"',
        "SGT",
        "pool V3",
        "SmartDeed V2",
        "protocol Statutes",
        "retired-coordinate denylist",
        "bootstrap_manifest_v2.json",
    ):
        assert required in text


def test_genesis_runbook_locks_writes_and_minting() -> None:
    text = _read("GENESIS_README.md")
    assert "SOLSLOT_CEREMONY_MODE_ENABLED=true" in text
    assert "SOLSLOT_ALPHA_WRITES_ENABLED=true" in text
    assert "SOLSLOT_MINTING_ENABLED=false" in text
    assert "Write `bootstrap_manifest_v2.json` last" in text
    assert "only that exact preserved bundle" in text.lower()
    assert "fresh owner-plus-one signed" in text.lower()
    assert "never build or submit a replacement" in text.lower()


def test_genesis_runbook_requires_complete_credential_smoke() -> None:
    text = _read("GENESIS_README.md")
    assert "fresh EVM vault" in text
    assert "fresh BLS vault" in text
    assert "zkPassport proof" in text
    assert "Coinset confirmation" in text
    assert "synced local primary Chia node" in text
    assert "Attempt replay" in text


def test_security_contract_forbids_browser_and_public_faucet_authority() -> None:
    text = _read("SECURITY.md")
    assert "Browser storage is never an authorization source" in text
    assert "Public enrollment requests cannot spend the faucet" in text
    assert "there is no public signer endpoint" in text


def test_admin_contract_separates_ceremony_and_chain_authority() -> None:
    text = _read("ADMIN_README.md")
    assert "Ceremony Authority" in text
    assert "Chain-Bound Admin Authority" in text
    assert "The only membership source" in text
    assert "ceremony tokens are rejected by post-genesis routes" in text


def test_staging_contract_is_atomic_and_rollbackable() -> None:
    text = _read("docs/STAGING_BACKEND_DEPLOY.md")
    assert "exact 40-character protocol commit" in text
    assert "/opt/solslot/api-staging/releases/<api-sha>-<protocol-prefix>/" in text
    assert ".release-ready" in text
    assert "current` symlink" in text
    assert "five newest releases" in text
    assert "rollback_sha" in text


def test_staging_contract_has_no_public_bridge_autotopup() -> None:
    text = _read("docs/STAGING_BACKEND_DEPLOY.md")
    assert "Public enrollment cannot" in text
    assert "chain-bound admin JWT" in text
    assert "Static parent-ID configuration is not used" in text


def test_staging_contract_pins_server_hardening_boundary() -> None:
    text = _read("docs/STAGING_BACKEND_DEPLOY.md")
    for required in (
        "--host 127.0.0.1",
        "--forwarded-allow-ips 127.0.0.1",
        "--no-server-header",
        "SOLSLOT_API_DOCS_ENABLED=false",
        "SOLSLOT_MAX_REQUEST_BODY_BYTES=4194304",
        "SOLSLOT_REQUEST_TIMEOUT_SECONDS=30",
        "HSTS/security headers",
    ):
        assert required in text
    assert "Do not add `--reload`" in text


def test_zkpassport_contract_uses_chia_as_final_authority() -> None:
    text = _read("docs/ZKPASSPORT_CHIA_VAULT_ATTESTATION.md")
    assert "reserved -> evm_confirmed -> stamp_pending -> chia_confirmed" in text
    assert "current unspent" in text
    assert "Browser storage" in text
    assert "no public signing endpoint" in text


def test_readme_requires_namespace_and_full_tests() -> None:
    text = _read("README.md")
    assert "scripts/check_namespace.py --paths ." in text
    assert ".venv/bin/python -m pytest -q" in text
    assert "Minting remains disabled" in text
