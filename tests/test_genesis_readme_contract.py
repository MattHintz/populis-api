from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_genesis_runbook_pins_breaking_v2_contract() -> None:
    text = _read("GENESIS_README.md")
    for required in (
        'schemaVersion: 2',
        'protocolVersion: "solslot-v2"',
        "SGT",
        "pool V3",
        "SmartDeed V2",
        "retired-coordinate denylist",
        "bootstrap_manifest_v2.json",
    ):
        assert required in text


def test_genesis_runbook_locks_writes_and_minting() -> None:
    text = _read("GENESIS_README.md")
    assert "SOLSLOT_ALPHA_WRITES_ENABLED=false" in text
    assert "SOLSLOT_MINTING_ENABLED=false" in text
    assert "Write `bootstrap_manifest_v2.json` last" in text
    assert "failed ceremony is abandoned" in text.lower() or "partial or ambiguous push ends" in text


def test_genesis_runbook_requires_complete_credential_smoke() -> None:
    text = _read("GENESIS_README.md")
    assert "fresh EVM vault" in text
    assert "fresh BLS vault" in text
    assert "zkPassport proof" in text
    assert "Coinset confirmation" in text
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
    assert "/opt/solslot/api-staging/releases/<sha>/" in text
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
