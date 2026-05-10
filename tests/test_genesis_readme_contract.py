from pathlib import Path


README = Path(__file__).resolve().parents[1] / "GENESIS_README.md"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def test_genesis_readme_pins_first_admin_bootstrap_boundary() -> None:
    text = _readme()

    assert "POPULIS_ADMIN_TOKEN` is a bootstrap operator token" in text
    assert "`POST /admin/deploy/protocol` deploys the base protocol stack" in text
    assert "does not create the `admin_authority_v2` singleton" in text
    assert "The first protocol admin cannot be voted in by an existing admin" in text
    assert "must be born at admin-authority genesis as admin slot" in text


def test_genesis_readme_separates_admins_from_pgt_governance() -> None:
    text = _readme()

    assert "PGT holders are committee/governance participants" in text
    assert "separate authority system from admin login" in text
    assert "Later admin/key rotation is self-governed" in text


def test_genesis_readme_has_extreme_atomic_phase_zero_brick_map() -> None:
    text = _readme()

    for brick in ("Brick -1", "Brick 0.1", "Brick 0.2A", "Brick 0.2B", "Brick 0.3", "Brick 0.4", "Brick 0.5"):
        assert brick in text

    assert "pytest tests/test_genesis_readme_contract.py" in text
    assert "Bootstrap-accessible first-admin launch" in text
    assert "Combined bootstrap manifest" in text


def test_genesis_readme_pins_hybrid_bootstrapper_shutdown_model() -> None:
    text = _readme()

    assert "run-once bootstrapper" in text
    assert "hybrid manifest + runtime-config handoff" in text
    assert "`bootstrap_manifest.json`" in text
    assert "`portal_runtime_config.json`" in text
    assert "After the bootstrapper records success, every mutable bootstrap route" in text
    assert "must fail closed" in text
    assert "read-only runtime config" in text


def test_genesis_readme_forbids_runtime_config_secret_injection() -> None:
    text = _readme()

    assert "public coordinates only" in text
    assert "must never contain" in text
    assert "`POPULIS_ADMIN_TOKEN`" in text
    assert "faucet private keys" in text
    assert "JWT secrets" in text
    assert "No permanent admin membership is ever created by frontend env injection" in text


def test_genesis_readme_pins_two_step_bootstrap_challenge_boundary() -> None:
    text = " ".join(_readme().split())

    assert "two-step challenge" in text
    assert "short-lived bootstrap session cookie" in text
    assert "scoped only to bootstrap routes" in text
    assert "never an admin-desk session" in text
    assert "must not authorize mint proposals" in text
    assert "invalidated when the bootstrapper writes a success" in text


def test_genesis_readme_forbids_persisting_raw_bootstrap_token() -> None:
    text = " ".join(_readme().split())

    assert "raw bootstrap token must never be stored" in text
    assert "`localStorage`" in text
    assert "`sessionStorage`" in text
    assert "URLs" in text
    assert "manifests" in text
    assert "downloaded artifacts" in text


def test_genesis_readme_pins_first_admin_wallet_capture_contract() -> None:
    text = " ".join(_readme().split())

    assert "First-admin wallet capture contract" in text
    assert "one-shot wallet signature" in text
    assert "proof-of-possession only" in text
    assert "not an authority artifact" in text
    assert "admin slot `0`" in text
    assert "`m_within`" in text
    assert "network/domain binding" in text
    assert "MIPS root that will govern the initial `admin_authority_v2` state" in text


def test_genesis_readme_pins_initial_admin_records_artifact_shape() -> None:
    text = " ".join(_readme().split())

    assert "durable off-chain admin artifact is `admin_records.json`" in text
    assert '"admin_idx": 0' in text
    assert '"m_within": 1' in text
    assert "`eip712_member` leaf" in text
    for field in (
        "`leaf_hash`",
        "`evm_address`",
        "`secp256k1_pubkey`",
        "`type_hash`",
        "`prefix_and_domain_separator`",
    ):
        assert field in text
    assert "`admins_hash` is computed from the displayed admin records" in text


def test_genesis_readme_forbids_first_admin_artifact_secret_leakage() -> None:
    text = " ".join(_readme().split())

    assert "Neither `admin_records.json`, `bootstrap_manifest.json`, nor `portal_runtime_config.json` may contain" in text
    assert "`POPULIS_ADMIN_TOKEN`" in text
    assert "bootstrap session cookie/JWT" in text
    assert "raw wallet signatures" in text
    assert "auth nonces" in text
    assert "JWT secrets" in text
    assert "faucet private keys" in text
    assert "any bearer credential" in text
