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

    for brick in ("Brick -1", "Brick 0.1", "Brick 0.2", "Brick 0.3", "Brick 0.4", "Brick 0.5"):
        assert brick in text

    assert "pytest tests/test_genesis_readme_contract.py" in text
    assert "Bootstrap-accessible first-admin launch" in text
    assert "Combined bootstrap manifest" in text
