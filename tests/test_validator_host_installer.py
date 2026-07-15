from __future__ import annotations

from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "install_validator_host.sh"


def test_first_install_does_not_treat_missing_current_link_as_a_release() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert 'if [ -L "$current_link" ]; then' in text
    assert 'previous="$(readlink -f "$current_link" || true)"' in text
    assert '[ "$previous" != "$current_link" ]' in text
    assert 'rm -f "$current_link"' in text


def test_release_tree_is_readable_by_the_isolated_service_account() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert 'chown -R root:solslot-validator "$release_dir"' in text
    assert 'chmod -R u=rwX,g=rX,o= "$release_dir"' in text
