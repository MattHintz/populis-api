from __future__ import annotations

from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "install_validator_host.sh"
UNIT = (
    Path(__file__).parents[1]
    / "ops"
    / "validator"
    / "solslot-validator.service.in"
)


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


def test_install_waits_for_private_listener_before_accepting_release() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "for _ in $(seq 1 30); do" in text
    assert "systemctl is-active --quiet solslot-validator.service" in text
    assert 'ss -ltn | grep -Eq "$wg_ip:9443[[:space:]]"' in text
    assert '[ "$validator_ready" = true ]' in text


def test_installer_requires_and_validates_a_distinct_stripe_read_key() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    unit = UNIT.read_text(encoding="utf-8")

    assert '[ "$#" -eq 9 ] || usage' in text
    assert 'stripe_read_key="$(readlink -f "$9")"' in text
    assert 'load_stripe_read_only_key(settings)' in text
    assert (
        'install -m 0600 "$stripe_read_key" '
        '/etc/solslot-validator/private/stripe.read.key'
    ) in text
    assert (
        "LoadCredential=stripe-read-key:"
        "/etc/solslot-validator/private/stripe.read.key"
    ) in unit
    assert (
        "Environment=SOLSLOT_VALIDATOR_STRIPE_READ_ONLY_KEY_FILE="
        "%d/stripe-read-key"
    ) in unit
