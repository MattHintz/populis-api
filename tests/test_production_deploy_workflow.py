from pathlib import Path


WORKFLOW = Path(".github/workflows/deploy-production.yml")


def test_production_requires_existing_private_chia_tunnel() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "solslot-chia-rpc-tunnel.service" in text
    assert 'systemctl is-active --quiet "$chia_tunnel_service"' in text
    assert "configure_local_chia_provider.sh" in text
    assert "--existing-tls" in text
    assert "After=network-online.target $chia_tunnel_service" in text


def test_production_fails_closed_when_local_node_is_not_primary() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert text.count("/chia/provider-status") >= 2
    assert 'data["activeProvider"] == "local-full-node"' in text
    assert 'data["primaryRequired"] is True' in text
    assert 'data["fallbackActive"] is False' in text


def test_production_installs_locked_stripe_state_and_guided_gate() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "Environment=SOLSLOT_STRIPE_SETTLEMENT_ENABLED=false" in text
    assert "Environment=SOLSLOT_STRIPE_DELIVERY_WORKER_ENABLED=false" in text
    assert "Environment=SOLSLOT_STRIPE_MODE=test" in text
    assert "Environment=SOLSLOT_LAUNCH_CONTROL_ENABLED=true" in text
    assert "Environment=SOLSLOT_PAYMENT_PURCHASE_DB_PATH=$state_dir/" in text
    assert "zz-stripe-test-rehearsal.conf" in text
    manager = Path("scripts/manage_stripe_test_rehearsal_ceiling.sh").read_text(
        encoding="utf-8"
    )
    assert '"SOLSLOT_STRIPE_RESTRICTED_KEY_FILE"' in manager
    assert 'restricted_key.startswith("rk_test_")' in manager
    assert "st_mode & 0o077" in manager


def test_stripe_rehearsal_workflow_never_opens_signed_windows() -> None:
    text = Path(
        ".github/workflows/stripe-test-rehearsal-ceiling.yml"
    ).read_text(encoding="utf-8")
    manager = Path(
        "scripts/manage_stripe_test_rehearsal_ceiling.sh"
    ).read_text(encoding="utf-8")

    assert "STRIPE TEST MODE ONLY" in text
    assert "--action '${{ inputs.action }}'" in text
    assert "gates/purchases/activate" not in text
    assert "gate:purchases" not in manager
    assert "stripeSettlementReady" in manager
    assert "check_stripe_rehearsal_ceiling.py" in manager
    assert "SOLSLOT_STRIPE_MODE=live" not in manager
