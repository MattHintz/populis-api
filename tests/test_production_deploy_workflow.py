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
