from __future__ import annotations

from solslot_api.alpha_observability import (
    AlphaBugReportRequest,
    AlphaObservabilityStore,
    AlphaTelemetryRequest,
)


SHA = "a" * 40
HASH = "0x" + "b" * 64


def test_telemetry_is_pseudonymous_and_bounded() -> None:
    store = AlphaObservabilityStore(":memory:")
    event_id = store.telemetry(
        AlphaTelemetryRequest(
            event="VOUCHER_PURCHASE_STARTED",
            correlation_id="corr-alpha-0001",
            release_sha=SHA,
            artifact_hash=HASH,
            rail="VOUCHER_USDC",
            details={"screen": "presale"},
        ),
        "203.0.113.1",
    )
    row = store._conn.execute("SELECT source_ip_hash, details_json FROM alpha_telemetry_events WHERE id=?", (event_id,)).fetchone()
    assert row is not None
    assert row["source_ip_hash"] != "203.0.113.1"
    assert row["details_json"] == '{"screen":"presale"}'


def test_bug_diagnostics_require_explicit_opt_in() -> None:
    store = AlphaObservabilityStore(":memory:")
    report_id = store.report(
        AlphaBugReportRequest(
            category="UI",
            summary="The pending state is unclear",
            description="The portal did not explain which chain confirmation was pending.",
            diagnostics={"browser": "test"},
        ),
        "203.0.113.2",
    )
    row = store._conn.execute("SELECT diagnostics_json, source_ip_hash FROM alpha_bug_reports WHERE id=?", (report_id,)).fetchone()
    assert row is not None
    assert row["diagnostics_json"] == "{}"
    assert row["source_ip_hash"] != "203.0.113.2"
