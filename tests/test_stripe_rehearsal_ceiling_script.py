from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import sys


SCRIPT = Path(__file__).parents[1] / "scripts" / "check_stripe_rehearsal_ceiling.py"


def _genesis_db(tmp_path: Path, *, state: str = "locked", gate_state: str = "closed") -> Path:
    path = tmp_path / "genesis.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE ceremonies (
                ceremony_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE launch_gates (
                ceremony_id TEXT NOT NULL,
                gate_name TEXT NOT NULL,
                state TEXT NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO ceremonies(ceremony_id,state,created_at) VALUES('rc27',?,1)",
            (state,),
        )
        for gate in ("minting", "presale", "purchases"):
            connection.execute(
                "INSERT INTO launch_gates(ceremony_id,gate_name,state) "
                "VALUES('rc27',?,?)",
                (gate, gate_state),
            )
    return path


def _delivery_db(tmp_path: Path, *operations: tuple[str, str]) -> Path:
    path = tmp_path / "stripe-deliveries.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE stripe_delivery_operations ("
            "purchase_id TEXT PRIMARY KEY,payment_rail TEXT NOT NULL,state TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO stripe_delivery_operations"
            "(purchase_id,payment_rail,state) VALUES(?,?,?)",
            ((f"purchase-{index}", rail, state) for index, (rail, state) in enumerate(operations)),
        )
    return path


def _admin_db(
    tmp_path: Path,
    *vouchers: str,
    refund_authorizations: tuple[str, ...] = (),
) -> Path:
    path = tmp_path / "admin.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE voucher_records_v2 ("
            "serial INTEGER PRIMARY KEY,payment_rail TEXT NOT NULL,state TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE stripe_refund_authorizations_v3 ("
            "authorization_id TEXT PRIMARY KEY,state TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO voucher_records_v2(serial,payment_rail,state) VALUES(?,?,?)",
            (
                (index, "STRIPE_USD", state)
                for index, state in enumerate(vouchers)
            ),
        )
        connection.executemany(
            "INSERT INTO stripe_refund_authorizations_v3(authorization_id,state) "
            "VALUES(?,?)",
            (
                (f"authorization-{index}", state)
                for index, state in enumerate(refund_authorizations)
            ),
        )
    return path


def _run(
    mode: str,
    genesis: Path,
    purchases: Path,
    admin: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--mode",
            mode,
            "--genesis-db",
            str(genesis),
            "--delivery-db",
            str(purchases),
            "--admin-db",
            str(admin),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_arm_requires_locked_genesis(tmp_path: Path) -> None:
    result = _run(
        "arm",
        _genesis_db(tmp_path, state="approving"),
        _delivery_db(tmp_path),
        _admin_db(tmp_path),
    )
    assert result.returncode == 1
    assert "requires a locked genesis" in result.stderr


def test_arm_requires_explicitly_closed_signed_windows(tmp_path: Path) -> None:
    result = _run(
        "arm",
        _genesis_db(tmp_path, gate_state="open"),
        _delivery_db(tmp_path),
        _admin_db(tmp_path),
    )
    assert result.returncode == 1
    assert "must be explicitly closed" in result.stderr


def test_arm_allows_existing_work_so_workers_can_recover(tmp_path: Path) -> None:
    result = _run(
        "arm",
        _genesis_db(tmp_path),
        _delivery_db(tmp_path, ("stripe", "PAYMENT_VERIFIED")),
        _admin_db(
            tmp_path,
            "REDEEMING",
            refund_authorizations=("PENDING",),
        ),
    )
    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["stripeOperations"]["nonterminalCount"] == 1
    assert evidence["stripeVouchers"]["nonterminalCount"] == 2


def test_disarm_blocks_nonterminal_stripe_operations(tmp_path: Path) -> None:
    result = _run(
        "disarm",
        _genesis_db(tmp_path),
        _delivery_db(tmp_path, ("stripe", "MANUAL_REVIEW")),
        _admin_db(tmp_path),
    )
    assert result.returncode == 1
    assert "must remain armed" in result.stderr
    assert "direct:MANUAL_REVIEW=1" in result.stderr


def test_disarm_blocks_nonterminal_voucher_and_refund_authorization(
    tmp_path: Path,
) -> None:
    result = _run(
        "disarm",
        _genesis_db(tmp_path),
        _delivery_db(tmp_path),
        _admin_db(
            tmp_path,
            "ESCROWED",
            refund_authorizations=("PENDING",),
        ),
    )
    assert result.returncode == 1
    assert "voucher:ESCROWED=1" in result.stderr
    assert "refund:PENDING=1" in result.stderr


def test_disarm_allows_only_terminal_stripe_operations(tmp_path: Path) -> None:
    result = _run(
        "disarm",
        _genesis_db(tmp_path),
        _delivery_db(
            tmp_path,
            ("stripe", "FINALIZED"),
            ("base_usdc", "PAYMENT_VERIFIED"),
        ),
        _admin_db(
            tmp_path,
            "REDEEMED",
            "REFUNDED",
            refund_authorizations=("COMPLETED",),
        ),
    )
    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["stripeOperations"]["nonterminalCount"] == 0
    assert evidence["stripeVouchers"]["nonterminalCount"] == 0


def test_missing_purchase_schema_fails_closed(tmp_path: Path) -> None:
    deliveries = tmp_path / "stripe-deliveries.db"
    sqlite3.connect(deliveries).close()
    result = _run(
        "arm",
        _genesis_db(tmp_path),
        deliveries,
        _admin_db(tmp_path),
    )
    assert result.returncode == 1
    assert "required SQLite table is missing" in result.stderr


def test_missing_voucher_schema_fails_closed(tmp_path: Path) -> None:
    admin = tmp_path / "admin.db"
    sqlite3.connect(admin).close()
    result = _run(
        "arm",
        _genesis_db(tmp_path),
        _delivery_db(tmp_path),
        admin,
    )
    assert result.returncode == 1
    assert "required SQLite table is missing" in result.stderr
