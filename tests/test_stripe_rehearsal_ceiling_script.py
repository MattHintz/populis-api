from __future__ import annotations

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
            "INSERT INTO ceremonies(ceremony_id,state,created_at) VALUES('rc24',?,1)",
            (state,),
        )
        for gate in ("minting", "presale", "purchases"):
            connection.execute(
                "INSERT INTO launch_gates(ceremony_id,gate_name,state) "
                "VALUES('rc24',?,?)",
                (gate, gate_state),
            )
    return path


def _purchase_db(tmp_path: Path, *operations: tuple[str, str]) -> Path:
    path = tmp_path / "purchases.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE purchase_operations_v1 ("
            "purchase_id TEXT PRIMARY KEY,rail TEXT NOT NULL,state TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO purchase_operations_v1(purchase_id,rail,state) VALUES(?,?,?)",
            ((f"purchase-{index}", rail, state) for index, (rail, state) in enumerate(operations)),
        )
    return path


def _run(mode: str, genesis: Path, purchases: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--mode",
            mode,
            "--genesis-db",
            str(genesis),
            "--purchase-db",
            str(purchases),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_arm_requires_locked_genesis(tmp_path: Path) -> None:
    result = _run(
        "arm",
        _genesis_db(tmp_path, state="approving"),
        _purchase_db(tmp_path),
    )
    assert result.returncode == 1
    assert "requires a locked genesis" in result.stderr


def test_arm_requires_explicitly_closed_signed_windows(tmp_path: Path) -> None:
    result = _run(
        "arm",
        _genesis_db(tmp_path, gate_state="open"),
        _purchase_db(tmp_path),
    )
    assert result.returncode == 1
    assert "must be explicitly closed" in result.stderr


def test_arm_allows_existing_work_so_workers_can_recover(tmp_path: Path) -> None:
    result = _run(
        "arm",
        _genesis_db(tmp_path),
        _purchase_db(tmp_path, ("stripe", "PAYMENT_PROCESSING")),
    )
    assert result.returncode == 0, result.stderr
    assert '"nonterminalCount":1' in result.stdout


def test_disarm_blocks_nonterminal_stripe_operations(tmp_path: Path) -> None:
    result = _run(
        "disarm",
        _genesis_db(tmp_path),
        _purchase_db(tmp_path, ("stripe", "REVIEW_REQUIRED")),
    )
    assert result.returncode == 1
    assert "must remain armed" in result.stderr
    assert "REVIEW_REQUIRED=1" in result.stderr


def test_disarm_allows_only_terminal_stripe_operations(tmp_path: Path) -> None:
    result = _run(
        "disarm",
        _genesis_db(tmp_path),
        _purchase_db(
            tmp_path,
            ("stripe", "CANCELED"),
            ("stripe", "REFUNDED"),
            ("stripe", "FINALIZED"),
            ("base_usdc", "PAYMENT_PROCESSING"),
        ),
    )
    assert result.returncode == 0, result.stderr
    assert '"nonterminalCount":0' in result.stdout


def test_missing_purchase_schema_fails_closed(tmp_path: Path) -> None:
    purchases = tmp_path / "purchases.db"
    sqlite3.connect(purchases).close()
    result = _run("arm", _genesis_db(tmp_path), purchases)
    assert result.returncode == 1
    assert "required SQLite table is missing" in result.stderr
