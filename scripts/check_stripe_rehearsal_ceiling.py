#!/usr/bin/env python3
"""Fail-closed checks for the production Stripe rehearsal ceiling.

This script reads the chain-coordination SQLite stores without migrating or
mutating them. Infrastructure may arm the static Stripe workers only while the
signed customer windows are closed. It may disarm those workers only after the
same windows are closed and every accepted Stripe operation is terminal.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any


_GATE_NAMES = ("minting", "presale", "purchases")
_DIRECT_TERMINAL_STATES = frozenset({"FINALIZED"})
_VOUCHER_TERMINAL_STATES = frozenset({"REFUNDED", "REDEEMED"})
_REFUND_TERMINAL_STATES = frozenset({"COMPLETED"})


class CeilingCheckError(RuntimeError):
    """The requested ceiling transition is not currently safe."""


def _read_only_connection(path: str) -> sqlite3.Connection:
    database = Path(path).expanduser().resolve()
    if not database.is_file():
        raise CeilingCheckError(f"required SQLite store does not exist: {database}")
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def _require_table(connection: sqlite3.Connection, table: str) -> None:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    if row is None:
        raise CeilingCheckError(f"required SQLite table is missing: {table}")


def _closed_launch_gates(genesis_db: str) -> dict[str, Any]:
    with _read_only_connection(genesis_db) as connection:
        _require_table(connection, "ceremonies")
        _require_table(connection, "launch_gates")
        active_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM ceremonies "
                "WHERE state NOT IN ('locked', 'abandoned')"
            ).fetchone()[0]
        )
        if active_count:
            raise CeilingCheckError(
                "Stripe rehearsal requires a locked genesis; "
                f"found {active_count} nonterminal ceremony record(s)"
            )
        ceremony = connection.execute(
            "SELECT ceremony_id,state FROM ceremonies "
            "WHERE state='locked' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if ceremony is None:
            raise CeilingCheckError("Stripe rehearsal requires a locked genesis")
        ceremony_id = str(ceremony["ceremony_id"])
        rows = connection.execute(
            "SELECT gate_name,state FROM launch_gates "
            "WHERE ceremony_id=? "
            "AND gate_name IN ('minting','presale','purchases')",
            (ceremony_id,),
        ).fetchall()

    configured = {str(row["gate_name"]): str(row["state"]) for row in rows}
    unsafe = {
        name: configured[name]
        for name in _GATE_NAMES
        if name in configured and configured[name] not in {"closed", "cancelled"}
    }
    if unsafe:
        states = ", ".join(f"{name}={state}" for name, state in sorted(unsafe.items()))
        raise CeilingCheckError(
            "signed write windows must be explicitly closed before changing "
            f"the Stripe ceiling: {states}"
        )
    return {
        "ceremonyId": ceremony_id,
        "gates": {name: configured.get(name, "not-configured") for name in _GATE_NAMES},
    }


def _stripe_operation_summary(delivery_db: str) -> dict[str, Any]:
    with _read_only_connection(delivery_db) as connection:
        _require_table(connection, "stripe_delivery_operations")
        rows = connection.execute(
            "SELECT state,COUNT(*) AS operation_count "
            "FROM stripe_delivery_operations "
            "WHERE LOWER(payment_rail)='stripe' "
            "GROUP BY state ORDER BY state"
        ).fetchall()
    counts = {str(row["state"]): int(row["operation_count"]) for row in rows}
    nonterminal = {
        state: count
        for state, count in counts.items()
        if state not in _DIRECT_TERMINAL_STATES and count > 0
    }
    return {
        "counts": counts,
        "nonterminal": nonterminal,
        "nonterminalCount": sum(nonterminal.values()),
    }


def _stripe_voucher_summary(admin_db: str) -> dict[str, Any]:
    with _read_only_connection(admin_db) as connection:
        _require_table(connection, "voucher_records_v2")
        _require_table(connection, "stripe_refund_authorizations_v3")
        voucher_rows = connection.execute(
            "SELECT state,COUNT(*) AS operation_count "
            "FROM voucher_records_v2 WHERE payment_rail='STRIPE_USD' "
            "GROUP BY state ORDER BY state"
        ).fetchall()
        refund_rows = connection.execute(
            "SELECT state,COUNT(*) AS operation_count "
            "FROM stripe_refund_authorizations_v3 "
            "GROUP BY state ORDER BY state"
        ).fetchall()
    voucher_counts = {
        str(row["state"]): int(row["operation_count"]) for row in voucher_rows
    }
    refund_counts = {
        str(row["state"]): int(row["operation_count"]) for row in refund_rows
    }
    nonterminal_vouchers = {
        state: count
        for state, count in voucher_counts.items()
        if state not in _VOUCHER_TERMINAL_STATES and count > 0
    }
    nonterminal_refunds = {
        state: count
        for state, count in refund_counts.items()
        if state not in _REFUND_TERMINAL_STATES and count > 0
    }
    return {
        "voucherCounts": voucher_counts,
        "refundAuthorizationCounts": refund_counts,
        "nonterminalVouchers": nonterminal_vouchers,
        "nonterminalRefundAuthorizations": nonterminal_refunds,
        "nonterminalCount": (
            sum(nonterminal_vouchers.values())
            + sum(nonterminal_refunds.values())
        ),
    }


def check_transition(
    *,
    mode: str,
    genesis_db: str,
    delivery_db: str,
    admin_db: str,
) -> dict[str, Any]:
    gates = _closed_launch_gates(genesis_db)
    operations = _stripe_operation_summary(delivery_db)
    vouchers = _stripe_voucher_summary(admin_db)
    if mode == "disarm" and (
        operations["nonterminalCount"] or vouchers["nonterminalCount"]
    ):
        states = [
            *(
                f"direct:{state}={count}"
                for state, count in sorted(operations["nonterminal"].items())
            ),
            *(
                f"voucher:{state}={count}"
                for state, count in sorted(
                    vouchers["nonterminalVouchers"].items()
                )
            ),
            *(
                f"refund:{state}={count}"
                for state, count in sorted(
                    vouchers["nonterminalRefundAuthorizations"].items()
                )
            ),
        ]
        raise CeilingCheckError(
            "Stripe workers must remain armed until every accepted operation is "
            f"terminal: {', '.join(states)}"
        )
    return {
        "ok": True,
        "mode": mode,
        "launch": gates,
        "stripeOperations": operations,
        "stripeVouchers": vouchers,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("arm", "disarm"), required=True)
    parser.add_argument("--genesis-db", required=True)
    parser.add_argument("--delivery-db", required=True)
    parser.add_argument("--admin-db", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = check_transition(
            mode=args.mode,
            genesis_db=args.genesis_db,
            delivery_db=args.delivery_db,
            admin_db=args.admin_db,
        )
    except (CeilingCheckError, sqlite3.Error) as exc:
        print(f"Stripe rehearsal ceiling check failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
