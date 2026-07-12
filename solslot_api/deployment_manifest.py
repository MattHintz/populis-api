"""Thread-safe validation for the public Solslot V2 deployment manifest.

Request handlers must not import the deployment driver: that module owns CLVM
``Program`` objects whose lazy nodes are tied to the importing thread.  The API
only needs structural validation when reading a frozen ceremony artifact, so
this module deliberately depends on JSON and the standard library alone.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROTOCOL_VERSION = "solslot-v2"
POOL_PUZZLE_VERSION = 3
SMART_DEED_PUZZLE_VERSION = 2

_VERSION_FIELDS = {
    "protocol_version": PROTOCOL_VERSION,
    "pool_puzzle_version": POOL_PUZZLE_VERSION,
    "smart_deed_puzzle_version": SMART_DEED_PUZZLE_VERSION,
}

_HEX_FIELDS = {
    "faucet_inner_puzhash",
    "sgt_genesis_coin_id",
    "pool_genesis_coin_id",
    "did_genesis_coin_id",
    "gov_genesis_coin_id",
    "pool_launcher_id",
    "did_launcher_id",
    "tracker_launcher_id",
    "sgt_tail_hash",
    "sgt_full_puzhash",
    "pool_token_tail_hash",
    "pool_inner_puzhash",
    "pool_full_puzhash",
    "pool_inner_mod_hash",
    "p2_pool_mod_hash",
    "smart_deed_inner_mod_hash",
    "governance_singleton_struct_hash",
    "did_inner_puzhash",
    "did_full_puzhash",
    "tracker_inner_puzhash",
    "tracker_full_puzhash",
}

_REQUIRED_FIELDS = {
    "network",
    "params",
    *_VERSION_FIELDS,
    *_HEX_FIELDS,
}


def load_deployment_manifest(path: Path) -> dict[str, Any]:
    """Read and structurally validate a frozen Solslot V2 manifest."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Deployment manifest root must be a JSON object.")

    missing = _REQUIRED_FIELDS - raw.keys()
    if missing:
        raise ValueError(f"Manifest missing required fields: {sorted(missing)}")

    if raw["network"] not in {"testnet11", "mainnet"}:
        raise ValueError(f"Unsupported network: {raw['network']!r}")
    if not isinstance(raw["params"], dict):
        raise ValueError("Manifest params must be a JSON object.")

    for field, expected in _VERSION_FIELDS.items():
        if raw[field] != expected:
            raise ValueError(
                f"Unsupported or retired {field}: {raw[field]!r}; expected {expected!r}."
            )

    for field in _HEX_FIELDS:
        value = raw[field]
        if (
            not isinstance(value, str)
            or not value.startswith("0x")
            or len(value) != 66
        ):
            raise ValueError(
                f"Manifest field {field} is not a 0x-prefixed 32-byte hex string."
            )
        try:
            decoded = bytes.fromhex(value[2:])
        except ValueError as exc:
            raise ValueError(f"Manifest field {field} is not valid hex.") from exc
        if len(decoded) != 32:
            raise ValueError(f"Manifest field {field} must decode to 32 bytes.")

    return raw


__all__ = [
    "POOL_PUZZLE_VERSION",
    "PROTOCOL_VERSION",
    "SMART_DEED_PUZZLE_VERSION",
    "load_deployment_manifest",
]
