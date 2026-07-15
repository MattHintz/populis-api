#!/usr/bin/env python3
"""Create signer 1/2 seeds while retaining signer 0's existing seed."""

from __future__ import annotations

import argparse
import json
import os
import secrets
from pathlib import Path

from chia_rs import AugSchemeMPL
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash


CONFIRMATION = "GENERATE-SOLSLOT-VALIDATOR-SEEDS-1-AND-2"


def _read_seed(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SystemExit("Signer 0 seed file is missing or is a symlink.")
    if path.stat().st_mode & 0o077:
        raise SystemExit("Signer 0 seed file must not be accessible by group/other.")
    try:
        seed = bytes.fromhex(path.read_text(encoding="ascii").strip().removeprefix("0x"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit("Signer 0 seed file is invalid.") from exc
    if len(seed) != 32:
        raise SystemExit("Signer 0 seed file must contain 32 bytes of hex.")
    return seed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signer-zero-seed-file", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"--confirm must equal {CONFIRMATION}")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit("Output directory must be absent or empty.")
    args.output_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(args.output_dir, 0o700)

    seeds = [_read_seed(args.signer_zero_seed_file), secrets.token_bytes(32), secrets.token_bytes(32)]
    private_dir = args.output_dir / "private"
    public_dir = args.output_dir / "public"
    private_dir.mkdir(mode=0o700)
    public_dir.mkdir(mode=0o700)
    keys = [AugSchemeMPL.key_gen(seed) for seed in seeds]
    for index, seed in enumerate(seeds[1:], start=1):
        path = private_dir / f"signer-{index}.seed"
        path.write_text(seed.hex() + "\n", encoding="ascii")
        path.chmod(0o600)
    pubkeys = ["0x" + bytes(key.get_g1()).hex() for key in keys]
    policy = make_bridge_policy_hash([bytes(key.get_g1()) for key in keys], 2)
    roster = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "threshold": 2,
        "pubkeys": pubkeys,
        "bridgePolicyHash": "0x" + bytes(policy).hex(),
        "privateSeedFiles": {
            "signer1": "private/signer-1.seed",
            "signer2": "private/signer-2.seed",
        },
    }
    roster_path = public_dir / "validator-roster.json"
    roster_path.write_text(json.dumps(roster, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    roster_path.chmod(0o600)
    print(str(roster_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
