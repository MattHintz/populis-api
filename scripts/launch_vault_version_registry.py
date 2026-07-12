#!/usr/bin/env python3
"""Operator script: deploy the vault-version registry singleton on testnet11.

Uses the API faucet wallet (SOLSLOT_FAUCET_MASTER_SK_HEX) to fund the launcher
coin. Reads protocol coordinates from .env (admin_authority_v2, bridge policy)
and deployment_manifest_v2.json (pool/tracker launchers). Builds, signs, and pushes
the registry genesis spend bundle.

Usage (from solslot_api/):
  # Inspect the unsigned bundle without broadcasting
  PYTHONPATH=../solslot_protocol .venv/bin/python scripts/launch_vault_version_registry.py --dry-run

  # Build + sign + push to testnet11
  PYTHONPATH=../solslot_protocol .venv/bin/python scripts/launch_vault_version_registry.py

The script prints the registry launcher id, content_hash, and the parent coin it
spent. On success, paste the launcher id into:
  - solslot_api/.env SOLSLOT_VAULT_VERSION_REGISTRY_LAUNCHER_ID
  - solslot_portal/src/environments/environment.ts vaultVersionRegistryLauncherId
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.derive_keys import master_sk_to_wallet_sk_unhardened
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    MOD as P2_MOD,
)
from chia_rs import AugSchemeMPL, PrivateKey, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)

from solslot_api.coinset_client import CoinsetClient
from solslot_api.config import get_settings
from solslot_puzzles.vault_driver import VAULT_INNER_MOD
from solslot_puzzles.vault_version_registry_driver import (
    build_launch_registry_bundle,
    compute_canonical_params_hash,
)


COINSET_URL = "https://testnet11.api.coinset.org"
NETWORK = "testnet11"
AGG_SIG_ME_DATA = bytes.fromhex(
    "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
)
WALLET_INDEX = 0


def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def _load_deployment_manifest(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def _load_env(path: Path) -> dict:
    """Minimal .env parser (no external deps) so the script works without dotenv."""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            env[key] = value
    return env


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and print the bundle but do not push it to testnet11.",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to the .env file with SOLSLOT_FAUCET_MASTER_SK_HEX.",
    )
    parser.add_argument(
        "--manifest",
        default="deployment_manifest_v2.json",
        help="Path to the deployment manifest JSON.",
    )
    parser.add_argument(
        "--fee",
        type=int,
        default=0,
        help="Network fee in mojos (default 0).",
    )
    args = parser.parse_args()

    # Load settings and manifest.
    env = _load_env(Path(args.env_file))
    if not env.get("SOLSLOT_FAUCET_MASTER_SK_HEX"):
        print(f"ERROR: SOLSLOT_FAUCET_MASTER_SK_HEX not found in {args.env_file}")
        return 1

    settings = get_settings()
    master_sk_hex = settings.faucet_master_sk_hex or env.get("SOLSLOT_FAUCET_MASTER_SK_HEX")
    if not master_sk_hex:
        print("ERROR: no faucet master key available")
        return 1

    manifest = _load_deployment_manifest(args.manifest)
    pool_launcher_id = bytes32.fromhex(_strip0x(manifest["pool_launcher_id"]))
    tracker_launcher_id = bytes32.fromhex(_strip0x(manifest["tracker_launcher_id"]))
    admin_authority_launcher_id = bytes32.fromhex(
        _strip0x(settings.protocol_admin_authority_v2_launcher_id or env["SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID"])
    )
    bridge_policy_hash = bytes32.fromhex(_strip0x(settings.zkpassport_bridge_policy_hash))

    vault_inner_mod_hash = bytes32(VAULT_INNER_MOD.get_tree_hash())
    canonical_params_hash = compute_canonical_params_hash(
        pool_singleton_mod_hash=SINGLETON_MOD_HASH,
        pool_launcher_id=pool_launcher_id,
        pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    vault_version = settings.vault_version_registry_version or 1

    print(f"Network               : {NETWORK}")
    print(f"Pool launcher id      : 0x{pool_launcher_id.hex()}")
    print(f"Gov tracker launcher  : 0x{tracker_launcher_id.hex()}")
    print(f"Admin authority v2 id : 0x{admin_authority_launcher_id.hex()}")
    print(f"Bridge policy hash    : 0x{bridge_policy_hash.hex()}")
    print(f"Vault inner mod hash  : 0x{vault_inner_mod_hash.hex()}")
    print(f"Canonical params hash : 0x{canonical_params_hash.hex()}")
    print(f"Vault version         : {vault_version}")
    print()

    # Derive wallet puzzle hash.
    master_sk = PrivateKey.from_bytes(bytes.fromhex(_strip0x(master_sk_hex)))
    wallet_sk = master_sk_to_wallet_sk_unhardened(master_sk, WALLET_INDEX)
    wallet_pk = wallet_sk.get_g1()
    puzzle = P2_MOD.curry(wallet_pk)
    puzzle_hash = bytes32(puzzle.get_tree_hash())

    print(f"Spending wallet ph    : 0x{puzzle_hash.hex()}")

    client = CoinsetClient(COINSET_URL)
    records = await client.get_coin_records_by_puzzle_hash(
        puzzle_hash.hex(), include_spent=False
    )
    unspent = [
        r for r in records
        if r.get("spent_block_index") in (0, None)
    ]
    if not unspent:
        print("ERROR: no unspent coins at spending wallet.")
        await client.close()
        return 1

    # Pick a coin that covers the 1-mojo launcher + fee.
    usable = [r for r in unspent if int(r["coin"]["amount"]) >= 1 + args.fee]
    if not usable:
        print("ERROR: no coin large enough to cover launcher + fee.")
        await client.close()
        return 1
    rec = sorted(usable, key=lambda r: int(r["coin"]["amount"]))[0]
    coin_json = rec["coin"]
    parent_coin = Coin(
        parent_coin_info=bytes32.fromhex(_strip0x(coin_json["parent_coin_info"])),
        puzzle_hash=bytes32.fromhex(_strip0x(coin_json["puzzle_hash"])),
        amount=int(coin_json["amount"]),
    )
    print(f"Spending coin         : 0x{parent_coin.name().hex()} ({parent_coin.amount} mojos)")
    print()

    artifacts = build_launch_registry_bundle(
        parent_coin=parent_coin,
        parent_puzzle=puzzle,
        admin_authority_launcher_id=admin_authority_launcher_id,
        governance_launcher_id=tracker_launcher_id,
        vault_inner_mod_hash=vault_inner_mod_hash,
        canonical_params_hash=canonical_params_hash,
        vault_version=vault_version,
        fee=args.fee,
    )

    print(f"Registry launcher id  : 0x{artifacts.registry_launcher_id.hex()}")
    print(f"Registry full ph      : 0x{artifacts.registry_full_puzzle_hash.hex()}")
    print(f"Registry inner ph     : 0x{artifacts.registry_inner_puzzle_hash.hex()}")
    print(f"Content hash          : 0x{artifacts.content_hash.hex()}")
    print()

    if args.dry_run:
        print("DRY RUN — bundle built but not pushed.")
        print(f"Re-run without --dry-run to broadcast.")
        await client.close()
        return 0

    # Sign the parent spend.
    parent_spend = next(
        s for s in artifacts.unsigned_bundle.coin_spends
        if bytes32(s.coin.name()) == bytes32(parent_coin.name())
    )
    # solution_for_conditions produces [[], delegated_puzzle, 0];
    # the delegated puzzle is the second list element.
    parent_solution = Program.from_bytes(bytes(parent_spend.solution))
    delegated_puzzle = parent_solution.rest().first()
    message = (
        bytes(delegated_puzzle.get_tree_hash())
        + bytes(parent_coin.name())
        + AGG_SIG_ME_DATA
    )
    sig = AugSchemeMPL.sign(wallet_sk, message)
    signed_bundle = SpendBundle(artifacts.unsigned_bundle.coin_spends, sig)

    bundle_json = {
        "coin_spends": [
            {
                "coin": {
                    "parent_coin_info": "0x" + s.coin.parent_coin_info.hex(),
                    "puzzle_hash": "0x" + s.coin.puzzle_hash.hex(),
                    "amount": s.coin.amount,
                },
                "puzzle_reveal": "0x" + bytes(s.puzzle_reveal).hex(),
                "solution": "0x" + bytes(s.solution).hex(),
            }
            for s in signed_bundle.coin_spends
        ],
        "aggregated_signature": "0x" + bytes(sig).hex(),
    }

    print("Pushing spend bundle to testnet11...")
    result = await client.push_tx(bundle_json)
    print(f"Result: {result}")

    if result.get("status") in ("SUCCESS", "PENDING") or result.get("success"):
        print()
        print("=" * 60)
        print("SUCCESS — paste this launcher id into your configs:")
        print(f"  SOLSLOT_VAULT_VERSION_REGISTRY_LAUNCHER_ID=0x{artifacts.registry_launcher_id.hex()}")
        print()
        print("Portal environment.ts:")
        print(f"  vaultVersionRegistryLauncherId: '0x{artifacts.registry_launcher_id.hex()}',")
        print("=" * 60)
    else:
        print(f"ERROR: push_tx failed: {result}")
        await client.close()
        return 1

    await client.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
