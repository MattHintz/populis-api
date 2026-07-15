#!/usr/bin/env python3
"""Dry-run or explicitly submit the deterministic nine-coin fan-out."""

from __future__ import annotations

import argparse
import asyncio
import json

from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.admin import _build_single_coin_create_bundle
from solslot_api.coinset_client import CoinsetClient
from solslot_api.config import Settings
from solslot_api.faucet import Faucet
from solslot_api.genesis_funding import plan_genesis_funding_fanout


def _faucet(settings: Settings) -> Faucet:
    if settings.faucet_master_sk_hex:
        return Faucet.from_master_private_key_hex(
            settings.faucet_master_sk_hex, settings.network
        )
    if settings.faucet_seed_hex:
        return Faucet.from_seed_hex(settings.faucet_seed_hex, settings.network)
    if settings.faucet_mnemonic:
        return Faucet.from_mnemonic(settings.faucet_mnemonic, settings.network)
    raise SystemExit("A configured existing faucet credential is required.")


def _coin(record: dict) -> Coin:
    fields = record.get("coin") or record
    return Coin(
        bytes32.fromhex(str(fields["parent_coin_info"]).removeprefix("0x")),
        bytes32.fromhex(str(fields["puzzle_hash"]).removeprefix("0x")),
        uint64(int(fields["amount"])),
    )


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare nine distinct confirmed funding coins for Solslot V2 genesis."
    )
    parser.add_argument("--source-coin-id")
    parser.add_argument("--sgt-total-supply", type=int, default=1_000_000)
    parser.add_argument("--fee", type=int, default=0)
    parser.add_argument("--submit", action="store_true")
    parser.add_argument("--confirm-digest")
    args = parser.parse_args()

    settings = Settings()
    if settings.network != "testnet11":
        raise SystemExit("Funding fan-out is restricted to testnet11.")
    faucet = _faucet(settings)
    coinset = CoinsetClient(settings.coinset_base_url)
    try:
        records = await coinset.get_coin_records_by_puzzle_hash(
            "0x" + faucet.address_puzzle_hash.hex(),
            include_spent=False,
        )
        coins = [
            _coin(record)
            for record in records
            if int(record.get("spent_block_index") or 0) == 0
            and int(record.get("confirmed_block_index") or 0) > 0
        ]
        if args.source_coin_id:
            source_id = args.source_coin_id.lower().removeprefix("0x")
            matches = [coin for coin in coins if coin.name().hex() == source_id]
            if len(matches) != 1:
                raise SystemExit("The requested source coin is not confirmed and unspent.")
            source = matches[0]
        else:
            minimum = args.sgt_total_supply + 600 + (args.fee * 10)
            fitting = sorted(
                (coin for coin in coins if int(coin.amount) >= minimum),
                key=lambda coin: int(coin.amount),
            )
            if not fitting:
                raise SystemExit("No confirmed faucet coin is large enough for the fan-out.")
            source = fitting[0]

        fanout = plan_genesis_funding_fanout(
            source_coin=source,
            faucet_puzzle_hash=faucet.address_puzzle_hash,
            network=settings.network,
            sgt_total_supply=args.sgt_total_supply,
            fee=args.fee,
        )
        result = {**fanout.plan, "confirmationDigest": fanout.digest, "submitted": False}
        if not args.submit:
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if not args.source_coin_id:
            raise SystemExit("--submit requires an explicit --source-coin-id.")
        if not args.confirm_digest or args.confirm_digest.lower() != fanout.digest:
            raise SystemExit(
                "--submit requires --confirm-digest equal to the current dry-run digest."
            )
        outputs = [
            (faucet.address_puzzle_hash, int(item["amount"]))
            for item in fanout.plan["outputs"]
        ]
        bundle = _build_single_coin_create_bundle(
            faucet=faucet,
            source_coin=source,
            outputs=outputs,
            change_puzzle_hash=faucet.address_puzzle_hash,
            fee=args.fee,
        )
        response = await coinset.push_tx(bundle.to_json_dict())
        push_status = str(response.get("status") or "").upper()
        if not response.get("success") and push_status not in {"SUCCESS", "PENDING"}:
            raise SystemExit(f"Coinset rejected funding fan-out: {response}")
        result["submitted"] = True
        result["spendBundleId"] = "0x" + bytes(bundle.name()).hex()
        result["pushStatus"] = response
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    finally:
        await coinset.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
