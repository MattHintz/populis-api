"""Deterministic nine-coin funding fan-out for the V2 ceremony."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64


FUNDING_NAMES = (
    "sgt",
    "pool",
    "did",
    "governance",
    "navRegistry",
    "protocolConfig",
    "adminAuthority",
    "vaultVersionRegistry",
    "bridgeBatch",
)
GENESIS_BRIDGE_PARENT_TOTAL = sum(range(1, 33))


@dataclass(frozen=True)
class GenesisFundingFanout:
    plan: dict[str, Any]
    digest: str


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def plan_genesis_funding_fanout(
    *,
    source_coin: Coin,
    faucet_puzzle_hash: bytes32,
    network: str,
    sgt_total_supply: int = 1_000_000,
    fee: int = 0,
) -> GenesisFundingFanout:
    if network != "testnet11":
        raise ValueError("genesis funding fan-out is restricted to testnet11")
    if source_coin.puzzle_hash != faucet_puzzle_hash:
        raise ValueError("source coin does not belong to the configured ceremony faucet")
    if sgt_total_supply <= 0 or fee < 0:
        raise ValueError("SGT supply must be positive and fee must be non-negative")

    minimums = {
        "sgt": sgt_total_supply + fee,
        "pool": 1 + fee,
        "did": 1 + fee,
        "governance": 1 + fee,
        "navRegistry": 1 + fee,
        "protocolConfig": 1 + fee,
        "adminAuthority": 1 + fee,
        "vaultVersionRegistry": 1 + fee,
        "bridgeBatch": GENESIS_BRIDGE_PARENT_TOTAL + fee,
    }
    used: set[int] = set()
    amounts: dict[str, int] = {}
    for name in FUNDING_NAMES:
        amount = minimums[name]
        while amount in used:
            amount += 1
        used.add(amount)
        amounts[name] = amount

    total = sum(amounts.values())
    change = int(source_coin.amount) - total - fee
    if change < 0:
        raise ValueError(
            f"source coin has {int(source_coin.amount)} mojos but fan-out needs {total + fee}"
        )
    source_id = bytes32(source_coin.name())
    outputs = []
    funding_coin_ids: dict[str, str] = {}
    for name in FUNDING_NAMES:
        coin = Coin(source_id, faucet_puzzle_hash, uint64(amounts[name]))
        coin_id = "0x" + bytes(coin.name()).hex()
        funding_coin_ids[name] = coin_id
        outputs.append(
            {
                "name": name,
                "amount": amounts[name],
                "puzzleHash": "0x" + bytes(faucet_puzzle_hash).hex(),
                "coinId": coin_id,
            }
        )
    plan = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "network": network,
        "sourceCoinId": "0x" + bytes(source_id).hex(),
        "sourceAmount": int(source_coin.amount),
        "faucetPuzzleHash": "0x" + bytes(faucet_puzzle_hash).hex(),
        "fee": fee,
        "outputs": outputs,
        "fundingCoinIds": funding_coin_ids,
        "changeAmount": change,
    }
    digest = "0x" + hashlib.sha256(_canonical_json(plan)).hexdigest()
    return GenesisFundingFanout(plan=plan, digest=digest)


__all__ = [
    "FUNDING_NAMES",
    "GENESIS_BRIDGE_PARENT_TOTAL",
    "GenesisFundingFanout",
    "plan_genesis_funding_fanout",
]
