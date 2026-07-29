from __future__ import annotations

from copy import deepcopy

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_api.admin_authority_v3 import (
    build_admin_authority_v3_snapshot,
)
from solslot_puzzles.admin_authority_v3_driver import (
    build_genesis_admin_authority_v3,
)


PARENT_ID = bytes32(b"\x71" * 32)
SOURCE_MANIFEST_HASH = bytes32(b"\x72" * 32)
DAILY_KEYS = tuple(
    keys.PrivateKey(bytes([index]) * 32).public_key.to_compressed_bytes()
    for index in (1, 2, 3)
)
RECOVERY_KEYS = tuple(
    bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
    for index in (4, 5, 6)
)


def _artifact() -> tuple[dict, object]:
    authority = build_genesis_admin_authority_v3(
        parent_coin_id=PARENT_ID,
        network="testnet11",
        daily_compressed_pubkeys=DAILY_KEYS,
        recovery_bls_pubkeys=RECOVERY_KEYS,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )
    artifact = {
        "network": "testnet11",
        "launcherIds": {
            "adminAuthority": "0x" + authority.authority_launcher_id.hex(),
        },
        "puzzleHashes": {
            "adminAuthorityInnerMod": (
                "0x"
                + __import__(
                    "solslot_puzzles.admin_authority_v3_driver",
                    fromlist=["admin_authority_v3_inner_mod_hash"],
                ).admin_authority_v3_inner_mod_hash().hex()
            ),
            "adminAuthorityFull": "0x" + authority.full_puzzle_hash.hex(),
        },
        "adminAuthority": {
            "version": 3,
            "sourceManifestHash": "0x" + SOURCE_MANIFEST_HASH.hex(),
            "operationalMipsRootHash": (
                "0x" + authority.operational_root_hash.hex()
            ),
            "recoveryMipsRootHash": "0x" + authority.recovery_root_hash.hex(),
            "routineDelaySeconds": 86_400,
            "lostKeyDelaySeconds": 604_800,
            "identityVaults": [
                {
                    "slot": identity.slot,
                    "launcherId": "0x" + identity.launcher_id.hex(),
                    "dailyCompressedPubkey": (
                        "0x" + identity.daily_compressed_pubkey.hex()
                    ),
                    "recoveryBlsPubkey": (
                        "0x" + identity.recovery_bls_pubkey.hex()
                    ),
                    "recoveryMemberHash": (
                        "0x" + identity.recovery_member_hash.hex()
                    ),
                    "custodyHash": "0x" + identity.custody_hash.hex(),
                    "fullPuzzleHash": "0x" + identity.full_puzzle_hash.hex(),
                }
                for identity in authority.identity_vaults
            ],
        },
    }
    return artifact, authority


def _record(coin: Coin, *, confirmed: int, spent: int = 0) -> dict:
    return {
        "coin": {
            "parent_coin_info": "0x" + coin.parent_coin_info.hex(),
            "puzzle_hash": "0x" + coin.puzzle_hash.hex(),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": confirmed,
        "spent_block_index": spent,
    }


class _GenesisProvider:
    def __init__(self, authority) -> None:
        launchers = [
            Coin(
                PARENT_ID,
                bytes32(SINGLETON_LAUNCHER_HASH),
                uint64(1),
            ),
            *[
                Coin(
                    PARENT_ID,
                    bytes32(SINGLETON_LAUNCHER_HASH),
                    uint64(identity.launcher_amount),
                )
                for identity in authority.identity_vaults
            ],
        ]
        children = [
            Coin(
                bytes32(launchers[0].name()),
                authority.full_puzzle_hash,
                uint64(1),
            ),
            *[
                Coin(
                    bytes32(launcher.name()),
                    identity.full_puzzle_hash,
                    uint64(identity.launcher_amount),
                )
                for launcher, identity in zip(
                    launchers[1:],
                    authority.identity_vaults,
                    strict=True,
                )
            ],
        ]
        self.records = {
            "0x" + coin.name().hex(): _record(coin, confirmed=100, spent=101)
            for coin in launchers
        }
        self.records.update(
            {
                "0x" + coin.name().hex(): _record(coin, confirmed=101)
                for coin in children
            }
        )

    async def get_coin_record_by_name(self, coin_id: str):
        return self.records.get(coin_id.lower())

    async def get_coin_records_by_parent_ids(
        self,
        parent_ids: list[str],
        *,
        include_spent: bool,
    ):
        del include_spent
        parents = {value.lower() for value in parent_ids}
        return [
            record
            for record in self.records.values()
            if str(record["coin"]["parent_coin_info"]).lower() in parents
        ]

    async def get_puzzle_and_solution(self, coin_id: str, height: int):
        raise AssertionError(
            f"genesis-only fixture should not request {coin_id} at {height}"
        )


@pytest.mark.asyncio
async def test_artifact_snapshot_is_honest_before_chain_launch() -> None:
    artifact, _authority = _artifact()
    snapshot = await build_admin_authority_v3_snapshot(artifact=artifact)
    assert snapshot.enabled is True
    assert snapshot.chain_verified is False
    assert snapshot.authority_rule == "slot0_and_one_of_slot1_slot2"
    assert snapshot.pending is False
    assert snapshot.authority_version == 1
    assert len(snapshot.identities) == 3


@pytest.mark.asyncio
async def test_genesis_lineage_verifies_all_four_singletons() -> None:
    artifact, authority = _artifact()
    snapshot = await build_admin_authority_v3_snapshot(
        artifact=artifact,
        provider=_GenesisProvider(authority),  # type: ignore[arg-type]
    )
    assert snapshot.chain_verified is True
    assert snapshot.current_coin_id is not None
    assert snapshot.evidence["lineageDepth"] == 1
    assert all(identity.live_coin_id for identity in snapshot.identities)


@pytest.mark.asyncio
async def test_chain_puzzle_mismatch_fails_closed() -> None:
    artifact, authority = _artifact()
    provider = _GenesisProvider(authority)
    authority_child = next(
        record
        for record in provider.records.values()
        if record["coin"]["parent_coin_info"]
        == "0x" + authority.authority_launcher_id.hex()
    )
    authority_child["coin"]["puzzle_hash"] = "0x" + "ff" * 32
    with pytest.raises(ValueError, match="genesis puzzle hash mismatches"):
        await build_admin_authority_v3_snapshot(
            artifact=deepcopy(artifact),
            provider=provider,  # type: ignore[arg-type]
        )
