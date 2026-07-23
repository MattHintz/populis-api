from __future__ import annotations

import pytest
from chia.types.blockchain_format.program import Program

from solslot_puzzles.property_metadata import build_metadata_memos
from solslot_api.metadata_chain_indexer import MetadataChainIndexer
from solslot_api.property_metadata import PropertyDossierV1

from tests.test_collection_store import verified_store


class FakeCoinset:
    def __init__(self, *, anchor_id: bytes, puzzle: Program, solution: Program) -> None:
        self.anchor_hex = "0x" + anchor_id.hex()
        self.parent_hex = "0x" + (b"p" * 32).hex()
        self.puzzle = puzzle
        self.solution = solution

    async def get_coin_record_by_name(self, coin_id: str):
        normalized = "0x" + coin_id.removeprefix("0x").lower()
        if normalized == self.anchor_hex:
            return {
                "confirmed_block_index": 101,
                "spent_block_index": 0,
                "coin": {
                    "parent_coin_info": self.parent_hex,
                    "puzzle_hash": "0x" + (b"h" * 32).hex(),
                    "amount": 1,
                },
            }
        if normalized == self.parent_hex:
            return {
                "confirmed_block_index": 100,
                "spent_block_index": 101,
                "coin": {
                    "parent_coin_info": "0x" + (b"q" * 32).hex(),
                    "puzzle_hash": "0x" + (b"r" * 32).hex(),
                    "amount": 10,
                },
            }
        return None

    async def get_puzzle_and_solution(self, coin_id: str, height: int):
        assert "0x" + coin_id.removeprefix("0x").lower() == self.parent_hex
        assert height == 101
        return {
            "puzzle_reveal": "0x" + bytes(self.puzzle).hex(),
            "solution": "0x" + bytes(self.solution).hex(),
        }


def _published_store():
    store, collection = verified_store()
    store.seal(
        "HARBOR-17",
        expected_revision=collection["revision"],
        actor_subject="0xowner",
    )
    anchor_id = b"a" * 32
    store.record_proposal_publication(
        "HARBOR-17",
        "HARBOR-17-A",
        actor_subject="0xowner",
        proposal_id="proposal-anchor",
        proposal_hash=b"x" * 32,
        proposal_launcher_id=b"l" * 32,
        deed_launcher_id=anchor_id,
        output_coin_id=anchor_id,
        publish_bundle_id="0xbundle",
    )
    dossier = PropertyDossierV1.model_validate(
        store.public_collection("HARBOR-17")["dossier"]
    )
    return store, anchor_id, dossier


def _quoted_create_coin(memos: tuple[bytes, ...]) -> tuple[Program, Program]:
    conditions = [[51, b"h" * 32, 1, list(memos)]]
    return Program.to((1, conditions)), Program.to([])


@pytest.mark.asyncio
async def test_chain_indexer_reconstructs_authoritative_metadata() -> None:
    store, anchor_id, dossier = _published_store()
    try:
        memos = build_metadata_memos(dossier.commitment())
        puzzle, solution = _quoted_create_coin(memos)
        result = await MetadataChainIndexer(
            FakeCoinset(anchor_id=anchor_id, puzzle=puzzle, solution=solution),
            store,
        ).refresh("HARBOR-17")
        assert result["anchorEvidence"][0]["status"] == "CONFIRMED"
        public = store.public_collection("HARBOR-17")
        assert public["verification"]["chainReconstructed"] is True
        assert public["verification"]["verified"] is True
    finally:
        store.close()


@pytest.mark.asyncio
async def test_chain_indexer_rejects_reordered_chunks() -> None:
    store, anchor_id, dossier = _published_store()
    try:
        memos = list(build_metadata_memos(dossier.commitment()))
        memos[1], memos[2] = memos[2], memos[1]
        puzzle, solution = _quoted_create_coin(tuple(memos))
        result = await MetadataChainIndexer(
            FakeCoinset(anchor_id=anchor_id, puzzle=puzzle, solution=solution),
            store,
        ).refresh("HARBOR-17")
        evidence = result["anchorEvidence"][0]
        assert evidence["status"] == "MISMATCH"
        assert "reordered" in evidence["details"]["reason"]
        assert store.public_collection("HARBOR-17")["verification"]["verified"] is False
    finally:
        store.close()
