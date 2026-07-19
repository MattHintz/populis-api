"""Authoritative reconstruction of collection metadata from Chia solutions."""
from __future__ import annotations

import hashlib
from typing import Any, Optional

from chia.types.blockchain_format.program import Program

from solslot_puzzles.property_metadata import (
    MetadataValidationError,
    reconstruct_metadata_memos,
)

from .coinset_client import CoinsetClient
from .collection_store import CollectionStore
from .property_metadata import PropertyDossierV1


CREATE_COIN = 51


class MetadataIndexError(ValueError):
    pass


class MetadataChainIndexer:
    def __init__(self, coinset: CoinsetClient, store: CollectionStore) -> None:
        self.coinset = coinset
        self.store = store

    async def refresh(self, collection_id: str) -> dict[str, Any]:
        collection = self.store.get(collection_id)
        anchor_hex = collection.get("metadataAnchorId")
        if not anchor_hex:
            raise MetadataIndexError("collection has no published metadata anchor")
        anchor_id = _bytes32(anchor_hex, "metadataAnchorId")
        deed = next(
            (
                item
                for item in collection["deeds"]
                if item.get("deedLauncherId", "").lower() == anchor_hex.lower()
            ),
            None,
        )
        if deed is None:
            raise MetadataIndexError("metadata anchor does not belong to a collection deed")

        anchor_record = await self.coinset.get_coin_record_by_name(anchor_hex)
        if anchor_record is None:
            return self.store.record_anchor_evidence(
                collection_id,
                deed["deedId"],
                anchor_coin_id=anchor_id,
                status="PENDING",
                reconstructed_root=None,
                spend_bundle_id=deed.get("publishBundleId"),
                confirmation_height=None,
                puzzle_solution_hash=None,
                details={"reason": "anchor coin is not confirmed"},
            )
        anchor_coin = _coin_payload(anchor_record)
        confirmed_height = int(anchor_record.get("confirmed_block_index") or 0)
        if confirmed_height <= 0:
            raise MetadataIndexError("Coinset anchor record has no confirmation height")
        parent_id = str(anchor_coin.get("parent_coin_info") or "")
        parent_record = await self.coinset.get_coin_record_by_name(parent_id)
        if parent_record is None:
            raise MetadataIndexError("anchor parent coin record is unavailable")
        spent_height = int(parent_record.get("spent_block_index") or confirmed_height)
        if spent_height <= 0:
            raise MetadataIndexError("anchor parent has no spent height")
        coin_solution = await self.coinset.get_puzzle_and_solution(parent_id, spent_height)
        if coin_solution is None:
            raise MetadataIndexError("anchor parent puzzle solution is unavailable")

        puzzle: Optional[Program] = None
        solution: Optional[Program] = None
        try:
            puzzle = _program(coin_solution, "puzzle_reveal")
            solution = _program(coin_solution, "solution")
            memos = _metadata_memos_for_output(puzzle, solution, anchor_coin)
            commitment = reconstruct_metadata_memos(memos)
            dossier = PropertyDossierV1.model_validate_json(commitment.canonical_json)
            if dossier.collection_id != collection["id"]:
                raise MetadataIndexError("chain dossier collectionId does not match workspace")
            issuance = next(
                (
                    version
                    for version in collection["metadataVersions"]
                    if version["kind"] == "ISSUANCE"
                ),
                None,
            )
            if issuance is None:
                raise MetadataIndexError("collection has no immutable issuance version")
            root_hex = "0x" + commitment.metadata_root.hex()
            status = "CONFIRMED" if root_hex == issuance["metadataRoot"] else "MISMATCH"
            details = {
                "source": "coinset-puzzle-solution",
                "parentCoinId": _normalize_hex(parent_id),
                "memoCount": len(memos),
                "canonicalByteSize": commitment.byte_size,
                "issuanceMetadataRoot": issuance["metadataRoot"],
            }
            reconstructed = bytes(commitment.metadata_root)
        except (MetadataValidationError, MetadataIndexError, ValueError, TypeError) as exc:
            status = "MISMATCH"
            details = {
                "source": "coinset-puzzle-solution",
                "parentCoinId": _normalize_hex(parent_id),
                "reason": str(exc),
            }
            reconstructed = None

        solution_hash = (
            "0x" + hashlib.sha256(bytes(puzzle) + bytes(solution)).hexdigest()
            if puzzle is not None and solution is not None
            else None
        )
        return self.store.record_anchor_evidence(
            collection_id,
            deed["deedId"],
            anchor_coin_id=anchor_id,
            status=status,
            reconstructed_root=reconstructed,
            spend_bundle_id=deed.get("publishBundleId"),
            confirmation_height=confirmed_height,
            puzzle_solution_hash=solution_hash,
            details=details,
        )


def _metadata_memos_for_output(
    puzzle: Program,
    solution: Program,
    output_coin: dict[str, Any],
) -> tuple[bytes, ...]:
    expected_puzzle_hash = _bytes32(str(output_coin.get("puzzle_hash") or ""), "anchor puzzle hash")
    expected_amount = int(output_coin.get("amount"))
    try:
        conditions = puzzle.run(solution).as_python()
    except Exception as exc:
        raise MetadataIndexError(f"cannot execute anchor parent puzzle: {exc}") from exc
    if not isinstance(conditions, list):
        raise MetadataIndexError("anchor parent puzzle did not return a condition list")
    matches: list[tuple[bytes, ...]] = []
    for condition in conditions:
        if not isinstance(condition, list) or len(condition) < 3:
            continue
        opcode = _clvm_int(condition[0])
        if opcode != CREATE_COIN:
            continue
        puzzle_hash = bytes(condition[1])
        amount = _clvm_int(condition[2])
        if puzzle_hash != expected_puzzle_hash or amount != expected_amount:
            continue
        if len(condition) < 4 or not isinstance(condition[3], list):
            raise MetadataIndexError("metadata anchor CREATE_COIN has no memo list")
        memos = tuple(bytes(memo) for memo in condition[3])
        matches.append(memos)
    if len(matches) != 1:
        raise MetadataIndexError(
            f"expected one metadata anchor CREATE_COIN, found {len(matches)}"
        )
    return matches[0]


def _program(payload: dict[str, Any], key: str) -> Program:
    value: Any = payload.get(key)
    if value is None and isinstance(payload.get("coin_solution"), dict):
        value = payload["coin_solution"].get(key)
    if isinstance(value, dict):
        value = value.get("serialized") or value.get("hex")
    if not isinstance(value, str):
        raise MetadataIndexError(f"Coinset solution lacks {key}")
    try:
        return Program.fromhex(value.removeprefix("0x"))
    except ValueError as exc:
        raise MetadataIndexError(f"Coinset {key} is not serialized CLVM") from exc


def _coin_payload(record: dict[str, Any]) -> dict[str, Any]:
    coin = record.get("coin")
    if not isinstance(coin, dict):
        raise MetadataIndexError("Coinset returned a malformed coin record")
    return coin


def _clvm_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, (bytes, bytearray)):
        raise MetadataIndexError("condition integer is malformed")
    raw = bytes(value)
    return int.from_bytes(raw, "big", signed=bool(raw and raw[0] & 0x80))


def _bytes32(value: str, field: str) -> bytes:
    try:
        parsed = bytes.fromhex(value.removeprefix("0x"))
    except ValueError as exc:
        raise MetadataIndexError(f"{field} is not hexadecimal") from exc
    if len(parsed) != 32:
        raise MetadataIndexError(f"{field} must be 32 bytes")
    return parsed


def _normalize_hex(value: str) -> str:
    return "0x" + value.removeprefix("0x").lower()


__all__ = ["MetadataChainIndexer", "MetadataIndexError"]
