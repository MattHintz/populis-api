"""Strict browser-facing allowlist for Chia full-node operations."""
from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from .chia_provider import ChiaProvider, ChiaProviderError

router = APIRouter(prefix="/chia", tags=["chia"])

_HEX_32 = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")


def _hex32(value: str, label: str) -> str:
    if not _HEX_32.fullmatch(value):
        raise ValueError(f"{label} must be exactly 32 bytes of hex")
    return "0x" + value.removeprefix("0x").lower()


class EmptyRequest(BaseModel):
    pass


class CoinNameRequest(BaseModel):
    name: str

    @model_validator(mode="after")
    def validate_name(self) -> "CoinNameRequest":
        self.name = _hex32(self.name, "name")
        return self


class CoinNamesRequest(BaseModel):
    coin_name: str

    @model_validator(mode="after")
    def validate_name(self) -> "CoinNamesRequest":
        self.coin_name = _hex32(self.coin_name, "coin_name")
        return self


class CoinRecordRange(BaseModel):
    include_spent_coins: bool = False
    start_height: int | None = Field(None, ge=0)
    end_height: int | None = Field(None, ge=0)

    @model_validator(mode="after")
    def validate_range(self) -> "CoinRecordRange":
        if (
            self.start_height is not None
            and self.end_height is not None
            and self.end_height < self.start_height
        ):
            raise ValueError("end_height must not precede start_height")
        return self


class PuzzleHashesRequest(CoinRecordRange):
    puzzle_hashes: list[str] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_hashes(self) -> "PuzzleHashesRequest":
        self.puzzle_hashes = [
            _hex32(value, f"puzzle_hashes[{index}]")
            for index, value in enumerate(self.puzzle_hashes)
        ]
        return self


class ParentIdsRequest(CoinRecordRange):
    parent_ids: list[str] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_ids(self) -> "ParentIdsRequest":
        self.parent_ids = [
            _hex32(value, f"parent_ids[{index}]")
            for index, value in enumerate(self.parent_ids)
        ]
        return self


class HintRequest(CoinRecordRange):
    hint: str

    @model_validator(mode="after")
    def validate_hint(self) -> "HintRequest":
        self.hint = _hex32(self.hint, "hint")
        return self


class PuzzleSolutionRequest(BaseModel):
    coin_id: str
    height: int | None = Field(None, ge=0)
    height_at_spend: int | None = Field(None, ge=0)

    @model_validator(mode="after")
    def validate_request(self) -> "PuzzleSolutionRequest":
        self.coin_id = _hex32(self.coin_id, "coin_id")
        values = [value for value in (self.height, self.height_at_spend) if value is not None]
        if len(values) != 1:
            raise ValueError("provide exactly one of height or height_at_spend")
        return self

    def effective_height(self) -> int:
        value = self.height if self.height is not None else self.height_at_spend
        assert value is not None
        return value


class PushTransactionRequest(BaseModel):
    spend_bundle: dict[str, Any]

    @model_validator(mode="after")
    def validate_bundle_shape(self) -> "PushTransactionRequest":
        coin_spends = self.spend_bundle.get(
            "coin_spends", self.spend_bundle.get("coinSpends")
        )
        if not isinstance(coin_spends, list) or not 1 <= len(coin_spends) <= 100:
            raise ValueError("spend_bundle must contain between 1 and 100 coin spends")
        signature = self.spend_bundle.get(
            "aggregated_signature",
            self.spend_bundle.get("aggregatedSignature"),
        )
        if not isinstance(signature, str) or len(signature.removeprefix("0x")) != 192:
            raise ValueError("spend_bundle aggregated signature must be 96 bytes")
        return self


def _provider(request: Request) -> ChiaProvider:
    provider = getattr(request.app.state, "coinset", None)
    if not isinstance(provider, ChiaProvider):
        raise HTTPException(status_code=503, detail="Chia provider is unavailable")
    return provider


async def _serve(call: Any) -> Any:
    try:
        return await call
    except ChiaProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/get_blockchain_state")
async def get_blockchain_state(_: EmptyRequest, request: Request) -> dict[str, Any]:
    return await _serve(_provider(request).get_blockchain_state())


@router.post("/get_network_info")
async def get_network_info(_: EmptyRequest, request: Request) -> dict[str, Any]:
    return await _serve(_provider(request).get_network_info())


@router.post("/get_coin_record_by_name")
async def get_coin_record_by_name(
    body: CoinNameRequest, request: Request
) -> dict[str, Any]:
    record = await _serve(_provider(request).get_coin_record_by_name(body.name))
    return {"success": True, "coin_record": record}


@router.post("/get_coin_records_by_puzzle_hashes")
async def get_coin_records_by_puzzle_hashes(
    body: PuzzleHashesRequest, request: Request
) -> dict[str, Any]:
    records = await _serve(
        _provider(request).get_coin_records_by_puzzle_hashes(
            body.puzzle_hashes,
            include_spent=body.include_spent_coins,
            start_height=body.start_height,
            end_height=body.end_height,
        )
    )
    return {"success": True, "coin_records": records}


@router.post("/get_coin_records_by_hint")
async def get_coin_records_by_hint(
    body: HintRequest, request: Request
) -> dict[str, Any]:
    records = await _serve(
        _provider(request).get_coin_records_by_hint(
            body.hint,
            include_spent=body.include_spent_coins,
            start_height=body.start_height,
            end_height=body.end_height,
        )
    )
    return {"success": True, "coin_records": records}


@router.post("/get_coin_records_by_parent_ids")
async def get_coin_records_by_parent_ids(
    body: ParentIdsRequest, request: Request
) -> dict[str, Any]:
    records = await _serve(
        _provider(request).get_coin_records_by_parent_ids(
            body.parent_ids,
            include_spent=body.include_spent_coins,
        )
    )
    return {"success": True, "coin_records": records}


@router.post("/get_puzzle_and_solution")
async def get_puzzle_and_solution(
    body: PuzzleSolutionRequest, request: Request
) -> dict[str, Any]:
    solution = await _serve(
        _provider(request).get_puzzle_and_solution(
            body.coin_id, body.effective_height()
        )
    )
    return {"success": True, "coin_solution": solution}


@router.post("/get_mempool_items_by_coin_name")
async def get_mempool_items_by_coin_name(
    body: CoinNamesRequest, request: Request
) -> dict[str, Any]:
    items = await _serve(
        _provider(request).get_mempool_items_by_coin_name(body.coin_name)
    )
    return {"success": True, "mempool_items": items}


@router.post("/push_tx")
async def push_tx(
    body: PushTransactionRequest, request: Request
) -> dict[str, Any]:
    return await _serve(_provider(request).push_tx(body.spend_bundle))


__all__ = ["router"]
