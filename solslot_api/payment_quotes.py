"""Fail-closed loading of H-system oracle rounds for native Chia offers."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import (
    OracleRoundV1,
    PaymentArtifactError,
    oracle_operator_set_root,
    oracle_round_from_json,
    oracle_round_signature_message,
    oracle_round_to_json,
)

from .config import Settings


SNAPSHOT_SCHEMA = "solslot.payment-oracle-snapshots.v1"
MAX_SNAPSHOT_BYTES = 1024 * 1024


class PaymentQuoteError(RuntimeError):
    """Raised when no independently authorized H-system quote is usable."""


@dataclass(frozen=True)
class AuthorizedOracleRound:
    round: OracleRoundV1
    signatures: tuple[dict[str, Any], ...]

    def public_evidence(self) -> dict[str, Any]:
        return {
            "schema": SNAPSHOT_SCHEMA,
            "round": oracle_round_to_json(self.round),
            "signatures": [dict(value) for value in self.signatures],
        }


def load_authorized_oracle_round(
    settings: Settings,
    *,
    asset_id: bytes32,
    now: int,
) -> AuthorizedOracleRound:
    path_value = settings.payment_oracle_rounds_path
    if not path_value:
        raise PaymentQuoteError(
            "SOLSLOT_PAYMENT_ORACLE_ROUNDS_PATH is not configured"
        )
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise PaymentQuoteError("payment oracle snapshot is unavailable")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PaymentQuoteError("payment oracle snapshot cannot be read") from exc
    if size <= 0 or size > MAX_SNAPSHOT_BYTES:
        raise PaymentQuoteError("payment oracle snapshot size is invalid")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PaymentQuoteError("payment oracle snapshot is invalid JSON") from exc
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema",
        "generatedAt",
        "rounds",
    }:
        raise PaymentQuoteError("payment oracle snapshot fields are invalid")
    if payload["schema"] != SNAPSHOT_SCHEMA:
        raise PaymentQuoteError("payment oracle snapshot schema is unsupported")
    if isinstance(payload["generatedAt"], bool) or not isinstance(
        payload["generatedAt"], int
    ):
        raise PaymentQuoteError("payment oracle generatedAt must be an integer")
    raw_rounds = payload["rounds"]
    if not isinstance(raw_rounds, list) or not raw_rounds:
        raise PaymentQuoteError("payment oracle snapshot contains no rounds")

    pubkeys = _configured_operator_pubkeys(settings)
    expected_root = oracle_operator_set_root(pubkeys)
    candidates: list[AuthorizedOracleRound] = []
    for raw in raw_rounds:
        authorized = _parse_authorized_round(
            raw,
            pubkeys=pubkeys,
            expected_root=expected_root,
        )
        if authorized.round.asset_id != asset_id:
            continue
        try:
            authorized.round.assert_live(now)
        except PaymentArtifactError:
            continue
        candidates.append(authorized)
    if not candidates:
        raise PaymentQuoteError(
            "no live, quorum-authorized oracle round exists for this asset"
        )
    candidates.sort(key=lambda item: item.round.sequence, reverse=True)
    if (
        len(candidates) > 1
        and candidates[0].round.sequence == candidates[1].round.sequence
    ):
        raise PaymentQuoteError(
            "payment oracle snapshot contains conflicting active sequences"
        )
    return candidates[0]


def parse_authorized_oracle_round(
    settings: Settings,
    value: Any,
) -> AuthorizedOracleRound:
    """Verify public round evidence without consulting mutable quote state."""

    pubkeys = _configured_operator_pubkeys(settings)
    return _parse_authorized_round(
        value,
        pubkeys=pubkeys,
        expected_root=oracle_operator_set_root(pubkeys),
    )


def _parse_authorized_round(
    value: Any,
    *,
    pubkeys: tuple[bytes, bytes, bytes],
    expected_root: bytes32,
) -> AuthorizedOracleRound:
    if not isinstance(value, Mapping) or set(value) not in (
        {"round", "signatures"},
        {"schema", "round", "signatures"},
    ):
        raise PaymentQuoteError("authorized oracle round fields are invalid")
    if "schema" in value and value["schema"] != SNAPSHOT_SCHEMA:
        raise PaymentQuoteError("authorized oracle round schema is unsupported")
    try:
        round_ = oracle_round_from_json(value["round"])
    except (PaymentArtifactError, TypeError) as exc:
        raise PaymentQuoteError("authorized oracle round is invalid") from exc
    if round_.operator_set_root != expected_root:
        raise PaymentQuoteError(
            "oracle round operator set does not match configured H-system keys"
        )
    raw_signatures = value["signatures"]
    if not isinstance(raw_signatures, list):
        raise PaymentQuoteError("oracle round signatures must be a list")
    message = oracle_round_signature_message(round_.round_hash)
    verified: list[dict[str, Any]] = []
    seen: set[int] = set()
    for raw_signature in raw_signatures:
        if (
            not isinstance(raw_signature, Mapping)
            or set(raw_signature) != {"signerIndex", "signature"}
        ):
            raise PaymentQuoteError("oracle signature fields are invalid")
        index = raw_signature["signerIndex"]
        signature_hex = raw_signature["signature"]
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or index >= len(pubkeys)
            or index in seen
        ):
            raise PaymentQuoteError("oracle signer indices are invalid")
        if (
            not isinstance(signature_hex, str)
            or not signature_hex.startswith("0x")
        ):
            raise PaymentQuoteError("oracle signature must be 0x-prefixed hex")
        try:
            signature = G2Element.from_bytes(
                bytes.fromhex(signature_hex.removeprefix("0x"))
            )
            public_key = G1Element.from_bytes(pubkeys[index])
        except (ValueError, TypeError) as exc:
            raise PaymentQuoteError("oracle signature is malformed") from exc
        if not AugSchemeMPL.verify(public_key, message, signature):
            raise PaymentQuoteError("oracle signature verification failed")
        seen.add(index)
        verified.append(
            {
                "signerIndex": index,
                "signature": "0x" + bytes(signature).hex(),
            }
        )
    if len(verified) < 2:
        raise PaymentQuoteError(
            "oracle round requires two independent operator signatures"
        )
    verified.sort(key=lambda item: item["signerIndex"])
    return AuthorizedOracleRound(round=round_, signatures=tuple(verified))


def _configured_operator_pubkeys(
    settings: Settings,
) -> tuple[bytes, bytes, bytes]:
    values = settings.payment_oracle_operator_pubkeys
    if len(values) != 3:
        raise PaymentQuoteError(
            "SOLSLOT_PAYMENT_ORACLE_OPERATOR_PUBKEYS must contain three keys"
        )
    try:
        pubkeys = tuple(
            bytes.fromhex(value.removeprefix("0x")) for value in values
        )
        oracle_operator_set_root(pubkeys)
    except (ValueError, PaymentArtifactError) as exc:
        raise PaymentQuoteError(
            "payment oracle operator key configuration is invalid"
        ) from exc
    return pubkeys  # type: ignore[return-value]


__all__ = [
    "AuthorizedOracleRound",
    "MAX_SNAPSHOT_BYTES",
    "PaymentQuoteError",
    "SNAPSHOT_SCHEMA",
    "load_authorized_oracle_round",
    "parse_authorized_oracle_round",
]
