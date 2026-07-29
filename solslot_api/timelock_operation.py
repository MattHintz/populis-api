"""Strict decoding for the reviewed two-contract ownership timelock batch."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address


ZERO_BYTES32 = bytes(32)
ACCEPT_OWNERSHIP_CALLDATA = keccak(text="acceptOwnership()")[:4]
SCHEDULE_BATCH_SIGNATURE = (
    "scheduleBatch(address[],uint256[],bytes[],bytes32,bytes32,uint256)"
)
EXECUTE_BATCH_SIGNATURE = (
    "executeBatch(address[],uint256[],bytes[],bytes32,bytes32)"
)
_BATCH_TYPES = ["address[]", "uint256[]", "bytes[]", "bytes32", "bytes32"]
_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


class TimelockOperationError(ValueError):
    """The timelock calldata does not describe the reviewed ownership batch."""


@dataclass(frozen=True)
class OwnershipSchedule:
    targets: tuple[str, str]
    predecessor: bytes
    salt: bytes
    delay_seconds: int
    operation_id: str


def _decode_call(
    value: object,
    *,
    signature: str,
    types: list[str],
    label: str,
) -> tuple[Any, ...]:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]+", value)
        or len(value) % 2 != 0
    ):
        raise TimelockOperationError(f"{label} is invalid")
    raw = bytes.fromhex(value[2:])
    selector = keccak(text=signature)[:4]
    if len(raw) <= 4 or raw[:4] != selector:
        raise TimelockOperationError(f"{label} is invalid")
    try:
        return abi_decode(types, raw[4:])
    except Exception as exc:
        raise TimelockOperationError(f"{label} is invalid") from exc


def _normalize_targets(value: object, label: str) -> tuple[str, str]:
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise TimelockOperationError(
            "ownership timelock batch must contain exactly two targets"
        )
    try:
        targets = tuple(to_checksum_address(str(target)) for target in value)
    except ValueError as exc:
        raise TimelockOperationError(f"{label} contains an invalid address") from exc
    if len(set(target.lower() for target in targets)) != 2:
        raise TimelockOperationError(
            "ownership timelock batch targets must be distinct"
        )
    return targets  # type: ignore[return-value]


def decode_ownership_schedule(
    value: object,
    *,
    expected_operation_id: str,
    label: str = "ownership schedule data",
) -> OwnershipSchedule:
    """Decode and validate the exact 24-hour two-target ownership schedule."""

    (
        raw_targets,
        values,
        payloads,
        predecessor,
        salt,
        delay,
    ) = _decode_call(
        value,
        signature=SCHEDULE_BATCH_SIGNATURE,
        types=[*_BATCH_TYPES, "uint256"],
        label=label,
    )
    targets = _normalize_targets(raw_targets, f"{label}.targets")
    if (
        list(values) != [0, 0]
        or list(payloads)
        != [ACCEPT_OWNERSHIP_CALLDATA, ACCEPT_OWNERSHIP_CALLDATA]
        or predecessor != ZERO_BYTES32
        or delay != 86_400
    ):
        raise TimelockOperationError(
            "ownership timelock schedule terms mismatch"
        )
    if not isinstance(expected_operation_id, str) or not _HASH_RE.fullmatch(
        expected_operation_id
    ):
        raise TimelockOperationError("ownership operation ID is invalid")
    computed_operation_id = "0x" + keccak(
        abi_encode(
            _BATCH_TYPES,
            [
                list(raw_targets),
                list(values),
                list(payloads),
                predecessor,
                salt,
            ],
        )
    ).hex()
    if computed_operation_id.lower() != expected_operation_id.lower():
        raise TimelockOperationError(
            "ownership intent operation ID mismatches"
        )
    return OwnershipSchedule(
        targets=targets,
        predecessor=predecessor,
        salt=salt,
        delay_seconds=int(delay),
        operation_id=computed_operation_id,
    )


def validate_ownership_execute(
    value: object,
    *,
    schedule: OwnershipSchedule,
    label: str = "ownership execute data",
) -> None:
    """Require execution calldata to match the decoded schedule byte-for-byte."""

    targets, values, payloads, predecessor, salt = _decode_call(
        value,
        signature=EXECUTE_BATCH_SIGNATURE,
        types=_BATCH_TYPES,
        label=label,
    )
    if (
        _normalize_targets(targets, f"{label}.targets") != schedule.targets
        or list(values) != [0, 0]
        or list(payloads)
        != [ACCEPT_OWNERSHIP_CALLDATA, ACCEPT_OWNERSHIP_CALLDATA]
        or predecessor != schedule.predecessor
        or salt != schedule.salt
    ):
        raise TimelockOperationError(
            "ownership intent calldata mismatches"
        )


def encode_ownership_execute(schedule: OwnershipSchedule) -> str:
    """Encode the only executeBatch call accepted for a reviewed schedule."""

    return "0x" + (
        keccak(text=EXECUTE_BATCH_SIGNATURE)[:4]
        + abi_encode(
            _BATCH_TYPES,
            [
                list(schedule.targets),
                [0, 0],
                [ACCEPT_OWNERSHIP_CALLDATA, ACCEPT_OWNERSHIP_CALLDATA],
                schedule.predecessor,
                schedule.salt,
            ],
        )
    ).hex()


__all__ = [
    "ACCEPT_OWNERSHIP_CALLDATA",
    "OwnershipSchedule",
    "TimelockOperationError",
    "decode_ownership_schedule",
    "encode_ownership_execute",
    "validate_ownership_execute",
]
