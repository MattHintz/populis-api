"""Pure-byte CLVM tree hashing for request-safe protocol snapshots."""
from __future__ import annotations

import hashlib
from typing import Iterable

from chia_rs.sized_bytes import bytes32


def atom_hash(atom: bytes) -> bytes32:
    return bytes32(hashlib.sha256(b"\x01" + atom).digest())


def pair_hash(left: bytes32, right: bytes32) -> bytes32:
    return bytes32(hashlib.sha256(b"\x02" + bytes(left) + bytes(right)).digest())


def list_hash(atoms: Iterable[bytes]) -> bytes32:
    result = atom_hash(b"")
    material = list(atoms)
    for atom in reversed(material):
        result = pair_hash(atom_hash(atom), result)
    return result


def positive_clvm_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("Only non-negative protocol versions are supported.")
    if value == 0:
        return b""
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return b"\x00" + encoded if encoded[0] & 0x80 else encoded


__all__ = ["atom_hash", "list_hash", "pair_hash", "positive_clvm_int"]
