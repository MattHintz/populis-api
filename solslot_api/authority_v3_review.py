"""Checksum-pinned independent-review receipt for Authority V3."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from solslot_puzzles.recovery_dependencies import (
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_LICENSE,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
)

from .config import Settings


MAX_REVIEW_BYTES = 128 * 1024
REVIEW_KIND = "solslot-authority-v3-independent-review"
REQUIRED_SCOPES = frozenset(
    {
        "chialisp-wrapper",
        "mips-composition",
        "safe-recovery-module",
        "safe-authority-guards",
    }
)
class AuthorityV3ReviewError(ValueError):
    """Authority V3 review evidence is absent, stale, or malformed."""


def read_authority_v3_review_receipt(
    settings: Settings,
    *,
    expected_file_sha256: str,
) -> bytes:
    path_value = settings.authority_v3_independent_review_path
    expected = expected_file_sha256.removeprefix("0x").lower()
    configured = (
        settings.authority_v3_independent_review_sha256 or ""
    ).removeprefix("0x").lower()
    if (
        not path_value
        or len(expected) != 64
        or not secrets.compare_digest(expected, configured)
    ):
        raise AuthorityV3ReviewError(
            "Authority V3 review archive checksum is not pinned"
        )
    path = Path(path_value)
    try:
        stat = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.st_size <= 0
            or stat.st_size > MAX_REVIEW_BYTES
        ):
            raise AuthorityV3ReviewError(
                "Authority V3 review receipt is invalid"
            )
        raw = path.read_bytes()
    except OSError as exc:
        raise AuthorityV3ReviewError(
            "Authority V3 review receipt is unreadable"
        ) from exc
    actual = hashlib.sha256(raw).hexdigest()
    if not secrets.compare_digest(actual, expected):
        raise AuthorityV3ReviewError(
            "Authority V3 review receipt changed before archival"
        )
    return raw


def _hex(
    value: object,
    *,
    length: int,
    label: str,
) -> str:
    normalized = str(value or "").lower()
    if not normalized.startswith("0x") or len(normalized) != length * 2 + 2:
        raise AuthorityV3ReviewError(
            f"{label} must be 0x-prefixed {length}-byte hex"
        )
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise AuthorityV3ReviewError(
            f"{label} must be valid hex"
        ) from exc
    if not any(raw):
        raise AuthorityV3ReviewError(f"{label} cannot be zero")
    return normalized


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key != "artifactHash"
    }
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _full_sha(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if len(normalized) != 40:
        raise AuthorityV3ReviewError(
            f"{label} must be a full commit SHA"
        )
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise AuthorityV3ReviewError(
            f"{label} must be valid hex"
        ) from exc
    return normalized


def load_authority_v3_review(
    settings: Settings,
    *,
    source_shas: Mapping[str, Any],
    authority_inner_mod_hash: str,
    governance_evidence_hash: str,
) -> dict[str, Any]:
    path_value = settings.authority_v3_independent_review_path
    expected_file_hash = (
        settings.authority_v3_independent_review_sha256 or ""
    ).removeprefix("0x").lower()
    if not path_value or len(expected_file_hash) != 64:
        raise AuthorityV3ReviewError(
            "Authority V3 independent review is not checksum-pinned"
        )
    try:
        int(expected_file_hash, 16)
    except ValueError as exc:
        raise AuthorityV3ReviewError(
            "Authority V3 review checksum is invalid"
        ) from exc
    path = Path(path_value)
    try:
        stat = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.st_size <= 0
            or stat.st_size > MAX_REVIEW_BYTES
        ):
            raise AuthorityV3ReviewError(
                "Authority V3 review receipt is invalid"
            )
        raw = path.read_bytes()
        file_hash = hashlib.sha256(raw).hexdigest()
        if not secrets.compare_digest(file_hash, expected_file_hash):
            raise AuthorityV3ReviewError(
                "Authority V3 review receipt checksum changed"
            )
        payload = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityV3ReviewError(
            "Authority V3 review receipt is unreadable"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schemaVersion") != 1
        or payload.get("kind") != REVIEW_KIND
        or payload.get("network") != "testnet11"
        or payload.get("protocolVersion") != "solslot-v2-rc23"
        or payload.get("outcome") != "approved"
        or payload.get("artifactHash") != _canonical_hash(payload)
    ):
        raise AuthorityV3ReviewError(
            "Authority V3 review receipt is unsupported"
        )
    reviewed_sources = payload.get("sourceShas")
    if not isinstance(reviewed_sources, Mapping) or set(
        reviewed_sources
    ) != set(source_shas):
        raise AuthorityV3ReviewError(
            "Authority V3 review source manifest is incomplete"
        )
    for key, expected in source_shas.items():
        reviewed = _full_sha(
            reviewed_sources.get(key),
            f"sourceShas.{key}",
        )
        if reviewed != _full_sha(expected, f"expected sourceShas.{key}"):
            raise AuthorityV3ReviewError(
                f"Authority V3 review sourceShas.{key} is stale"
            )
    authority = payload.get("chiaAuthority")
    evm = payload.get("evmAuthority")
    upstream = payload.get("upstream")
    if not all(
        isinstance(value, Mapping)
        for value in (authority, evm, upstream)
    ):
        raise AuthorityV3ReviewError(
            "Authority V3 review bindings are incomplete"
        )
    if (
        _hex(
            authority.get("innerModHash"),
            length=32,
            label="Authority V3 inner module hash",
        )
        != _hex(
            authority_inner_mod_hash,
            length=32,
            label="expected Authority V3 inner module hash",
        )
        or _hex(
            evm.get("governanceEvidenceHash"),
            length=32,
            label="Authority V3 EVM evidence hash",
        )
        != _hex(
            governance_evidence_hash,
            length=32,
            label="expected Authority V3 EVM evidence hash",
        )
    ):
        raise AuthorityV3ReviewError(
            "Authority V3 review targets different code or deployment evidence"
        )
    if (
        upstream.get("repository")
        != PINNED_CNI_WALLET_SDK_REPOSITORY
        or upstream.get("commit")
        != PINNED_CNI_WALLET_SDK_COMMIT
        or upstream.get("license") != PINNED_CNI_WALLET_SDK_LICENSE
        or upstream.get("manifestHash")
        != "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
    ):
        raise AuthorityV3ReviewError(
            "Authority V3 review does not bind the pinned Chia SDK"
        )
    reviews = payload.get("reviews")
    if (
        not isinstance(reviews, list)
        or {item.get("scope") for item in reviews if isinstance(item, Mapping)}
        != REQUIRED_SCOPES
    ):
        raise AuthorityV3ReviewError(
            "Authority V3 review must cover all four trust boundaries"
        )
    for review in reviews:
        if (
            not isinstance(review, Mapping)
            or review.get("approved") is not True
            or not str(review.get("reviewer") or "").strip()
        ):
            raise AuthorityV3ReviewError(
                "Authority V3 review approval is incomplete"
            )
        _hex(
            review.get("evidenceHash"),
            length=32,
            label=f"{review.get('scope')} evidence hash",
        )
        try:
            completed = datetime.fromisoformat(
                str(review.get("completedAt") or "").replace(
                    "Z",
                    "+00:00",
                )
            )
        except ValueError as exc:
            raise AuthorityV3ReviewError(
                "Authority V3 review completion time is invalid"
            ) from exc
        if completed.tzinfo is None:
            raise AuthorityV3ReviewError(
                "Authority V3 review completion time needs a timezone"
            )
    return {
        "artifactHash": payload["artifactHash"],
        "fileSha256": "0x" + file_hash,
        "reviewerCount": len(
            {
                str(item["reviewer"]).strip()
                for item in reviews
            }
        ),
        "scopes": sorted(REQUIRED_SCOPES),
    }


__all__ = [
    "AuthorityV3ReviewError",
    "PINNED_CNI_WALLET_SDK_COMMIT",
    "PINNED_CNI_WALLET_SDK_REPOSITORY",
    "RECOVERY_DEPENDENCY_MANIFEST_HASH",
    "REQUIRED_SCOPES",
    "load_authority_v3_review",
    "read_authority_v3_review_receipt",
]
