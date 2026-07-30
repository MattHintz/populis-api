"""Deterministic Authority V3 independent-review request and receipt helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from solslot_puzzles.recovery_dependencies import (
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_LICENSE,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
)

from .authority_v3_review import REQUIRED_SCOPES, REVIEW_KIND


REQUEST_KIND = "solslot-authority-v3-review-request"
REQUEST_STATUS = "review-required"
PROTOCOL_VERSION = "solslot-v2-rc23"
MAX_SCOPE_EVIDENCE_BYTES = 2 * 1024 * 1024
SOURCE_REPOSITORIES = {
    "protocol": "https://github.com/MattHintz/solslot-protocol",
    "evm": "https://github.com/MattHintz/solslot-evm",
    "omnichain": "https://github.com/solslot/omnichain",
    "api": "https://github.com/MattHintz/solslot-api",
    "legacyBackend": "https://github.com/solslot/solslot-backend",
    "keyOfSolomon": "https://github.com/solslot/KeyofSolomon",
    "samuel": "https://github.com/solslot/Samuel",
    "customerWeb": "https://github.com/solslot/solslot",
    "adminPortal": "https://github.com/MattHintz/solslot-portal",
}
CHANGED_SOURCE_PULL_REQUESTS = frozenset(
    {"protocol", "omnichain", "api", "adminPortal"}
)
TRUST_BOUNDARIES = {
    "chialisp-wrapper": {
        "repositories": ["protocol", "api"],
        "sourcePaths": [
            "solslot_puzzles/admin_authority_v3_inner.clsp",
            "solslot_puzzles/admin_authority_action_v1.clsp",
            "solslot_puzzles/admin_identity_action_v1.clsp",
            "solslot_puzzles/admin_identity_prepare_announcement_v1.clsp",
            "solslot_puzzles/admin_identity_terminal_action_v1.clsp",
            "solslot_puzzles/eip712_member_v2.clsp",
            "solslot_puzzles/admin_authority_v3_driver.py",
            "solslot_api/admin_key_changes.py",
        ],
        "reviewObjectives": [
            "owner slot 0 plus exactly one coadministrator is required",
            "recovery keys cannot authorize operational spends",
            "replacement, network, manifest, nonce, and expiry are bound",
            "pending recovery freezes unrelated privileged operations",
            "cancel and completion can only reach the committed state",
        ],
        "verificationCommands": [
            {
                "repository": "protocol",
                "command": "pytest -q tests/test_admin_authority_v3.py",
            },
            {
                "repository": "api",
                "command": "pytest -q "
                "tests/test_admin_key_change_chia_packages.py "
                "tests/test_admin_key_changes.py",
            },
        ],
    },
    "mips-composition": {
        "repositories": ["protocol"],
        "sourcePaths": [
            "solslot_puzzles/recovery_dependencies.py",
            "solslot_puzzles/admin_authority_v3_inner.clsp",
            "solslot_puzzles/admin_authority_v3_driver.py",
            "tests/test_recovery_dependencies.py",
        ],
        "reviewObjectives": [
            "the pinned Apache-2.0 SDK commit is exact and reproducible",
            "singleton-member identities cannot change the authority tree",
            "restricted recovery modules expose no operational authority",
            "timelocks, vetoes, and side-effect prevention compose correctly",
        ],
        "verificationCommands": [
            {
                "repository": "protocol",
                "command": "pytest -q tests/test_recovery_dependencies.py "
                "tests/test_admin_authority_v3.py",
            },
        ],
    },
    "safe-recovery-module": {
        "repositories": ["omnichain", "api"],
        "sourcePaths": [
            "contracts/SolslotAdminRecoveryV3.sol",
            "test/AuthorityV3Recovery.test.js",
            "test/AuthorityV3IntentFixture.test.js",
            "solslot_api/admin_key_changes.py",
            "tests/test_admin_key_changes.py",
        ],
        "reviewObjectives": [
            "the two other identity Safes approve lost-key recovery",
            "the exact replacement and cross-chain intent are immutable",
            "routine and lost-key delays cannot be bypassed",
            "completion cannot create a partial authority transition",
        ],
        "verificationCommands": [
            {
                "repository": "omnichain",
                "command": "npm test -- --grep \"Authority V3\"",
            },
            {
                "repository": "api",
                "command": "pytest -q tests/test_admin_key_changes.py "
                "tests/test_admin_key_change_chia_packages.py",
            },
        ],
    },
    "safe-authority-guards": {
        "repositories": ["omnichain"],
        "sourcePaths": [
            "contracts/SolslotAuthorityGuardV3.sol",
            "contracts/SolslotAdminRecoveryV3.sol",
            "test/SafeAuthorityOperation.test.js",
            "test/AuthorityV3Recovery.test.js",
            "scripts/lib/authority-v3-deployment.js",
        ],
        "reviewObjectives": [
            "owner swaps, guard removal, and module removal are blocked",
            "owner slot 0 plus one coadministrator remains mandatory",
            "a pending recovery blocks arbitrary Safe transactions",
            "deployment evidence binds runtime code and the identity roster",
        ],
        "verificationCommands": [
            {
                "repository": "omnichain",
                "command": "npm test -- --grep "
                "\"Safe Authority|Authority V3\"",
            },
        ],
    },
}

_EVIDENCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class AuthorityV3ReviewPacketError(ValueError):
    """Review request or reviewer evidence is malformed or stale."""


def canonical_hash(payload: Mapping[str, Any]) -> str:
    unsigned = {
        key: value for key, value in payload.items() if key != "artifactHash"
    }
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def file_sha256(path: Path, *, maximum_bytes: int) -> str:
    try:
        stat = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.st_size <= 0
            or stat.st_size > maximum_bytes
        ):
            raise AuthorityV3ReviewPacketError(
                f"review evidence is invalid: {path}"
            )
        raw = path.read_bytes()
    except OSError as exc:
        raise AuthorityV3ReviewPacketError(
            f"review evidence is unreadable: {path}"
        ) from exc
    return "0x" + hashlib.sha256(raw).hexdigest()


def normalize_repository(value: object) -> str:
    candidate = str(value or "").strip()
    if candidate.startswith("git@github.com:"):
        candidate = (
            "https://github.com/"
            + candidate.removeprefix("git@github.com:")
        )
    parts = urlsplit(candidate)
    if (
        parts.scheme != "https"
        or parts.hostname != "github.com"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise AuthorityV3ReviewPacketError(
            "review repositories must use credential-free GitHub URLs"
        )
    path = parts.path.removesuffix(".git").rstrip("/")
    if len([item for item in path.split("/") if item]) != 2:
        raise AuthorityV3ReviewPacketError(
            "review repository URL must name one GitHub repository"
        )
    return urlunsplit(("https", "github.com", path, "", ""))


def _full_sha(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if len(normalized) != 40:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be a full commit SHA"
        )
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be valid hex"
        ) from exc
    return normalized


def _bytes32(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if not normalized.startswith("0x") or len(normalized) != 66:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be 0x-prefixed 32-byte hex"
        )
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be valid hex"
        ) from exc
    if not any(raw):
        raise AuthorityV3ReviewPacketError(f"{label} cannot be zero")
    return normalized


def _timestamp(value: object, label: str) -> str:
    candidate = str(value or "")
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be ISO-8601"
        ) from exc
    if parsed.tzinfo is None:
        raise AuthorityV3ReviewPacketError(
            f"{label} must include a timezone"
        )
    return candidate


def _pull_request_url(
    value: object,
    *,
    source: str,
) -> str:
    candidate = str(value or "").strip()
    parts = urlsplit(candidate)
    expected_repository = normalize_repository(SOURCE_REPOSITORIES[source])
    expected_parts = urlsplit(expected_repository)
    path_parts = [item for item in parts.path.split("/") if item]
    if (
        parts.scheme != "https"
        or parts.hostname != "github.com"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or path_parts[:2]
        != [item for item in expected_parts.path.split("/") if item]
        or len(path_parts) != 4
        or path_parts[2] != "pull"
        or not path_parts[3].isdigit()
        or int(path_parts[3]) <= 0
    ):
        raise AuthorityV3ReviewPacketError(
            f"{source} pull request URL is invalid"
        )
    return urlunsplit(
        ("https", "github.com", "/" + "/".join(path_parts), "", "")
    )


def build_review_request(
    *,
    source_states: Mapping[str, Mapping[str, object]],
    pull_requests: Mapping[str, Mapping[str, object]],
    puzzle_inventory: Mapping[str, Any],
    puzzle_inventory_file_sha256: str,
    generated_at: str,
) -> dict[str, Any]:
    if set(source_states) != set(SOURCE_REPOSITORIES):
        raise AuthorityV3ReviewPacketError(
            "review request must bind all nine source repositories"
        )
    if set(pull_requests) != CHANGED_SOURCE_PULL_REQUESTS:
        raise AuthorityV3ReviewPacketError(
            "review request must bind the four Authority V3 pull requests"
        )
    sources: dict[str, dict[str, str]] = {}
    for name, expected_repository in SOURCE_REPOSITORIES.items():
        state = source_states[name]
        repository = normalize_repository(state.get("repository"))
        if repository != normalize_repository(expected_repository):
            raise AuthorityV3ReviewPacketError(
                f"{name} does not use the canonical repository"
            )
        branch = str(state.get("branch") or "").strip()
        if not branch:
            raise AuthorityV3ReviewPacketError(
                f"{name} branch is unavailable"
            )
        sources[name] = {
            "repository": repository,
            "branch": branch,
            "commit": _full_sha(state.get("commit"), f"{name} commit"),
        }
    normalized_prs: dict[str, dict[str, str]] = {}
    for source in sorted(CHANGED_SOURCE_PULL_REQUESTS):
        item = pull_requests[source]
        head_sha = _full_sha(
            item.get("headSha"),
            f"{source} pull request head",
        )
        if head_sha != sources[source]["commit"]:
            raise AuthorityV3ReviewPacketError(
                f"{source} pull request does not match the reviewed source"
            )
        normalized_prs[source] = {
            "url": _pull_request_url(item.get("url"), source=source),
            "headSha": head_sha,
        }
    if (
        puzzle_inventory.get("schema") != "solslot.puzzle-hashes.v1"
        or puzzle_inventory.get("release") != "RC23"
        or not isinstance(puzzle_inventory.get("newPuzzleHashes"), Mapping)
    ):
        raise AuthorityV3ReviewPacketError(
            "RC23 puzzle inventory is missing or unsupported"
        )
    inner_hash = _bytes32(
        "0x"
        + str(
            puzzle_inventory["newPuzzleHashes"].get(
                "admin_authority_v3_inner.clsp"
            )
            or ""
        ).removeprefix("0x"),
        "Authority V3 inner module hash",
    )
    inventory_hash = _bytes32(
        "0x" + puzzle_inventory_file_sha256.removeprefix("0x"),
        "puzzle inventory file SHA-256",
    )
    generated = _timestamp(generated_at, "generatedAt")
    source_shas = {
        name: sources[name]["commit"] for name in SOURCE_REPOSITORIES
    }
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": REQUEST_KIND,
        "status": REQUEST_STATUS,
        "network": "testnet11",
        "protocolVersion": PROTOCOL_VERSION,
        "generatedAt": generated,
        "sourceShas": source_shas,
        "sources": sources,
        "pullRequests": normalized_prs,
        "chiaAuthority": {
            "innerModHash": inner_hash,
            "puzzleInventoryFileSha256": inventory_hash,
            "canonicalPuzzleChecksum": _bytes32(
                "0x"
                + str(
                    puzzle_inventory.get("canonicalChecksum") or ""
                ).removeprefix("0x"),
                "canonical puzzle checksum",
            ),
        },
        "evmAuthority": {
            "sourceSha": source_shas["omnichain"],
            "governanceEvidenceRequired": True,
            "governanceEvidenceHash": None,
        },
        "upstream": {
            "repository": PINNED_CNI_WALLET_SDK_REPOSITORY,
            "commit": PINNED_CNI_WALLET_SDK_COMMIT,
            "license": PINNED_CNI_WALLET_SDK_LICENSE,
            "manifestHash": "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH,
        },
        "trustBoundaries": [
            {"scope": scope, **TRUST_BOUNDARIES[scope]}
            for scope in sorted(REQUIRED_SCOPES)
        ],
        "finalApprovalRequirements": [
            "all nine source SHAs must match the final RC23 source manifest",
            "the live Base Sepolia governance deployment evidence must pass "
            "the API evidence loader",
            "all four trust boundaries need independent evidence",
            "the final receipt must be checksum-pinned before ceremony use",
        ],
    }
    payload["artifactHash"] = canonical_hash(payload)
    return payload


def validate_review_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    if (
        payload.get("schemaVersion") != 1
        or payload.get("kind") != REQUEST_KIND
        or payload.get("status") != REQUEST_STATUS
        or payload.get("network") != "testnet11"
        or payload.get("protocolVersion") != PROTOCOL_VERSION
        or payload.get("artifactHash") != canonical_hash(payload)
        or "outcome" in payload
        or "reviews" in payload
    ):
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request is unsupported or approving"
        )
    source_shas = payload.get("sourceShas")
    sources = payload.get("sources")
    pull_requests = payload.get("pullRequests")
    chia = payload.get("chiaAuthority")
    evm = payload.get("evmAuthority")
    upstream = payload.get("upstream")
    boundaries = payload.get("trustBoundaries")
    if not all(
        isinstance(value, Mapping)
        for value in (
            source_shas,
            sources,
            pull_requests,
            chia,
            evm,
            upstream,
        )
    ) or not isinstance(boundaries, list):
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request is incomplete"
        )
    if set(source_shas) != set(SOURCE_REPOSITORIES) or set(sources) != set(
        SOURCE_REPOSITORIES
    ):
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request source set is incomplete"
        )
    for name, repository in SOURCE_REPOSITORIES.items():
        state = sources[name]
        if (
            not isinstance(state, Mapping)
            or normalize_repository(state.get("repository"))
            != normalize_repository(repository)
            or _full_sha(state.get("commit"), f"{name} commit")
            != _full_sha(source_shas.get(name), f"sourceShas.{name}")
            or not str(state.get("branch") or "").strip()
        ):
            raise AuthorityV3ReviewPacketError(
                f"Authority V3 review request {name} source is invalid"
            )
    if set(pull_requests) != CHANGED_SOURCE_PULL_REQUESTS:
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request pull request set is incomplete"
        )
    for source in CHANGED_SOURCE_PULL_REQUESTS:
        item = pull_requests[source]
        if (
            not isinstance(item, Mapping)
            or _pull_request_url(item.get("url"), source=source)
            != item.get("url")
            or _full_sha(item.get("headSha"), f"{source} pull request head")
            != source_shas[source]
        ):
            raise AuthorityV3ReviewPacketError(
                f"Authority V3 {source} pull request is stale"
            )
    _timestamp(payload.get("generatedAt"), "generatedAt")
    _bytes32(chia.get("innerModHash"), "Authority V3 inner module hash")
    _bytes32(
        chia.get("puzzleInventoryFileSha256"),
        "puzzle inventory file SHA-256",
    )
    _bytes32(
        chia.get("canonicalPuzzleChecksum"),
        "canonical puzzle checksum",
    )
    if (
        _full_sha(evm.get("sourceSha"), "EVM source SHA")
        != source_shas["omnichain"]
        or evm.get("governanceEvidenceRequired") is not True
        or evm.get("governanceEvidenceHash") is not None
    ):
        raise AuthorityV3ReviewPacketError(
            "review request must leave live EVM evidence unresolved"
        )
    if (
        upstream.get("repository") != PINNED_CNI_WALLET_SDK_REPOSITORY
        or upstream.get("commit") != PINNED_CNI_WALLET_SDK_COMMIT
        or upstream.get("license") != PINNED_CNI_WALLET_SDK_LICENSE
        or upstream.get("manifestHash")
        != "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
    ):
        raise AuthorityV3ReviewPacketError(
            "review request does not bind the pinned Chia SDK"
        )
    expected_boundaries = [
        {"scope": scope, **TRUST_BOUNDARIES[scope]}
        for scope in sorted(REQUIRED_SCOPES)
    ]
    if boundaries != expected_boundaries:
        raise AuthorityV3ReviewPacketError(
            "review request must cover all four trust boundaries"
        )
    return dict(payload)


def build_review_receipt(
    *,
    request: Mapping[str, Any],
    governance_evidence: Mapping[str, Any],
    scope_reviews: Mapping[str, Mapping[str, object]],
) -> dict[str, Any]:
    validated = validate_review_request(request)
    if set(scope_reviews) != REQUIRED_SCOPES:
        raise AuthorityV3ReviewPacketError(
            "review receipt requires all four trust boundaries"
        )
    if (
        governance_evidence.get("schemaVersion") != 3
        or governance_evidence.get("kind")
        != "solslot-alpha-authority-v3-governance-deployment"
        or governance_evidence.get("network") != "baseSepolia"
        or governance_evidence.get("chainId") != 84_532
        or governance_evidence.get("artifactHash")
        != canonical_hash(governance_evidence)
    ):
        raise AuthorityV3ReviewPacketError(
            "live Authority V3 governance evidence is invalid"
        )
    reviews: list[dict[str, Any]] = []
    evidence_names: set[str] = set()
    for scope in sorted(REQUIRED_SCOPES):
        item = scope_reviews[scope]
        if not isinstance(item, Mapping):
            raise AuthorityV3ReviewPacketError(
                f"{scope} review must be an object"
            )
        reviewer = str(item.get("reviewer") or "").strip()
        evidence_path = Path(str(item.get("evidencePath") or ""))
        completed_at = _timestamp(
            item.get("completedAt"),
            f"{scope} completedAt",
        )
        if not reviewer:
            raise AuthorityV3ReviewPacketError(
                f"{scope} reviewer is required"
            )
        if (
            not evidence_path.name
            or not _EVIDENCE_NAME.fullmatch(evidence_path.name)
        ):
            raise AuthorityV3ReviewPacketError(
                f"{scope} evidencePath must end in one safe file name"
            )
        if evidence_path.name in evidence_names:
            raise AuthorityV3ReviewPacketError(
                "each trust boundary needs a distinct evidence file"
            )
        evidence_names.add(evidence_path.name)
        reviews.append(
            {
                "scope": scope,
                "approved": True,
                "reviewer": reviewer,
                "evidenceFile": evidence_path.name,
                "evidenceHash": file_sha256(
                    evidence_path,
                    maximum_bytes=MAX_SCOPE_EVIDENCE_BYTES,
                ),
                "completedAt": completed_at,
            }
        )
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": REVIEW_KIND,
        "network": "testnet11",
        "protocolVersion": PROTOCOL_VERSION,
        "outcome": "approved",
        "reviewRequestHash": validated["artifactHash"],
        "sourceShas": validated["sourceShas"],
        "chiaAuthority": {
            "innerModHash": validated["chiaAuthority"]["innerModHash"],
        },
        "evmAuthority": {
            "governanceEvidenceHash": governance_evidence["artifactHash"],
        },
        "upstream": validated["upstream"],
        "reviews": reviews,
    }
    payload["artifactHash"] = canonical_hash(payload)
    return payload


def review_request_file_sha256(payload: Mapping[str, Any]) -> str:
    raw = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode(
        "ascii"
    )
    return hashlib.sha256(raw).hexdigest()


__all__ = [
    "AuthorityV3ReviewPacketError",
    "CHANGED_SOURCE_PULL_REQUESTS",
    "MAX_SCOPE_EVIDENCE_BYTES",
    "REQUEST_KIND",
    "REQUEST_STATUS",
    "SOURCE_REPOSITORIES",
    "TRUST_BOUNDARIES",
    "build_review_receipt",
    "build_review_request",
    "canonical_hash",
    "file_sha256",
    "normalize_repository",
    "review_request_file_sha256",
    "validate_review_request",
]
