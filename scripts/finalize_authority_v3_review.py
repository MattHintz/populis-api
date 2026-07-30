#!/usr/bin/env python3
"""Finalize an Authority V3 review receipt from independent evidence files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Sequence

from solslot_api.authority_v3_review import REQUIRED_SCOPES
from solslot_api.authority_v3_review_packet import (
    AuthorityV3ReviewPacketError,
    build_review_receipt,
)


ATTESTATION = (
    "I independently reviewed all listed Authority V3 trust boundaries"
)


def _mapping(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        scope, separator, item = value.partition("=")
        if (
            not separator
            or scope not in REQUIRED_SCOPES
            or not item.strip()
            or scope in result
        ):
            raise AuthorityV3ReviewPacketError(
                f"{label} must contain each scope once as scope=value"
            )
        result[scope] = item.strip()
    if set(result) != REQUIRED_SCOPES:
        raise AuthorityV3ReviewPacketError(
            f"{label} must cover all four trust boundaries"
        )
    return result


def _json_object(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorityV3ReviewPacketError(
            f"{label} is unreadable"
        ) from exc
    if not isinstance(value, dict):
        raise AuthorityV3ReviewPacketError(f"{label} must be an object")
    return value


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--governance-evidence", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument(
        "--reviewer",
        action="append",
        default=[],
        help="Repeat as scope=reviewer name.",
    )
    parser.add_argument(
        "--evidence",
        action="append",
        default=[],
        help="Repeat as scope=file-name; files must be in --evidence-dir.",
    )
    parser.add_argument(
        "--completed-at",
        action="append",
        default=[],
        help="Repeat as scope=ISO-8601 timestamp.",
    )
    parser.add_argument("--attestation", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.attestation != ATTESTATION:
        raise AuthorityV3ReviewPacketError(
            "the exact independent-review attestation is required"
        )
    reviewers = _mapping(args.reviewer, "--reviewer")
    evidence_names = _mapping(args.evidence, "--evidence")
    completed_at = _mapping(args.completed_at, "--completed-at")
    evidence_dir = args.evidence_dir.resolve()
    if (
        not evidence_dir.is_dir()
        or evidence_dir.is_symlink()
    ):
        raise AuthorityV3ReviewPacketError(
            "evidence directory must be a real directory"
        )
    scope_reviews = {}
    for scope in sorted(REQUIRED_SCOPES):
        file_name = evidence_names[scope]
        if Path(file_name).name != file_name:
            raise AuthorityV3ReviewPacketError(
                f"{scope} evidence must be a file name, not a path"
            )
        evidence_path = evidence_dir / file_name
        if evidence_path.resolve().parent != evidence_dir:
            raise AuthorityV3ReviewPacketError(
                f"{scope} evidence escapes the evidence directory"
            )
        scope_reviews[scope] = {
            "reviewer": reviewers[scope],
            "evidencePath": evidence_path,
            "completedAt": completed_at[scope],
        }
    receipt = build_review_receipt(
        request=_json_object(args.request, "review request"),
        governance_evidence=_json_object(
            args.governance_evidence,
            "governance evidence",
        ),
        scope_reviews=scope_reviews,
    )
    output = args.output.resolve()
    if output.exists():
        raise AuthorityV3ReviewPacketError(
            "review receipt output already exists"
        )
    raw = (
        json.dumps(receipt, sort_keys=True, indent=2) + "\n"
    ).encode("ascii")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, output)
    print(
        json.dumps(
            {
                "artifactHash": receipt["artifactHash"],
                "fileSha256": "0x" + hashlib.sha256(raw).hexdigest(),
                "output": str(output),
                "reviewerCount": len(set(reviewers.values())),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
