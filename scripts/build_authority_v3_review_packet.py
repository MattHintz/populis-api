#!/usr/bin/env python3
"""Build a non-approving Authority V3 review request from exact Git heads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

from solslot_api.authority_v3_review_packet import (
    CHANGED_SOURCE_PULL_REQUESTS,
    SOURCE_REPOSITORIES,
    AuthorityV3ReviewPacketError,
    build_review_request,
    normalize_repository,
)


ARGUMENT_NAMES = {
    "protocol": "protocol-repo",
    "evm": "evm-repo",
    "omnichain": "omnichain-repo",
    "api": "api-repo",
    "legacyBackend": "legacy-backend-repo",
    "keyOfSolomon": "key-of-solomon-repo",
    "samuel": "samuel-repo",
    "customerWeb": "customer-web-repo",
    "adminPortal": "admin-portal-repo",
}
PR_ARGUMENT_NAMES = {
    "protocol": "protocol-pr",
    "omnichain": "omnichain-pr",
    "api": "api-pr",
    "adminPortal": "admin-portal-pr",
}


def _git(path: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuthorityV3ReviewPacketError(
            f"cannot inspect release repository {path}: {exc}"
        ) from exc
    return result.stdout.strip()


def _inspect_source(name: str, path: Path) -> dict[str, str]:
    resolved = path.resolve()
    commit = _git(resolved, "rev-parse", "HEAD").lower()
    branch = _git(resolved, "branch", "--show-current")
    if _git(resolved, "status", "--porcelain"):
        raise AuthorityV3ReviewPacketError(
            f"{name} worktree must be clean"
        )
    repository = normalize_repository(_git(resolved, "remote", "get-url", "origin"))
    if repository != normalize_repository(SOURCE_REPOSITORIES[name]):
        raise AuthorityV3ReviewPacketError(
            f"{name} origin is not the canonical repository"
        )
    return {
        "repository": repository,
        "branch": branch,
        "commit": commit,
    }


def _verify_pull_request(
    source: str,
    repository_path: Path,
    url: str,
    expected_head: str,
) -> dict[str, str]:
    path_parts = [item for item in urlsplit(url).path.split("/") if item]
    if (
        len(path_parts) != 4
        or path_parts[2] != "pull"
        or not path_parts[3].isdigit()
    ):
        raise AuthorityV3ReviewPacketError(
            f"{source} pull request URL is invalid"
        )
    remote_ref = f"refs/pull/{int(path_parts[3])}/head"
    output = _git(
        repository_path.resolve(),
        "ls-remote",
        "origin",
        remote_ref,
    )
    fields = output.split()
    if len(fields) != 2 or fields[1] != remote_ref:
        raise AuthorityV3ReviewPacketError(
            f"{source} pull request head is unavailable"
        )
    remote_head = fields[0].lower()
    if remote_head != expected_head:
        raise AuthorityV3ReviewPacketError(
            f"{source} pull request head differs from the clean worktree"
        )
    return {"url": url, "headSha": remote_head}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name, argument in ARGUMENT_NAMES.items():
        parser.add_argument(
            f"--{argument}",
            dest=name,
            type=Path,
            required=True,
        )
    for name, argument in PR_ARGUMENT_NAMES.items():
        parser.add_argument(
            f"--{argument}",
            dest=f"{name}_pr",
            required=True,
        )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--generated-at")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise AuthorityV3ReviewPacketError(
            "review packet output directory must be empty"
        )
    states = {
        name: _inspect_source(name, getattr(args, name))
        for name in SOURCE_REPOSITORIES
    }
    pull_requests = {}
    for source in sorted(CHANGED_SOURCE_PULL_REQUESTS):
        pull_requests[source] = _verify_pull_request(
            source,
            getattr(args, source),
            str(getattr(args, source + "_pr")),
            states[source]["commit"],
        )
    inventory_path = (
        args.protocol.resolve()
        / "release-manifests"
        / "rc23-puzzle-hashes.json"
    )
    try:
        inventory_bytes = inventory_path.read_bytes()
        puzzle_inventory = json.loads(inventory_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorityV3ReviewPacketError(
            "RC23 puzzle inventory is unreadable"
        ) from exc
    generated_at = args.generated_at or (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    request = build_review_request(
        source_states=states,
        pull_requests=pull_requests,
        puzzle_inventory=puzzle_inventory,
        puzzle_inventory_file_sha256=hashlib.sha256(
            inventory_bytes
        ).hexdigest(),
        generated_at=generated_at,
    )
    request_bytes = (
        json.dumps(request, sort_keys=True, indent=2) + "\n"
    ).encode("ascii")
    request_hash = hashlib.sha256(request_bytes).hexdigest()
    output_dir.mkdir(parents=True, exist_ok=True)
    request_path = output_dir / "authority-v3-review-request.json"
    checksum_path = output_dir / "SHA256SUMS"
    temporary_request = request_path.with_suffix(".json.tmp")
    temporary_checksum = checksum_path.with_suffix(".tmp")
    temporary_request.write_bytes(request_bytes)
    temporary_checksum.write_text(
        f"{request_hash}  {request_path.name}\n",
        encoding="ascii",
    )
    os.replace(temporary_request, request_path)
    os.replace(temporary_checksum, checksum_path)
    print(
        json.dumps(
            {
                "artifactHash": request["artifactHash"],
                "fileSha256": "0x" + request_hash,
                "output": str(request_path),
                "status": request["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
