#!/usr/bin/env python3
"""Build a non-approving review request from an exact release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from solslot_puzzles.admin_authority_v3_driver import (
    admin_authority_v3_inner_mod_hash,
)

from solslot_api.authority_v3_review_packet import (
    SOURCE_REPOSITORIES,
    AuthorityV3ReviewPacketError,
    build_review_request,
    normalize_repository,
    validate_source_manifest,
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


def _remote_ref(repository_path: Path, ref: str) -> str:
    output = _git(
        repository_path.resolve(),
        "ls-remote",
        "origin",
        ref,
        ref + "^{}",
    )
    resolved = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 2:
            resolved[fields[1]] = fields[0].lower()
    commit = resolved.get(ref + "^{}") or resolved.get(ref)
    if commit is None:
        raise AuthorityV3ReviewPacketError(
            f"release ref {ref} is unavailable"
        )
    return commit


def _verify_release_refs(
    source: str,
    repository_path: Path,
    *,
    release_id: str,
    release_branch: str,
    expected_commit: str,
) -> None:
    refs = (
        "refs/heads/main",
        f"refs/heads/{release_branch}",
        f"refs/tags/{release_id}",
    )
    for ref in refs:
        if _remote_ref(repository_path, ref) != expected_commit:
            label = ref.removeprefix("refs/")
            raise AuthorityV3ReviewPacketError(
                f"{source} remote {label} differs from the release manifest"
            )


def _read_json(path: Path, label: str) -> tuple[dict, bytes]:
    try:
        raw = path.resolve().read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityV3ReviewPacketError(
            f"{label} is unreadable"
        ) from exc
    if not isinstance(value, dict):
        raise AuthorityV3ReviewPacketError(f"{label} must be an object")
    return value, raw


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name, argument in ARGUMENT_NAMES.items():
        parser.add_argument(
            f"--{argument}",
            dest=name,
            type=Path,
            required=True,
        )
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--puzzle-inventory", type=Path)
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
    source_manifest, manifest_bytes = _read_json(
        args.source_manifest,
        "release source manifest",
    )
    manifest = validate_source_manifest(source_manifest)
    states = {
        name: _inspect_source(name, getattr(args, name))
        for name in SOURCE_REPOSITORIES
    }
    for source in SOURCE_REPOSITORIES:
        _verify_release_refs(
            source,
            getattr(args, source),
            release_id=manifest["releaseId"],
            release_branch=manifest["releaseBranch"],
            expected_commit=manifest["sourceShas"][source],
        )
    release_line = (
        manifest["releaseId"]
        .removeprefix("solslot-v2-alpha-")
        .split("-", 1)[0]
        .split(".", 1)[0]
    )
    inventory_path = args.puzzle_inventory or (
        args.protocol.resolve()
        / "release-manifests"
        / f"{release_line}-puzzle-hashes.json"
    )
    puzzle_inventory, inventory_bytes = _read_json(
        inventory_path,
        "current puzzle inventory",
    )
    generated_at = args.generated_at or (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    request = build_review_request(
        source_states=states,
        source_manifest=source_manifest,
        source_manifest_file_sha256=hashlib.sha256(
            manifest_bytes
        ).hexdigest(),
        puzzle_inventory=puzzle_inventory,
        puzzle_inventory_file_sha256=hashlib.sha256(
            inventory_bytes
        ).hexdigest(),
        authority_inner_mod_hash=(
            "0x" + admin_authority_v3_inner_mod_hash().hex()
        ),
        generated_at=generated_at,
        release_refs_verified=True,
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
