#!/usr/bin/env python3
"""Reject embedded credentials in source trees and packaged releases."""

from __future__ import annotations

import argparse
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable


EXCLUDED_PARTS = frozenset(
    {".git", ".mypy_cache", ".pytest_cache", ".venv", "__pycache__", "node_modules"}
)
PATTERNS = (
    re.compile(rb"sk_" + rb"(?:live|test)_" + rb"[A-Za-z0-9]{12,}"),
    re.compile(rb"rk_" + rb"live_" + rb"[A-Za-z0-9]{12,}"),
    re.compile(rb"whsec_" + rb"[A-Za-z0-9]{12,}"),
    re.compile(rb"MANDRILL_" + rb"API_KEY\s*=\s*\S+"),
    re.compile(rb"STRIPE_" + rb"SECRET_KEY\s*=\s*\S+"),
    re.compile(rb"BEGIN " + rb"(?:RSA|EC|OPENSSH|PRIVATE)" + rb" PRIVATE KEY"),
    re.compile(
        rb"https://[a-z0-9.-]*g\.alchemy\.com/v2/[A-Za-z0-9_-]{8,}",
        re.I,
    ),
    re.compile(
        rb"https://[a-z0-9.-]*infura\.io/v3/[A-Za-z0-9_-]{8,}",
        re.I,
    ),
    re.compile(
        rb"https://[A-Za-z0-9_-]{8,}\.[a-z0-9.-]*quiknode\.pro(?:/|\b)",
        re.I,
    ),
)


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [
        root / raw.decode()
        for raw in result.stdout.split(b"\0")
        if raw and (root / raw.decode()).is_file()
    ]


def iter_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from (
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and not any(part in EXCLUDED_PARTS for part in candidate.parts)
            )
        elif path.is_file() and not any(
            part in EXCLUDED_PARTS for part in path.parts
        ):
            yield path


def _contains_credential(data: bytes) -> bool:
    return any(pattern.search(data) for pattern in PATTERNS)


def violations_for_path(path: Path) -> list[str]:
    violations: list[str] = []
    try:
        if tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    handle = archive.extractfile(member)
                    if handle is not None and _contains_credential(handle.read()):
                        violations.append(f"{path}!{member.name}")
            return violations
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if not name.endswith("/") and _contains_credential(archive.read(name)):
                        violations.append(f"{path}!{name}")
            return violations
        if _contains_credential(path.read_bytes()):
            violations.append(str(path))
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        violations.append(f"{path} (unreadable)")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--paths", nargs="*", type=Path)
    args = parser.parse_args()

    root = args.repo_root.resolve()
    candidates = (
        list(iter_files(args.paths)) if args.paths else tracked_files(root)
    )
    violations = [
        violation
        for path in candidates
        for violation in violations_for_path(path)
    ]
    if violations:
        print("Embedded credential detected in:")
        for violation in violations:
            print(f"  {violation}")
        return 1
    print(f"Credential gate passed for {len(candidates)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
