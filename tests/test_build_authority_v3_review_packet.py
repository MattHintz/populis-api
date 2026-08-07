from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from solslot_api.authority_v3_review_packet import (
    AuthorityV3ReviewPacketError,
)


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "build_authority_v3_review_packet.py"
)
SPEC = importlib.util.spec_from_file_location(
    "build_authority_v3_review_packet",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def test_release_ref_verification_requires_main_branch_and_tag(
    monkeypatch,
) -> None:
    commit = "a" * 40
    checked: list[str] = []

    def resolve(_path: Path, ref: str) -> str:
        checked.append(ref)
        return commit

    monkeypatch.setattr(builder, "_remote_ref", resolve)
    builder._verify_release_refs(
        "api",
        Path("/release/api"),
        release_id="solslot-v2-alpha-rc27.4-20260807",
        release_branch="release/testnet-alpha-rc27.4-20260807",
        expected_commit=commit,
    )

    assert checked == [
        "refs/heads/main",
        "refs/heads/release/testnet-alpha-rc27.4-20260807",
        "refs/tags/solslot-v2-alpha-rc27.4-20260807",
    ]


def test_release_ref_verification_rejects_a_stale_remote_tag(
    monkeypatch,
) -> None:
    commit = "a" * 40

    def resolve(_path: Path, ref: str) -> str:
        return "b" * 40 if ref.startswith("refs/tags/") else commit

    monkeypatch.setattr(builder, "_remote_ref", resolve)
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="remote tags/.* differs",
    ):
        builder._verify_release_refs(
            "api",
            Path("/release/api"),
            release_id="solslot-v2-alpha-rc27.4-20260807",
            release_branch="release/testnet-alpha-rc27.4-20260807",
            expected_commit=commit,
        )
