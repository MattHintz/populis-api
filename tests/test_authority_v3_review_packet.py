from __future__ import annotations

import json

import pytest

from solslot_api.authority_v3_review import REQUIRED_SCOPES
from solslot_api.authority_v3_review_packet import (
    SOURCE_REPOSITORIES,
    AuthorityV3ReviewPacketError,
    build_review_receipt,
    build_review_request,
    canonical_hash,
    validate_review_request,
)


def _request() -> dict:
    source_states = {
        name: {
            "repository": repository,
            "branch": (
                "feature/authority-v3-recovery"
                if name
                in {"protocol", "omnichain", "api", "adminPortal"}
                else "release/testnet-alpha-rc22.2-20260729"
            ),
            "commit": f"{index:040x}",
        }
        for index, (name, repository) in enumerate(
            SOURCE_REPOSITORIES.items(),
            start=1,
        )
    }
    pull_requests = {
        name: {
            "url": f"{SOURCE_REPOSITORIES[name]}/pull/{index}",
            "headSha": source_states[name]["commit"],
        }
        for index, name in enumerate(
            ("protocol", "omnichain", "api", "adminPortal"),
            start=1,
        )
    }
    puzzle_inventory = {
        "schema": "solslot.puzzle-hashes.v1",
        "release": "RC23",
        "canonicalChecksum": "11" * 32,
        "newPuzzleHashes": {
            "admin_authority_v3_inner.clsp": "22" * 32,
        },
    }
    return build_review_request(
        source_states=source_states,
        pull_requests=pull_requests,
        puzzle_inventory=puzzle_inventory,
        puzzle_inventory_file_sha256="33" * 32,
        generated_at="2026-07-29T18:00:00Z",
    )


def _governance_evidence() -> dict:
    payload = {
        "schemaVersion": 3,
        "kind": "solslot-alpha-authority-v3-governance-deployment",
        "network": "baseSepolia",
        "chainId": 84_532,
    }
    payload["artifactHash"] = canonical_hash(payload)
    return payload


def test_review_request_is_complete_and_cannot_approve() -> None:
    request = _request()
    validated = validate_review_request(request)

    assert validated["status"] == "review-required"
    assert "outcome" not in validated
    assert "reviews" not in validated
    assert set(validated["sourceShas"]) == set(SOURCE_REPOSITORIES)
    assert {
        item["scope"] for item in validated["trustBoundaries"]
    } == REQUIRED_SCOPES
    assert (
        validated["evmAuthority"]["governanceEvidenceHash"]
        is None
    )


def test_review_request_rejects_stale_pull_request_or_approval() -> None:
    request = _request()
    request["pullRequests"]["api"]["headSha"] = "f" * 40
    request["artifactHash"] = canonical_hash(request)
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="api pull request is stale",
    ):
        validate_review_request(request)

    request = _request()
    request["outcome"] = "approved"
    request["artifactHash"] = canonical_hash(request)
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="unsupported or approving",
    ):
        validate_review_request(request)


def test_builds_receipt_from_four_real_evidence_files(tmp_path) -> None:
    scope_reviews = {}
    for index, scope in enumerate(sorted(REQUIRED_SCOPES), start=1):
        evidence = tmp_path / f"{scope}.md"
        evidence.write_text(
            f"# Independent evidence {index}\n",
            encoding="ascii",
        )
        scope_reviews[scope] = {
            "reviewer": f"Reviewer {index}",
            "evidencePath": evidence,
            "completedAt": "2026-07-29T19:00:00+00:00",
        }

    receipt = build_review_receipt(
        request=_request(),
        governance_evidence=_governance_evidence(),
        scope_reviews=scope_reviews,
    )

    assert receipt["outcome"] == "approved"
    assert receipt["artifactHash"] == canonical_hash(receipt)
    assert receipt["reviewRequestHash"] == _request()["artifactHash"]
    assert {item["scope"] for item in receipt["reviews"]} == REQUIRED_SCOPES
    assert all(
        item["evidenceHash"].startswith("0x")
        and len(item["evidenceHash"]) == 66
        for item in receipt["reviews"]
    )
    json.dumps(receipt, ensure_ascii=True)


def test_receipt_rejects_missing_or_symlinked_evidence(tmp_path) -> None:
    reviews = {}
    for scope in sorted(REQUIRED_SCOPES):
        evidence = tmp_path / f"{scope}.md"
        evidence.write_text("reviewed\n", encoding="ascii")
        reviews[scope] = {
            "reviewer": "Independent reviewer",
            "evidencePath": evidence,
            "completedAt": "2026-07-29T19:00:00Z",
        }
    missing_scope = dict(reviews)
    missing_scope.pop("mips-composition")
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="all four trust boundaries",
    ):
        build_review_receipt(
            request=_request(),
            governance_evidence=_governance_evidence(),
            scope_reviews=missing_scope,
        )

    target = tmp_path / "outside.md"
    target.write_text("not independently archived\n", encoding="ascii")
    symlink = tmp_path / "safe-recovery-module-link.md"
    symlink.symlink_to(target)
    reviews["safe-recovery-module"]["evidencePath"] = symlink
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="review evidence is invalid",
    ):
        build_review_receipt(
            request=_request(),
            governance_evidence=_governance_evidence(),
            scope_reviews=reviews,
        )
