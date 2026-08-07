from __future__ import annotations

import hashlib
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
from solslot_puzzles.recovery_dependencies import (
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_LICENSE,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
)


RELEASE_ID = "solslot-v2-alpha-rc27.4-20260807"
RELEASE_BRANCH = "release/testnet-alpha-rc27.4-20260807"


def _source_manifest(source_states: dict) -> dict:
    source_shas = {
        name: state["commit"] for name, state in source_states.items()
    }
    commitment = canonical_hash(
        {
            "version": 4,
            "sources": source_shas,
            "dependencies": {
                "administratorRecovery": (
                    "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
                )
            },
        }
    )
    payload = {
        "schemaVersion": 4,
        "kind": "solslot-release-source-manifest",
        "releaseId": RELEASE_ID,
        "network": "testnet11",
        "testOnly": True,
        "sourceShas": source_shas,
        "dependencies": {
            "administratorRecovery": {
                "repository": PINNED_CNI_WALLET_SDK_REPOSITORY,
                "commit": PINNED_CNI_WALLET_SDK_COMMIT,
                "license": PINNED_CNI_WALLET_SDK_LICENSE,
                "manifestHash": (
                    "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
                ),
            }
        },
        "authoritySourceCommitment": commitment,
        "sources": source_states,
    }
    unsigned = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    payload["manifestHash"] = "0x" + hashlib.sha256(unsigned).hexdigest()
    return payload


def _request() -> dict:
    source_states = {
        name: {
            "repository": repository,
            "branch": RELEASE_BRANCH,
            "commit": f"{index:040x}",
        }
        for index, (name, repository) in enumerate(
            SOURCE_REPOSITORIES.items(),
            start=1,
        )
    }
    puzzle_inventory = {
        "schema": "solslot.puzzle-hashes.v1",
        "release": "RC27",
        "canonicalChecksum": "11" * 32,
        "newPuzzleHashes": {},
        "changedPuzzleHashes": {},
    }
    return build_review_request(
        source_states=source_states,
        source_manifest=_source_manifest(source_states),
        source_manifest_file_sha256="44" * 32,
        puzzle_inventory=puzzle_inventory,
        puzzle_inventory_file_sha256="33" * 32,
        authority_inner_mod_hash="0x" + "22" * 32,
        generated_at="2026-07-29T18:00:00Z",
        release_refs_verified=True,
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
    assert validated["schemaVersion"] == 2
    assert validated["release"]["releaseId"] == RELEASE_ID
    assert validated["release"]["releaseRefsVerified"] is True
    assert "pullRequests" not in validated
    assert {
        item["scope"] for item in validated["trustBoundaries"]
    } == REQUIRED_SCOPES
    assert (
        validated["evmAuthority"]["governanceEvidenceHash"]
        is None
    )


def test_review_request_rejects_stale_manifest_or_approval() -> None:
    request = _request()
    request["release"]["sourceManifestHash"] = "0x" + "f" * 64
    request["artifactHash"] = canonical_hash(request)
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="source manifest hash is invalid",
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


def test_review_request_rejects_stale_authority_commitment() -> None:
    request = _request()
    request["release"]["authoritySourceCommitment"] = "0x" + "f" * 64
    request["artifactHash"] = canonical_hash(request)
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="source commitment is invalid",
    ):
        validate_review_request(request)


def test_review_request_rejects_ambiguous_approval_fields() -> None:
    request = _request()
    request["approved"] = True
    request["artifactHash"] = canonical_hash(request)
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="unsupported or missing fields",
    ):
        validate_review_request(request)


def test_release_manifest_rejects_noncanonical_source_metadata() -> None:
    source_states = {
        name: {
            "repository": repository,
            "branch": RELEASE_BRANCH,
            "commit": f"{index:040x}",
        }
        for index, (name, repository) in enumerate(
            SOURCE_REPOSITORIES.items(),
            start=1,
        )
    }
    manifest = _source_manifest(source_states)
    manifest["sources"]["api"]["repository"] = (
        "https://github.com/attacker/solslot-api"
    )
    unsigned = {
        key: value for key, value in manifest.items() if key != "manifestHash"
    }
    manifest["manifestHash"] = "0x" + hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    with pytest.raises(
        AuthorityV3ReviewPacketError,
        match="api repository is not canonical",
    ):
        build_review_request(
            source_states=source_states,
            source_manifest=manifest,
            source_manifest_file_sha256="44" * 32,
            puzzle_inventory={
                "schema": "solslot.puzzle-hashes.v1",
                "release": "RC27",
                "canonicalChecksum": "11" * 32,
                "newPuzzleHashes": {},
                "changedPuzzleHashes": {},
            },
            puzzle_inventory_file_sha256="33" * 32,
            authority_inner_mod_hash="0x" + "22" * 32,
            generated_at="2026-08-07T18:00:00Z",
            release_refs_verified=True,
        )


def test_builder_accepts_final_merge_commits_without_pr_heads() -> None:
    request = _request()
    assert request["sourceShas"]["api"] == request["sources"]["api"][
        "commit"
    ]
    assert request["status"] == "review-required"
    assert "pullRequests" not in request


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
