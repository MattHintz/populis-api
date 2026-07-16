"""One-shot process worker for thread-affine Chia genesis operations.

The Chia Python bindings contain Rust-backed lazy nodes that must not move from
the thread where they were created. FastAPI request handlers therefore invoke
this module in a fresh interpreter and exchange canonical JSON over stdio.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Mapping, Sequence


def _hex(value: bytes) -> str:
    return "0x" + bytes(value).hex()


def _hex_bytes(value: str, length: int, field: str, *, nonzero: bool = True) -> bytes:
    normalized = value.removeprefix("0x")
    if len(normalized) != length * 2:
        raise ValueError(f"{field} must be {length} bytes")
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be valid hex") from exc
    if nonzero and raw == b"\x00" * length:
        raise ValueError(f"{field} must be nonzero")
    return raw


def _admin_pubkeys(ceremony: Mapping[str, Any]) -> list[bytes]:
    invitations = ceremony.get("invitations")
    if not isinstance(invitations, list) or len(invitations) != 3:
        raise ValueError("three enrolled administrators are required")
    ordered = sorted(invitations, key=lambda item: int(item["slot"]))
    if [int(item["slot"]) for item in ordered] != [1, 2, 3]:
        raise ValueError("administrator roster slots are incomplete")
    return [
        _hex_bytes(str(item["compressed_pubkey"]), 33, "administrator pubkey")
        for item in ordered
    ]


def _build_plan(
    ceremony: Mapping[str, Any], body: Mapping[str, Any], expires_at: int
) -> Any:
    from chia_rs.sized_bytes import bytes32
    from solslot_puzzles.genesis_ceremony import (
        GenesisFundingCoinIds,
        build_genesis_ceremony_plan,
    )
    from solslot_puzzles.protocol_deployment import ProtocolDeploymentParams

    funding = body["fundingCoinIds"]
    parameters = body["protocolParameters"]
    ids = GenesisFundingCoinIds(
        sgt=bytes32(_hex_bytes(funding["sgt"], 32, "fundingCoinIds.sgt")),
        pool=bytes32(_hex_bytes(funding["pool"], 32, "fundingCoinIds.pool")),
        did=bytes32(_hex_bytes(funding["did"], 32, "fundingCoinIds.did")),
        governance=bytes32(
            _hex_bytes(funding["governance"], 32, "fundingCoinIds.governance")
        ),
        nav_registry=bytes32(
            _hex_bytes(funding["navRegistry"], 32, "fundingCoinIds.navRegistry")
        ),
        protocol_config=bytes32(
            _hex_bytes(
                funding["protocolConfig"], 32, "fundingCoinIds.protocolConfig"
            )
        ),
        admin_authority=bytes32(
            _hex_bytes(
                funding["adminAuthority"], 32, "fundingCoinIds.adminAuthority"
            )
        ),
        vault_version_registry=bytes32(
            _hex_bytes(
                funding["vaultVersionRegistry"],
                32,
                "fundingCoinIds.vaultVersionRegistry",
            )
        ),
        bridge_batch=bytes32(
            _hex_bytes(funding["bridgeBatch"], 32, "fundingCoinIds.bridgeBatch")
        ),
    )
    return build_genesis_ceremony_plan(
        ceremony_id=bytes32(
            _hex_bytes(str(ceremony["ceremony_id"]), 32, "ceremonyId")
        ),
        expires_at=expires_at,
        source_shas=ceremony["draft"]["sourceShas"],
        evm_addresses=body["evmAddresses"],
        funding=ids,
        faucet_puzzle_hash=bytes32(
            _hex_bytes(body["faucetPuzzleHash"], 32, "faucetPuzzleHash")
        ),
        governance_bls_pubkey=_hex_bytes(
            body["governanceBlsPubkey"], 48, "governanceBlsPubkey"
        ),
        admin_compressed_pubkeys=_admin_pubkeys(ceremony),
        validator_pubkeys=[
            _hex_bytes(value, 48, "validatorPubkey")
            for value in body["validatorPubkeys"]
        ],
        trusted_treasury_reserve_puzzle_hash=bytes32(
            _hex_bytes(
                body["trustedTreasuryReservePuzzleHash"],
                32,
                "trustedTreasuryReservePuzzleHash",
            )
        ),
        trusted_protocol_treasury_puzzle_hash=bytes32(
            _hex_bytes(
                body["trustedProtocolTreasuryPuzzleHash"],
                32,
                "trustedProtocolTreasuryPuzzleHash",
            )
        ),
        trusted_governance_rewards_puzzle_hash=bytes32(
            _hex_bytes(
                body["trustedGovernanceRewardsPuzzleHash"],
                32,
                "trustedGovernanceRewardsPuzzleHash",
            )
        ),
        trusted_governance_rewards_root=bytes32(
            _hex_bytes(
                body["trustedGovernanceRewardsRoot"],
                32,
                "trustedGovernanceRewardsRoot",
            )
        ),
        retired_coordinates=[
            bytes32(_hex_bytes(value, 32, "retiredCoordinate"))
            for value in body["retiredCoordinates"]
        ],
        params=ProtocolDeploymentParams(
            quorum_bps=int(parameters["quorumBps"]),
            voting_window_seconds=int(parameters["votingWindowSeconds"]),
            sgt_total_supply=int(parameters["sgtTotalSupply"]),
            min_proposal_stake=int(parameters["minProposalStake"]),
            fp_scale=int(parameters["fpScale"]),
            min_nav_registry_version=int(parameters["minNavRegistryVersion"]),
            initial_pool_status=int(parameters["initialPoolStatus"]),
            initial_total_pool_token_supply=int(
                parameters["initialTotalPoolTokenSupply"]
            ),
            initial_treasury_reserve_tokens=int(
                parameters["initialTreasuryReserveTokens"]
            ),
        ),
        nav_registry_version=int(parameters["minNavRegistryVersion"]),
    )


def _coin(value: Mapping[str, Any], field: str) -> Any:
    from chia.types.blockchain_format.coin import Coin
    from chia_rs.sized_bytes import bytes32
    from chia_rs.sized_ints import uint64

    coin = Coin(
        bytes32(
            _hex_bytes(
                str(value["parentCoinInfo"]), 32, f"{field}.parentCoinInfo", nonzero=False
            )
        ),
        bytes32(
            _hex_bytes(
                str(value["puzzleHash"]), 32, f"{field}.puzzleHash", nonzero=False
            )
        ),
        uint64(int(value["amount"])),
    )
    expected = str(value.get("expectedCoinId", "")).lower()
    if expected and _hex(coin.name()).lower() != expected:
        raise ValueError(f"{field} record does not match its expected coin id")
    return coin


def _funding_coins(values: Mapping[str, Mapping[str, Any]]) -> Any:
    from solslot_puzzles.genesis_ceremony import GenesisFundingCoins

    return GenesisFundingCoins(
        sgt=_coin(values["sgt"], "sgt"),
        pool=_coin(values["pool"], "pool"),
        did=_coin(values["did"], "did"),
        governance=_coin(values["governance"], "governance"),
        nav_registry=_coin(values["navRegistry"], "navRegistry"),
        protocol_config=_coin(values["protocolConfig"], "protocolConfig"),
        admin_authority=_coin(values["adminAuthority"], "adminAuthority"),
        vault_version_registry=_coin(
            values["vaultVersionRegistry"], "vaultVersionRegistry"
        ),
        bridge_batch=_coin(values["bridgeBatch"], "bridgeBatch"),
    )


def _expected_outputs(plan: Any) -> list[str]:
    from chia.types.blockchain_format.coin import Coin
    from chia_rs.sized_ints import uint64

    outputs = [
        _hex(
            Coin(
                plan.funding.sgt,
                plan.base_protocol.sgt_full_puzhash,
                uint64(plan.base_protocol.params.sgt_total_supply),
            ).name()
        )
    ]
    surfaces = (
        (plan.base_protocol.pool_launcher_id, plan.base_protocol.pool_full_puzhash),
        (plan.base_protocol.did_launcher_id, plan.base_protocol.did_full_puzhash),
        (
            plan.base_protocol.tracker_launcher_id,
            plan.base_protocol.tracker_full_puzhash,
        ),
        (plan.nav_registry.launcher_id, plan.nav_registry.full_puzzle_hash),
        (plan.protocol_config.launcher_id, plan.protocol_config.full_puzzle_hash),
        (plan.admin_authority.launcher_id, plan.admin_authority.full_puzzle_hash),
        (
            plan.vault_version_registry.launcher_id,
            plan.vault_version_registry.full_puzzle_hash,
        ),
    )
    outputs.extend(
        _hex(Coin(parent, puzzle_hash, uint64(1)).name())
        for parent, puzzle_hash in surfaces
    )
    outputs.extend(_hex(coin.name()) for coin in plan.bridge_batch.bridge_coins)
    return outputs


def _verify_artifact(artifact: Mapping[str, Any]) -> None:
    from solslot_puzzles.artifact_schema_v2 import (
        artifact_signing_typed_data,
        verify_public_artifact,
    )

    from .evm_auth import recover_evm_signer

    def verify_signature(
        payload: Mapping[str, Any], index: int, pubkey: bytes, signature: bytes
    ) -> bool:
        del index
        try:
            recovered = recover_evm_signer(
                artifact_signing_typed_data(payload), "0x" + signature.hex()
            )
        except (ValueError, TypeError):
            return False
        return recovered.compressed_pubkey == pubkey

    verify_public_artifact(artifact, signature_verifier=verify_signature)


def execute(payload: Mapping[str, Any]) -> dict[str, Any]:
    operation = payload.get("operation")
    if operation == "roster":
        from solslot_puzzles.admin_authority_v2_driver import (
            build_genesis_eip712_admin_quorum,
        )

        quorum = build_genesis_eip712_admin_quorum(
            network="testnet11",
            compressed_pubkeys=[
                _hex_bytes(str(value), 33, "administrator pubkey")
                for value in payload["compressedPubkeys"]
            ],
        )
        return {
            "adminsHash": _hex(quorum.admins_hash),
            "mipsRootHash": _hex(quorum.mips_root_hash),
        }

    if operation not in {"plan", "bundle", "outputs", "artifact"}:
        if operation == "verifyArtifact":
            _verify_artifact(payload["artifact"])
            return {"verified": True}
        raise ValueError("unsupported genesis worker operation")

    plan = _build_plan(
        payload["ceremony"], payload["planInput"], int(payload["expiresAt"])
    )
    canonical_plan = plan.canonical_payload()
    if operation == "plan":
        return {"plan": canonical_plan, "planHash": _hex(plan.plan_hash)}
    if operation == "outputs":
        return {
            "plan": canonical_plan,
            "planHash": _hex(plan.plan_hash),
            "coinIds": _expected_outputs(plan),
        }
    if operation == "artifact":
        from solslot_puzzles.artifact_schema_v2 import build_public_artifact

        artifact = build_public_artifact(
            plan=plan,
            spend_bundle_id=str(payload["spendBundleId"]),
            confirmed_block_index=int(payload["confirmedBlockIndex"]),
            build_timestamp=payload.get("buildTimestamp"),
            review_class=str(
                payload["ceremony"]["draft"].get(
                    "reviewClass", "independent-release-review"
                )
            ),
        )
        return {"plan": canonical_plan, "artifact": artifact}

    from solslot_puzzles.genesis_ceremony import build_genesis_ceremony_bundle

    from .faucet import Faucet

    faucet = Faucet.from_master_private_key_hex(
        str(payload["faucetMasterPrivateKey"]), str(payload["network"])
    )
    funding = _funding_coins(payload["fundingCoins"])
    bundle = build_genesis_ceremony_bundle(
        plan=plan, faucet=faucet, funding_coins=funding
    )
    return {
        "plan": canonical_plan,
        "planHash": _hex(plan.plan_hash),
        "spendBundle": bundle.spend_bundle.to_json_dict(),
        "spendBundleId": bundle.spend_bundle_id,
        "spendCount": len(bundle.spend_bundle.coin_spends),
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        result = execute(payload)
    except Exception as exc:
        json.dump(
            {"error": str(exc), "errorType": type(exc).__name__},
            sys.stderr,
            sort_keys=True,
        )
        sys.stderr.write("\n")
        return 1
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["execute", "main"]
