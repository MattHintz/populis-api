"""Authority V3 publication package for reviewed SGT allocations."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, get_innerpuzzle_from_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.admin_authority_v3_driver import (
    AUTHORITY_LAUNCHER_AMOUNT,
    IDENTITY_LAUNCHER_AMOUNTS,
    GenesisAdminAuthorityV3,
    IdentityVaultGenesis,
    build_authority_operational_mips_spend,
    build_identity_operational_action,
    build_identity_operational_solution,
    build_operational_solution,
)
from solslot_puzzles.eip712_helpers import (
    build_eip712_member_solution,
    eip712_hash_to_sign,
    eip712_prefix_and_domain_separator,
    eip712_typed_data_for_coin_spend,
    genesis_challenge_for_network,
)
from solslot_puzzles.mint_publish_driver import build_tracker_propose_coin_spend
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import (
    admin_governance_proposal_message,
    proposal_tracker_v2_inner_puzzle,
    sgt_free_inner_mod,
    sgt_free_inner_puzzle,
    sgt_locked_inner_mod,
)
from solslot_puzzles.sgt_reserve_driver import (
    build_reserve_lock_coin_spend,
    sgt_cat_puzzle,
    sgt_reserve_inner_puzzle,
)

from .admin_authority_v3 import (
    AdminAuthorityV3Snapshot,
    LiveSingletonContext,
    build_admin_authority_v3_snapshot,
    load_live_singleton_context,
)
from .admin_key_changes import (
    _assert_full_puzzle_hash,
    _authority_inner_from_snapshot,
    _current_identity_vaults,
    _genesis_authority_from_artifact,
    _singleton_spend,
    _verified_evidence_context,
)
from .genesis_store import GenesisStore
from .governance_queue import GovernanceQueueRecord, GovernanceQueueStore


CREATE_PUZZLE_ANNOUNCEMENT = 62


@dataclass(frozen=True)
class GovernanceSigningAction:
    action_id: str
    signer_slot: int
    signer_public_key: str
    message_hash: str
    coin_id: str
    delegated_puzzle_hash: str
    typed_data: dict[str, Any]

    def to_wire(self, *, signed: bool) -> dict[str, Any]:
        return {
            "actionId": self.action_id,
            "signerSlot": self.signer_slot,
            "signerPublicKey": self.signer_public_key,
            "messageHash": self.message_hash,
            "coinId": self.coin_id,
            "delegatedPuzzleHash": self.delegated_puzzle_hash,
            "typedData": self.typed_data,
            "network": "Testnet11",
            "title": (
                "Owner approves proposal publication"
                if self.signer_slot == 0
                else "Coadministrator approves proposal publication"
            ),
            "summary": (
                "Approve this exact SGT allocation for committee voting. "
                "This cannot publish another bill or move unrelated assets."
            ),
            "financialEffect": "No sale completes when this proposal is published.",
            "signed": signed,
        }


@dataclass(frozen=True)
class GovernancePublicationBuild:
    record: GovernanceQueueRecord
    snapshot: AdminAuthorityV3Snapshot
    authority: GenesisAdminAuthorityV3
    authority_inner: Program
    identities: tuple[IdentityVaultGenesis, IdentityVaultGenesis, IdentityVaultGenesis]
    authority_context: LiveSingletonContext
    identity_contexts: tuple[LiveSingletonContext, LiveSingletonContext, LiveSingletonContext]
    tracker_context: LiveSingletonContext
    tracker_inner: Program
    reserve_coin: Coin
    reserve_lineage: LineageProof
    reserve_inner: Program
    bill: Program
    proposal_hash: bytes32
    deadline: int
    coadmin_slot: int
    delegated_puzzle: Program
    actions: tuple[GovernanceSigningAction, GovernanceSigningAction]
    bundle: SpendBundle | None
    proposal_coin_id: str | None


def _hex32(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _b32(value: object, label: str) -> bytes32:
    try:
        raw = bytes.fromhex(str(value).lower().removeprefix("0x"))
    except ValueError as exc:
        raise ValueError(f"{label} must be 32-byte hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32-byte hex")
    return bytes32(raw)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"signed artifact {label} is unavailable")
    return value


def _coordinate(
    artifact: Mapping[str, Any],
    plan: Mapping[str, Any],
    group: str,
    key: str,
) -> Any:
    root_group = artifact.get(group)
    if isinstance(root_group, Mapping) and key in root_group:
        return root_group[key]
    plan_group = plan.get(group)
    if isinstance(plan_group, Mapping) and key in plan_group:
        return plan_group[key]
    raise ValueError(f"signed artifact coordinate {group}.{key} is unavailable")


def _coin(record: Mapping[str, Any]) -> Coin | None:
    payload = record.get("coin")
    if not isinstance(payload, Mapping):
        return None
    try:
        return Coin(
            _b32(payload.get("parent_coin_info"), "coin parent"),
            _b32(payload.get("puzzle_hash"), "coin puzzle hash"),
            uint64(int(payload.get("amount"))),
        )
    except (TypeError, ValueError):
        return None


def _action(
    *,
    slot: int,
    identity: IdentityVaultGenesis,
    coin_id: bytes32,
    delegated_puzzle_hash: bytes32,
    proposal_hash: bytes32,
) -> GovernanceSigningAction:
    prefix = eip712_prefix_and_domain_separator(
        genesis_challenge_for_network("testnet11")
    )
    digest = eip712_hash_to_sign(prefix, coin_id, delegated_puzzle_hash)
    payload = {
        "schemaVersion": 1,
        "purpose": "SGT_ALLOCATION_PROPOSAL",
        "proposalHash": _hex32(proposal_hash),
        "signerSlot": slot,
        "coinId": _hex32(coin_id),
        "delegatedPuzzleHash": _hex32(delegated_puzzle_hash),
        "messageHash": _hex32(digest),
    }
    action_id = "0x" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return GovernanceSigningAction(
        action_id=action_id,
        signer_slot=slot,
        signer_public_key="0x" + identity.daily_compressed_pubkey.hex(),
        message_hash=_hex32(digest),
        coin_id=_hex32(coin_id),
        delegated_puzzle_hash=_hex32(delegated_puzzle_hash),
        typed_data=eip712_typed_data_for_coin_spend(
            network="testnet11",
            coin_id=coin_id,
            delegated_puzzle_hash=delegated_puzzle_hash,
        ),
    )


async def build_governance_publication(
    *,
    record: GovernanceQueueRecord,
    coadmin_slot: int,
    request: Any,
    settings: Any,
    genesis_store: GenesisStore,
    queue_store: GovernanceQueueStore,
    actor: str,
    now: int | None = None,
) -> GovernancePublicationBuild:
    if record.state != "READY":
        raise ValueError("proposal must be reviewed before publication")
    if coadmin_slot not in (1, 2):
        raise ValueError("choose administrator 2 or administrator 3")
    provider = getattr(request.app.state, "coinset", None)
    if provider is None:
        raise ValueError("Testnet11 Chia provider is unavailable")

    artifact, evidence, _coordinator = await _verified_evidence_context(settings)
    plan = _mapping(artifact.get("genesisPlan", artifact), "genesisPlan")
    snapshot = await build_admin_authority_v3_snapshot(
        artifact=artifact,
        provider=provider,
    )
    if not snapshot.chain_verified or snapshot.current_coin_id is None:
        raise ValueError("Authority V3 is not confirmed on Testnet11")
    if snapshot.pending:
        raise ValueError("administrator key recovery is active; protocol writes are frozen")

    authority = _genesis_authority_from_artifact(artifact)
    identities = _current_identity_vaults(
        artifact=artifact,
        evidence=evidence,
        store=genesis_store,
        authority=authority,
    )
    authority_inner = _authority_inner_from_snapshot(snapshot)
    authority_context = await load_live_singleton_context(
        provider=provider,
        launcher_id=snapshot.launcher_id,
    )
    identity_contexts = tuple(
        [
            await load_live_singleton_context(
                provider=provider,
                launcher_id=snapshot.identities[slot].launcher_id,
            )
            for slot in range(3)
        ]
    )
    _assert_full_puzzle_hash(
        context=authority_context,
        launcher_id=authority.authority_launcher_id,
        inner_puzzle=authority_inner,
        label="Authority V3",
    )
    for slot, identity in enumerate(identities):
        _assert_full_puzzle_hash(
            context=identity_contexts[slot],
            launcher_id=identity.launcher_id,
            inner_puzzle=identity.custody_reveal,
            label=f"administrator identity {slot + 1}",
        )

    launchers = _mapping(plan.get("launcherIds"), "launcherIds")
    puzzles = _mapping(plan.get("puzzleHashes"), "puzzleHashes")
    parameters = _mapping(plan.get("protocolParameters"), "protocolParameters")
    governance = _mapping(artifact.get("governanceStruct"), "governanceStruct")
    tracker_launcher = _b32(launchers.get("governance"), "governance launcher")
    pool_launcher = _b32(launchers.get("pool"), "pool launcher")
    statutes_launcher = _b32(launchers.get("statutes"), "statutes launcher")
    admin_launcher = _b32(launchers.get("adminAuthority"), "authority launcher")
    sgt_tail = _b32(
        artifact.get("sgtTailHash")
        or _mapping(plan.get("permanentRules"), "permanentRules").get(
            "sgtTailHash"
        ),
        "SGT tail hash",
    )
    kos_pubkey = bytes.fromhex(
        str(governance.get("mintExecuteCosignerPubkey")).removeprefix("0x")
    )
    tracker_inner = proposal_tracker_v2_inner_puzzle(
        singleton_struct(tracker_launcher),
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        bytes32(CAT_MOD.get_tree_hash()),
        sgt_tail,
        _b32(puzzles.get("didFull"), "DID full puzzle hash"),
        singleton_struct(pool_launcher),
        singleton_struct(admin_launcher),
        singleton_struct(statutes_launcher),
        int(parameters.get("quorumBps")),
        int(parameters.get("votingWindowSeconds")),
        int(parameters.get("sgtTotalSupply")),
        int(parameters.get("minProposalStake")),
        kos_pubkey,
    )
    if bytes32(tracker_inner.get_tree_hash()) != _b32(
        puzzles.get("governanceInner"), "governance inner puzzle hash"
    ):
        raise ValueError("governance tracker does not match signed release evidence")
    tracker_context = await load_live_singleton_context(
        provider=provider,
        launcher_id=_hex32(tracker_launcher),
    )
    _assert_full_puzzle_hash(
        context=tracker_context,
        launcher_id=tracker_launcher,
        inner_puzzle=tracker_inner,
        label="idle governance tracker",
    )

    treasury = _b32(
        _mapping(plan.get("trustedDestinations"), "trustedDestinations").get(
            "companySgtSaleTreasuryPuzzleHash"
        ),
        "company SGT treasury",
    )
    wusdc_b_asset_id = _b32(
        _mapping(plan.get("trustedAssets"), "trustedAssets").get(
            "wusdcBAssetId"
        ),
        "trusted wUSDC.b asset ID",
    )
    reserve_inner = sgt_reserve_inner_puzzle(
        proposal_tracker_struct=singleton_struct(tracker_launcher),
        admin_authority_struct=singleton_struct(admin_launcher),
        sgt_tail_hash=sgt_tail,
        wusdc_b_asset_id=wusdc_b_asset_id,
        company_treasury_puzzle_hash=treasury,
    )
    if bytes32(reserve_inner.get_tree_hash()) != _b32(
        puzzles.get("sgtReserveInner"), "SGT reserve inner puzzle hash"
    ):
        raise ValueError("SGT reserve does not match signed release evidence")
    reserve_free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        singleton_struct(tracker_launcher),
        bytes32(reserve_inner.get_tree_hash()),
    )
    reserve_full = sgt_cat_puzzle(
        proposal_tracker_struct=singleton_struct(tracker_launcher),
        sgt_tail_hash=sgt_tail,
        owner_inner_puzzle=reserve_inner,
    )
    records = await provider.get_coin_records_by_puzzle_hash(
        _hex32(reserve_full.get_tree_hash()),
        include_spent=False,
    )
    candidates = [
        coin
        for item in records
        if isinstance(item, Mapping)
        and not int(item.get("spent_block_index") or 0)
        and (coin := _coin(item)) is not None
    ]
    if len(candidates) != 1:
        raise ValueError("company SGT reserve must be one confirmed unspent coin")
    reserve_coin = candidates[0]
    minimum_stake = int(parameters.get("minProposalStake"))
    if int(reserve_coin.amount) < minimum_stake:
        raise ValueError("company SGT reserve is below the minimum proposal stake")
    genesis_sgt_coin = _b32(
        artifact.get("sgtGenesisCoinId"),
        "SGT genesis coin",
    )
    if reserve_coin.name() == genesis_sgt_coin:
        reserve_lineage = LineageProof()
    else:
        parent_record = await provider.get_coin_record_by_name(
            _hex32(reserve_coin.parent_coin_info)
        )
        parent_coin = _coin(parent_record) if isinstance(parent_record, Mapping) else None
        height = int((parent_record or {}).get("spent_block_index") or 0)
        if parent_coin is None or height <= 0:
            raise ValueError("SGT reserve parent is unavailable")
        parent_solution = await provider.get_puzzle_and_solution(
            _hex32(parent_coin.name()),
            height,
        )
        if not isinstance(parent_solution, Mapping):
            raise ValueError("SGT reserve parent spend is unavailable")
        parent_puzzle = Program.from_bytes(
            bytes.fromhex(str(parent_solution["puzzle_reveal"]).removeprefix("0x"))
        )
        parent_inner = get_innerpuzzle_from_puzzle(parent_puzzle)
        if bytes32(parent_inner.get_tree_hash()) != bytes32(
            reserve_free_inner.get_tree_hash()
        ):
            raise ValueError("SGT reserve lineage changed owner")
        reserve_lineage = LineageProof(
            parent_name=parent_coin.parent_coin_info,
            inner_puzzle_hash=bytes32(parent_inner.get_tree_hash()),
            amount=parent_coin.amount,
        )

    bill = Program.from_bytes(bytes.fromhex(record.bill_clvm_hex.removeprefix("0x")))
    proposal_hash = bytes32(bill.get_tree_hash())
    if _hex32(proposal_hash) != record.proposal_hash.lower():
        raise ValueError("queued proposal hash does not match its canonical bill")
    timestamp = int(time.time()) if now is None else now
    if record.publication_coadmin_slot is None:
        record = queue_store.bind_publication_coadmin(
            proposal_id=record.id,
            coadmin_slot=coadmin_slot,
            actor=actor,
            now=timestamp,
        )
    elif record.publication_coadmin_slot != coadmin_slot:
        raise ValueError("a different coadministrator is already assigned")
    deadline = timestamp + int(parameters.get("votingWindowSeconds"))
    requested_sgt = int(record.bill.get("sgtAmount") or 0)
    if requested_sgt <= 0 or requested_sgt > int(reserve_coin.amount):
        raise ValueError("SGT allocation exceeds the confirmed company reserve")
    if record.kind == "SGT_SALE" and int(record.bill.get("expiresAt") or 0) <= deadline:
        raise ValueError("SGT sale must remain available beyond the committee vote")
    delegated_puzzle = Program.to(
        (
            1,
            [[CREATE_PUZZLE_ANNOUNCEMENT, admin_governance_proposal_message(proposal_hash)]],
        )
    )
    mips = build_authority_operational_mips_spend(
        authority=authority,
        current_authority_inner_puzzle=authority_inner,
        current_identities=identities,
        current_identity_coin_ids=tuple(
            bytes32(context.coin.name()) for context in identity_contexts
        ),
        authority_delegated_puzzle=delegated_puzzle,
        coadmin_slot=coadmin_slot,
    )
    actions = tuple(
        _action(
            slot=slot,
            identity=identities[slot],
            coin_id=bytes32(identity_contexts[slot].coin.name()),
            delegated_puzzle_hash=bytes32(
                build_identity_operational_action(
                    identity=identities[slot],
                    current_authority_inner_puzzle=authority_inner,
                    authority_delegated_puzzle=delegated_puzzle,
                ).get_tree_hash()
            ),
            proposal_hash=proposal_hash,
        )
        for slot in mips.selected_slots
    )
    stored = {item.action_id: item for item in queue_store.signatures(record.id)}
    if any(action.action_id not in stored for action in actions):
        bundle = None
        proposal_coin_id = None
    else:
        action_by_slot = {action.signer_slot: action for action in actions}
        authority_solution = build_operational_solution(
            my_amount=AUTHORITY_LAUNCHER_AMOUNT,
            new_authority_version=snapshot.authority_version + 1,
            mips_reveal=mips.reveal,
            mips_solution=mips.solution,
            authority_delegated_puzzle=delegated_puzzle,
            identity_records=mips.identity_records,
        )
        spends = [
            _singleton_spend(
                context=authority_context,
                inner_puzzle=authority_inner,
                inner_solution=authority_solution,
                amount=AUTHORITY_LAUNCHER_AMOUNT,
            )
        ]
        for slot in mips.selected_slots:
            action = action_by_slot[slot]
            signature = bytes.fromhex(stored[action.action_id].signature.removeprefix("0x"))
            member_solution = build_eip712_member_solution(
                network="testnet11",
                coin_id=bytes32(identity_contexts[slot].coin.name()),
                delegated_puzzle_hash=_b32(
                    action.delegated_puzzle_hash,
                    "identity delegated puzzle hash",
                ),
                compressed_pubkey=identities[slot].daily_compressed_pubkey,
                signature=signature,
            )
            spends.append(
                _singleton_spend(
                    context=identity_contexts[slot],
                    inner_puzzle=identities[slot].custody_reveal,
                    inner_solution=build_identity_operational_solution(
                        identity=identities[slot],
                        current_authority_inner_puzzle=authority_inner,
                        current_identity_coin_id=bytes32(
                            identity_contexts[slot].coin.name()
                        ),
                        daily_member_solution=member_solution,
                        authority_delegated_puzzle=delegated_puzzle,
                    ),
                    amount=IDENTITY_LAUNCHER_AMOUNTS[slot],
                )
            )
        tracker_spend = build_tracker_propose_coin_spend(
            tracker_coin=tracker_context.coin,
            tracker_inner_puzzle=tracker_inner,
            tracker_launcher_id=tracker_launcher,
            lineage_proof=lineage_proof_for_coinsol(tracker_context.parent_spend),
            proposal_hash=proposal_hash,
            bill_operation=bill,
            voter_inner_puzzle_hash=bytes32(reserve_inner.get_tree_hash()),
            first_vote_amount=int(reserve_coin.amount),
            voting_deadline=deadline,
        )
        spends.append(tracker_spend)
        spends.append(
            build_reserve_lock_coin_spend(
                reserve_coin=reserve_coin,
                reserve_lineage_proof=reserve_lineage,
                proposal_tracker_struct=singleton_struct(tracker_launcher),
                admin_authority_struct=singleton_struct(admin_launcher),
                sgt_tail_hash=sgt_tail,
                wusdc_b_asset_id=wusdc_b_asset_id,
                company_treasury_puzzle_hash=treasury,
                bill=bill,
                deadline=deadline,
                admin_authority_inner_puzzle_hash=bytes32(authority_inner.get_tree_hash()),
            )
        )
        bundle = SpendBundle(spends, G2Element())
        tracker_children = [
            coin for coin in bundle.additions()
            if coin.parent_coin_info == tracker_context.coin.name()
            and int(coin.amount) == int(tracker_context.coin.amount)
        ]
        if len(tracker_children) != 1:
            raise ValueError("proposal tracker successor is missing or ambiguous")
        proposal_coin_id = _hex32(tracker_children[0].name())

    return GovernancePublicationBuild(
        record=record,
        snapshot=snapshot,
        authority=authority,
        authority_inner=authority_inner,
        identities=identities,
        authority_context=authority_context,
        identity_contexts=identity_contexts,  # type: ignore[arg-type]
        tracker_context=tracker_context,
        tracker_inner=tracker_inner,
        reserve_coin=reserve_coin,
        reserve_lineage=reserve_lineage,
        reserve_inner=reserve_inner,
        bill=bill,
        proposal_hash=proposal_hash,
        deadline=deadline,
        coadmin_slot=coadmin_slot,
        delegated_puzzle=delegated_puzzle,
        actions=actions,  # type: ignore[arg-type]
        bundle=bundle,
        proposal_coin_id=proposal_coin_id,
    )


__all__ = [
    "GovernancePublicationBuild",
    "GovernanceSigningAction",
    "build_governance_publication",
]
