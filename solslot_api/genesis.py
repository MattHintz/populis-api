"""Three-administrator, deterministic Solslot V2 genesis orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .admin import require_admin_token
from .coinset_client import CoinsetClient
from .config import Settings, get_settings
from .evm_auth import normalize_evm_address, recover_evm_signer
from .genesis_store import (
    GenesisConflict,
    GenesisExpired,
    GenesisNotFound,
    GenesisStore,
    GenesisStoreError,
)
from .genesis_evm import GenesisEvmEvidenceError, verify_genesis_evm_deployment
from .validator_quorum import (
    ValidatorHealthResponse,
    ValidatorQuorumError,
    probe_validator_health,
)


router = APIRouter(prefix="/admin/genesis", tags=["admin-genesis"])

REQUIRED_SOURCE_SHAS = (
    "protocol",
    "evm",
    "api",
    "legacyBackend",
    "customerWeb",
    "adminPortal",
)
REQUIRED_EVM_ADDRESSES = ("forwarder", "verifierAdapter", "attestationEmitter")
REQUIRED_AUDIT_LANES = (
    "protocol",
    "evm",
    "credentialBridge",
    "ceremonyOrchestrator",
)
INDEPENDENT_REVIEW_CLASS = "independent-release-review"
INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS = "internal-engineering-testnet"


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class DraftRequest(ApiModel):
    source_shas: dict[str, str] = Field(alias="sourceShas")
    review_class: Literal[
        "independent-release-review", "internal-engineering-testnet"
    ] = Field(INDEPENDENT_REVIEW_CLASS, alias="reviewClass")

    @field_validator("source_shas")
    @classmethod
    def validate_source_shas(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value) != set(REQUIRED_SOURCE_SHAS):
            raise ValueError("sourceShas must contain all six frozen release commits")
        normalized: dict[str, str] = {}
        for key in REQUIRED_SOURCE_SHAS:
            sha = value[key].lower()
            if len(sha) != 40:
                raise ValueError(f"sourceShas.{key} must be a full commit SHA")
            int(sha, 16)
            normalized[key] = sha
        return normalized


class InvitationPrepareRequest(ApiModel):
    token: str = Field(min_length=32, max_length=256)
    wallet: str


class InvitationAcceptRequest(InvitationPrepareRequest):
    signature: str


class FundingCoinIds(ApiModel):
    sgt: str
    pool: str
    did: str
    governance: str
    nav_registry: str = Field(alias="navRegistry")
    protocol_config: str = Field(alias="protocolConfig")
    admin_authority: str = Field(alias="adminAuthority")
    vault_version_registry: str = Field(alias="vaultVersionRegistry")
    bridge_batch: str = Field(alias="bridgeBatch")


class ProtocolParameters(ApiModel):
    quorum_bps: int = Field(5000, alias="quorumBps", ge=1, le=10000)
    voting_window_seconds: int = Field(300, alias="votingWindowSeconds", ge=1)
    sgt_total_supply: int = Field(1_000_000, alias="sgtTotalSupply", ge=1)
    min_proposal_stake: int = Field(10_000, alias="minProposalStake", ge=1)
    fp_scale: int = Field(1000, alias="fpScale", ge=1)
    min_nav_registry_version: int = Field(1, alias="minNavRegistryVersion", ge=1)
    initial_pool_status: int = Field(1, alias="initialPoolStatus", ge=0, le=1)
    initial_total_pool_token_supply: int = Field(
        0, alias="initialTotalPoolTokenSupply", ge=0
    )
    initial_treasury_reserve_tokens: int = Field(
        0, alias="initialTreasuryReserveTokens", ge=0
    )


class PlanRequest(ApiModel):
    evm_addresses: dict[str, str] = Field(alias="evmAddresses")
    funding_coin_ids: FundingCoinIds = Field(alias="fundingCoinIds")
    faucet_puzzle_hash: str = Field(alias="faucetPuzzleHash")
    governance_bls_pubkey: str = Field(alias="governanceBlsPubkey")
    # A dedicated public key for the MINT-only KoS co-sign condition. It is
    # sealed into the governance puzzle and signed ceremony artifact; the
    # private key is never submitted to this API.
    kos_mint_execute_pubkey: str = Field(alias="kosMintExecutePubkey")
    validator_pubkeys: list[str] = Field(alias="validatorPubkeys", min_length=3, max_length=3)
    trusted_treasury_reserve_puzzle_hash: str = Field(
        alias="trustedTreasuryReservePuzzleHash"
    )
    trusted_protocol_treasury_puzzle_hash: str = Field(
        alias="trustedProtocolTreasuryPuzzleHash"
    )
    trusted_governance_rewards_puzzle_hash: str = Field(
        alias="trustedGovernanceRewardsPuzzleHash"
    )
    trusted_governance_rewards_root: str = Field(alias="trustedGovernanceRewardsRoot")
    retired_coordinates: list[str] = Field(
        alias="retiredCoordinates", min_length=1
    )
    protocol_parameters: ProtocolParameters = Field(
        default_factory=ProtocolParameters, alias="protocolParameters"
    )


class SignatureRequest(ApiModel):
    slot: int = Field(ge=1, le=3)
    signature: str


class SignaturePrepareRequest(ApiModel):
    slot: int = Field(ge=1, le=3)


class AbandonRequest(ApiModel):
    reason: str = Field(min_length=8, max_length=1000)


@lru_cache(maxsize=8)
def _store_for_path(path: str) -> GenesisStore:
    return GenesisStore(path)


def get_genesis_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> GenesisStore:
    return _store_for_path(settings.genesis_db_path)


def _coinset() -> CoinsetClient:
    from .app import app

    coinset = getattr(app.state, "coinset", None)
    if coinset is None:
        raise HTTPException(status_code=503, detail="Coinset client is unavailable.")
    return coinset


def _faucet() -> Any:
    from .app import app

    faucet = getattr(app.state, "faucet", None)
    if faucet is None:
        raise HTTPException(status_code=503, detail="Ceremony faucet is unavailable.")
    return faucet


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


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _raise_store_error(exc: GenesisStoreError) -> None:
    if isinstance(exc, GenesisNotFound):
        code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, GenesisExpired):
        code = status.HTTP_410_GONE
    else:
        code = status.HTTP_409_CONFLICT
    raise HTTPException(status_code=code, detail=str(exc)) from exc


def _safe_state(record: dict[str, Any]) -> dict[str, Any]:
    """Return the operator view without invitation token hashes."""
    for invitation in record.get("invitations", []):
        invitation.pop("token_hash", None)
    return record


def _admin_pubkeys(record: Mapping[str, Any]) -> list[bytes]:
    invitations = record.get("invitations")
    if not isinstance(invitations, list) or len(invitations) != 3:
        raise GenesisConflict("three enrolled administrators are required")
    ordered = sorted(invitations, key=lambda item: int(item["slot"]))
    if [int(item["slot"]) for item in ordered] != [1, 2, 3]:
        raise GenesisConflict("administrator roster slots are incomplete")
    return [
        _hex_bytes(str(item["compressed_pubkey"]), 33, "administrator pubkey")
        for item in ordered
    ]


async def _run_worker(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Execute CLVM work in a fresh interpreter and return canonical JSON."""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "solslot_api.genesis_worker",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(encoded), timeout=180
        )
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise GenesisConflict("isolated ceremony worker timed out") from exc
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        try:
            parsed = json.loads(detail)
            detail = str(parsed.get("error") or "ceremony worker failed")
        except json.JSONDecodeError:
            detail = detail[-2000:] or "ceremony worker failed"
        raise GenesisConflict(f"isolated ceremony worker rejected input: {detail}")
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise GenesisConflict("isolated ceremony worker returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise GenesisConflict("isolated ceremony worker returned an invalid result")
    return result


def _plan_typed_data(record: Mapping[str, Any]) -> dict[str, Any]:
    from solslot_puzzles.genesis_signing import genesis_plan_signing_typed_data

    return genesis_plan_signing_typed_data(
        ceremony_id=str(record["ceremony_id"]),
        roster_hash=str(record["roster_hash"]),
        plan_hash=str(record["plan_hash"]),
        expires_at=int(record["plan_expires_at"]),
    )


def _recover_expected(
    typed_data: dict[str, Any], signature: str, expected_pubkey: str | None = None
) -> Any:
    try:
        recovered = recover_evm_signer(typed_data, signature)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid EIP-712 signature: {exc}") from exc
    if expected_pubkey and recovered.compressed_pubkey_hex.lower() != expected_pubkey.lower():
        raise HTTPException(status_code=403, detail="Signature does not match roster slot.")
    return recovered


def _atomic_json(path: Path, payload: Any, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    data = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    with temporary.open("w", encoding="ascii") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


@router.post("/drafts", dependencies=[Depends(require_admin_token)])
async def create_draft(
    body: DraftRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    ceremony_id = "0x" + secrets.token_hex(32)
    output = Path(settings.genesis_output_dir) / ceremony_id[2:]
    if output.exists() and any(output.iterdir()):
        raise HTTPException(status_code=409, detail="Ceremony output directory is not empty.")
    draft = {
        "schemaVersion": 2,
        "network": "testnet11",
        "evmChainId": 11155111,
        "reviewClass": body.review_class,
        "sourceShas": body.source_shas,
    }
    try:
        return _safe_state(store.create_draft(ceremony_id, draft))
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.get("/{ceremony_id}", dependencies=[Depends(require_admin_token)])
async def ceremony_status(
    ceremony_id: str,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        return _safe_state(store.get(ceremony_id.lower()))
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post(
    "/{ceremony_id}/invitations/{slot}", dependencies=[Depends(require_admin_token)]
)
async def issue_invitation(
    ceremony_id: str,
    slot: int,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    nonce = "0x" + secrets.token_hex(32)
    expires_at = int(time.time()) + settings.genesis_invitation_ttl_seconds
    try:
        invitation = store.issue_invitation(
            ceremony_id.lower(),
            slot=slot,
            token_hash=_token_hash(token),
            nonce=nonce,
            expires_at=expires_at,
        )
    except (GenesisStoreError, ValueError) as exc:
        if isinstance(exc, GenesisStoreError):
            _raise_store_error(exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ceremonyId": ceremony_id.lower(),
        "slot": slot,
        "expiresAt": invitation["expires_at"],
        "invitationFragment": "#genesis-admin=" + token,
    }


def _invitation_typed_data(
    store: GenesisStore, token: str, wallet: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    from solslot_puzzles.genesis_signing import genesis_admin_enrollment_typed_data

    try:
        normalized_wallet = normalize_evm_address(wallet, "wallet")
        invitation = store.invitation_for_token(_token_hash(token))
        if invitation["consumed_at"] is not None:
            raise GenesisConflict("invitation was already consumed")
        if int(invitation["expires_at"]) < int(time.time()):
            raise GenesisExpired("invitation expired")
        typed = genesis_admin_enrollment_typed_data(
            ceremony_id=str(invitation["ceremony_id"]),
            slot=int(invitation["slot"]),
            wallet=normalized_wallet,
            nonce=str(invitation["nonce"]),
            expires_at=int(invitation["expires_at"]),
        )
        return invitation, typed
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/invitations/prepare")
async def prepare_invitation(
    body: InvitationPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    invitation, typed = _invitation_typed_data(store, body.token, body.wallet)
    return {
        "ceremonyId": invitation["ceremony_id"],
        "slot": invitation["slot"],
        "expiresAt": invitation["expires_at"],
        "typedData": typed,
    }


@router.post("/invitations/accept")
async def accept_invitation(
    body: InvitationAcceptRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    invitation, typed = _invitation_typed_data(store, body.token, body.wallet)
    recovered = _recover_expected(typed, body.signature)
    expected = normalize_evm_address(body.wallet, "wallet")
    if recovered.address.lower() != expected.lower():
        raise HTTPException(status_code=403, detail="Signature wallet does not match invitation.")
    try:
        record = store.consume_invitation(
            token_hash=_token_hash(body.token),
            wallet_address=recovered.address.lower(),
            compressed_pubkey=recovered.compressed_pubkey_hex.lower(),
            signature=body.signature.lower(),
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    return {
        "ceremonyId": invitation["ceremony_id"],
        "slot": invitation["slot"],
        "enrolled": True,
        "state": record["state"],
    }


@router.post("/{ceremony_id}/roster/freeze", dependencies=[Depends(require_admin_token)])
async def freeze_roster(
    ceremony_id: str,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        quorum = await _run_worker(
            {
                "operation": "roster",
                "compressedPubkeys": [_hex(value) for value in _admin_pubkeys(current)],
            }
        )
        return _safe_state(
            store.freeze_roster(ceremony_id.lower(), str(quorum["adminsHash"]))
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{ceremony_id}/plan", dependencies=[Depends(require_admin_token)])
async def create_plan(
    ceremony_id: str,
    body: PlanRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        expires_at = int(time.time()) + settings.genesis_plan_ttl_seconds
        input_payload = body.model_dump(by_alias=True)
        result = await _run_worker(
            {
                "operation": "plan",
                "ceremony": current,
                "planInput": input_payload,
                "expiresAt": expires_at,
            }
        )
        plan = result["plan"]
        if plan["adminAuthority"]["adminsHash"] != current["roster_hash"]:
            raise GenesisConflict("deterministic plan roster does not match frozen roster")
        created = store.set_plan(
            ceremony_id.lower(),
            plan_input=input_payload,
            plan=plan,
            plan_hash=str(result["planHash"]),
            expires_at=expires_at,
        )
        return {
            "ceremony": _safe_state(created),
            "typedData": _plan_typed_data(created),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{ceremony_id}/plan/signatures")
async def sign_plan(
    ceremony_id: str,
    body: SignatureRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        members = {int(item["slot"]): item for item in current["invitations"]}
        member = members.get(body.slot)
        if member is None or not member.get("compressed_pubkey"):
            raise GenesisConflict("administrator slot is not enrolled")
        recovered = _recover_expected(
            _plan_typed_data(current), body.signature, str(member["compressed_pubkey"])
        )
        return _safe_state(
            store.add_plan_signature(
                ceremony_id.lower(),
                slot=body.slot,
                plan_hash=str(current["plan_hash"]),
                compressed_pubkey=recovered.compressed_pubkey_hex.lower(),
                signature=body.signature.lower(),
            )
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/plan/signatures/prepare")
async def prepare_plan_signature(
    ceremony_id: str,
    body: SignaturePrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        members = {int(item["slot"]): item for item in current["invitations"]}
        member = members.get(body.slot)
        if member is None or not member.get("compressed_pubkey"):
            raise GenesisConflict("administrator slot is not enrolled")
        if not current.get("plan_hash") or not current.get("plan_expires_at"):
            raise GenesisConflict("deterministic ceremony plan has not been created")
        return {
            "ceremonyId": ceremony_id.lower(),
            "slot": body.slot,
            "typedData": _plan_typed_data(current),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


async def _live_funding(
    record: Mapping[str, Any], coinset: CoinsetClient
) -> dict[str, dict[str, Any]]:
    names = (
        "sgt",
        "pool",
        "did",
        "governance",
        "navRegistry",
        "protocolConfig",
        "adminAuthority",
        "vaultVersionRegistry",
        "bridgeBatch",
    )
    records: dict[str, dict[str, Any]] = {}
    for name in names:
        coin_id = str(record["plan_input"]["fundingCoinIds"][name]).lower()
        coin_record = await coinset.get_coin_record_by_name(coin_id)
        if coin_record is None:
            raise GenesisConflict(f"funding coin {name} is missing")
        if coin_record.get("spent") is True or int(coin_record.get("spent_block_index") or 0):
            raise GenesisConflict(f"funding coin {name} is already spent")
        if int(coin_record.get("confirmed_block_index") or 0) <= 0:
            raise GenesisConflict(f"funding coin {name} is not confirmed")
        coin = coin_record.get("coin") or coin_record
        try:
            records[name] = {
                "parentCoinInfo": str(coin["parent_coin_info"]),
                "puzzleHash": str(coin["puzzle_hash"]),
                "amount": int(coin["amount"]),
                "expectedCoinId": coin_id,
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise GenesisConflict(f"funding coin {name} record is malformed") from exc
    return records


def _validate_audit_approval(
    settings: Settings,
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
    spend_bundle_id: str,
) -> dict[str, Any]:
    path = Path(settings.genesis_audit_approval_path)
    if not path.is_file():
        raise GenesisConflict("independent audit approval file is missing")
    try:
        approval = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GenesisConflict("independent audit approval file is invalid") from exc
    expected = {
        "schemaVersion": 2,
        "ceremonyId": record["ceremony_id"],
        "planHash": record["plan_hash"],
        "sourceShas": record["draft"]["sourceShas"],
        "consensusSimulationBundleId": spend_bundle_id,
    }
    for key, value in expected.items():
        if approval.get(key) != value:
            raise GenesisConflict(f"audit approval {key} does not match ceremony")
    lanes = approval.get("approvals")
    if not isinstance(lanes, list) or {item.get("lane") for item in lanes} != set(
        REQUIRED_AUDIT_LANES
    ):
        raise GenesisConflict("all four independent audit lanes must approve")
    for lane in lanes:
        if lane.get("approved") is not True or not str(lane.get("reviewer", "")).strip():
            raise GenesisConflict(f"audit lane {lane.get('lane')} is not approved")
        _hex_bytes(str(lane.get("evidenceHash", "")), 32, "audit evidence hash")

    deployments = approval.get("evmContracts")
    if not isinstance(deployments, Mapping) or set(deployments) != set(
        REQUIRED_EVM_ADDRESSES
    ):
        raise GenesisConflict("audit approval lacks fresh EVM deployment evidence")
    for name in REQUIRED_EVM_ADDRESSES:
        deployment = deployments[name]
        if (
            str(deployment.get("address", "")).lower()
            != str(plan["evmAddresses"][name]).lower()
        ):
            raise GenesisConflict(f"audited EVM address {name} does not match plan")
        _hex_bytes(str(deployment.get("bytecodeHash", "")), 32, "bytecodeHash")
        if int(deployment.get("confirmations", 0)) < settings.genesis_sepolia_confirmations:
            raise GenesisConflict(f"EVM deployment {name} lacks 12 confirmations")

    validators = approval.get("validators")
    expected_keys = list(plan["validatorSet"]["pubkeys"])
    if not isinstance(validators, Mapping):
        raise GenesisConflict("validator health evidence is missing")
    if validators.get("threshold") != 2 or validators.get("pubkeys") != expected_keys:
        raise GenesisConflict("validator health evidence does not match plan")
    return approval


def _internal_review_approval(
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
    spend_bundle_id: str,
    evm_evidence: Mapping[str, Any],
    validator_health: tuple[ValidatorHealthResponse, ...],
) -> dict[str, Any]:
    invitations = sorted(
        record.get("invitations") or [], key=lambda item: int(item.get("slot", 0))
    )
    if len(invitations) != 3 or any(
        not item.get("wallet_address") or not item.get("compressed_pubkey")
        for item in invitations
    ):
        raise GenesisConflict("internal testnet review requires three enrolled administrators")
    plan_signatures = sorted(
        record.get("plan_signatures") or [], key=lambda item: int(item.get("slot", 0))
    )
    signer_slots = [int(item.get("slot", 0)) for item in plan_signatures]
    if len(set(signer_slots)) < 2:
        raise GenesisConflict("internal testnet review requires two administrator signatures")
    if len(validator_health) != 3:
        raise GenesisConflict("internal testnet review requires three live validators")
    if any(item.artifactReady for item in validator_health):
        raise GenesisConflict(
            "a pre-genesis validator has a stale signed artifact installed"
        )

    contracts = evm_evidence.get("contracts")
    if not isinstance(contracts, Mapping) or set(contracts) != set(
        REQUIRED_EVM_ADDRESSES
    ):
        raise GenesisConflict("live EVM deployment evidence is incomplete")
    return {
        "schemaVersion": 2,
        "reviewClass": INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
        "auditStatus": "unaudited",
        "testOnly": True,
        "ceremonyId": record["ceremony_id"],
        "planHash": record["plan_hash"],
        "sourceShas": record["draft"]["sourceShas"],
        "consensusSimulationBundleId": spend_bundle_id,
        "administratorReview": {
            "threshold": 2,
            "roster": [
                {
                    "slot": int(item["slot"]),
                    "wallet": str(item["wallet_address"]).lower(),
                    "compressedPubkey": str(item["compressed_pubkey"]).lower(),
                }
                for item in invitations
            ],
            "planSignerSlots": signer_slots,
        },
        "evmManifestArtifactHash": evm_evidence["manifestArtifactHash"],
        "evmCheckedAtBlock": evm_evidence["checkedAtBlock"],
        "evmContracts": {name: dict(contracts[name]) for name in REQUIRED_EVM_ADDRESSES},
        "validators": {
            "threshold": 2,
            "pubkeys": list(plan["validatorSet"]["pubkeys"]),
            "healthy": [True, True, True],
            "signerIndices": [item.signerIndex for item in validator_health],
            "artifactReady": [item.artifactReady for item in validator_health],
            "ledgerReady": [item.ledgerReady for item in validator_health],
        },
    }


async def _prepare_bundle(
    settings: Settings, record: Mapping[str, Any]
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    tuple[ValidatorHealthResponse, ...],
]:
    faucet = _faucet()
    if _hex(faucet.address_puzzle_hash).lower() != str(
        record["plan_input"]["faucetPuzzleHash"]
    ).lower():
        raise GenesisConflict("ceremony faucet no longer matches signed plan")
    funding = await _live_funding(record, _coinset())
    result = await _run_worker(
        {
            "operation": "bundle",
            "ceremony": record,
            "planInput": record["plan_input"],
            "expiresAt": int(record["plan_expires_at"]),
            "fundingCoins": funding,
            "faucetMasterPrivateKey": bytes(faucet.master_sk).hex(),
            "network": settings.network,
        }
    )
    plan = result["plan"]
    if plan != record["plan"] or result["planHash"] != record["plan_hash"]:
        raise GenesisConflict("stored ceremony plan does not reproduce exactly")
    try:
        validator_health = await probe_validator_health(
            settings,
            expected_api_commit=str(record["draft"]["sourceShas"]["api"]),
            expected_protocol_commit=str(record["draft"]["sourceShas"]["protocol"]),
            expected_network=str(plan["network"]),
            expected_bridge_policy_hash=str(plan["puzzleHashes"]["bridgePolicy"]),
            expected_evm_addresses={
                key: str(plan["evmAddresses"][key]) for key in REQUIRED_EVM_ADDRESSES
            },
            expected_artifact_ready=False,
        )
    except (KeyError, TypeError, ValidatorQuorumError) as exc:
        raise GenesisConflict(f"live validator preflight failed: {exc}") from exc
    review_class = str(
        record.get("draft", {}).get("reviewClass", INDEPENDENT_REVIEW_CLASS)
    )
    if review_class == INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS:
        if str(plan.get("network")) != "testnet11":
            raise GenesisConflict(
                "internal engineering review is permitted on testnet11 only"
            )
        try:
            evm_evidence = await asyncio.to_thread(
                verify_genesis_evm_deployment, settings, record, plan
            )
        except GenesisEvmEvidenceError as exc:
            raise GenesisConflict(f"live Sepolia preflight failed: {exc}") from exc
        approval = _internal_review_approval(
            record,
            plan,
            str(result["spendBundleId"]),
            evm_evidence,
            validator_health,
        )
    elif review_class == INDEPENDENT_REVIEW_CLASS:
        approval = _validate_audit_approval(
            settings, record, plan, str(result["spendBundleId"])
        )
    else:
        raise GenesisConflict("unsupported genesis review class")
    return plan, result, approval, validator_health


@router.post("/{ceremony_id}/preflight", dependencies=[Depends(require_admin_token)])
async def preflight(
    ceremony_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        if record["state"] != "plan_approved":
            raise GenesisConflict("two administrator plan signatures are required")
        plan, bundle, approval, validator_health = await _prepare_bundle(settings, record)
        output = Path(settings.genesis_output_dir) / ceremony_id.lower().removeprefix("0x")
        if output.exists() and any(output.iterdir()):
            raise GenesisConflict("ceremony output directory is not empty")
        return {
            "ready": True,
            "ceremonyId": ceremony_id.lower(),
            "planHash": plan["planHash"],
            "spendBundleId": bundle["spendBundleId"],
            "spendCount": bundle["spendCount"],
            "reviewClass": approval.get("reviewClass", INDEPENDENT_REVIEW_CLASS),
            "auditStatus": approval.get("auditStatus", "independently-reviewed"),
            "auditApprovalHash": "0x"
            + hashlib.sha256(
                json.dumps(approval, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "reviewApproval": approval,
            "validatorHealth": [
                item.model_dump(mode="json") for item in validator_health
            ],
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/broadcast", dependencies=[Depends(require_admin_token)])
async def broadcast(
    ceremony_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        if record["state"] != "plan_approved":
            raise GenesisConflict("two administrator plan signatures are required")
        plan, bundle, approval, validator_health = await _prepare_bundle(settings, record)
        output = Path(settings.genesis_output_dir) / ceremony_id.lower().removeprefix("0x")
        if output.exists() and any(output.iterdir()):
            raise GenesisConflict("ceremony output directory is not empty")
        output.mkdir(parents=True, exist_ok=False)
        _atomic_json(output / "plan.json", plan)
        _atomic_json(output / "spend_bundle.json", bundle["spendBundle"])
        _atomic_json(output / "audit_approval.json", approval)
        _atomic_json(
            output / "validator_health.json",
            {
                "checkedAt": int(time.time()),
                "signers": [item.model_dump(mode="json") for item in validator_health],
            },
        )
        try:
            response = await _coinset().push_tx(bundle["spendBundle"])
        except Exception as exc:
            store.abandon(ceremony_id.lower(), "Ambiguous Coinset broadcast failure")
            raise GenesisConflict(
                "Coinset response was ambiguous; ceremony was abandoned and must not be retried"
            ) from exc
        accepted = response.get("success") is True or str(response.get("status", "")).upper() in {
            "SUCCESS",
            "PENDING",
        }
        if not accepted:
            store.abandon(ceremony_id.lower(), "Coinset rejected the deterministic bundle")
            raise GenesisConflict("Coinset rejected the bundle; ceremony was abandoned")
        return _safe_state(
            store.mark_broadcast(
                ceremony_id.lower(),
                spend_bundle_id=str(bundle["spendBundleId"]),
                response=response,
            )
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/confirmation", dependencies=[Depends(require_admin_token)])
async def confirm(
    ceremony_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        if record["state"] != "broadcast":
            raise GenesisConflict("ceremony bundle has not been broadcast")
        result = await _run_worker(
            {
                "operation": "outputs",
                "ceremony": record,
                "planInput": record["plan_input"],
                "expiresAt": int(record["plan_expires_at"]),
            }
        )
        if result["plan"] != record["plan"] or result["planHash"] != record["plan_hash"]:
            raise GenesisConflict("stored ceremony plan does not reproduce exactly")
        heights: list[int] = []
        for coin_id in result["coinIds"]:
            coin_record = await _coinset().get_coin_record_by_name(coin_id)
            if coin_record is None:
                raise GenesisConflict("not all deterministic ceremony outputs are confirmed")
            if coin_record.get("spent") is True or int(coin_record.get("spent_block_index") or 0):
                raise GenesisConflict("a ceremony output was spent before artifact finalization")
            height = int(coin_record.get("confirmed_block_index") or 0)
            if height <= 0:
                raise GenesisConflict("a ceremony output is not confirmed")
            heights.append(height)
        chain_state = await _coinset().get_blockchain_state()
        peak = int(
            ((chain_state.get("blockchain_state") or {}).get("peak") or {}).get("height")
            or 0
        )
        newest = max(heights)
        confirmations = peak - newest + 1
        if confirmations < settings.genesis_chia_confirmations:
            raise GenesisConflict(
                f"ceremony has {confirmations} Chia confirmations; three are required"
            )
        return _safe_state(
            store.mark_confirmed(
                ceremony_id.lower(), confirmed_block_index=newest
            )
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/artifact", dependencies=[Depends(require_admin_token)])
async def create_artifact(
    ceremony_id: str,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        if record["state"] != "confirmed":
            raise GenesisConflict("ceremony must have three Chia confirmations")
        result = await _run_worker(
            {
                "operation": "artifact",
                "ceremony": record,
                "planInput": record["plan_input"],
                "expiresAt": int(record["plan_expires_at"]),
                "spendBundleId": str(record["spend_bundle_id"]),
                "confirmedBlockIndex": int(record["confirmed_block_index"]),
            }
        )
        if result["plan"] != record["plan"]:
            raise GenesisConflict("stored ceremony plan does not reproduce exactly")
        artifact = result["artifact"]
        created = store.set_artifact(
            ceremony_id.lower(),
            artifact=artifact,
            artifact_hash=str(artifact["artifactHash"]),
        )
        from solslot_puzzles.genesis_signing import (
            genesis_artifact_signing_typed_data,
        )

        return {
            "ceremony": _safe_state(created),
            "typedData": genesis_artifact_signing_typed_data(artifact),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/artifact/signatures")
async def sign_artifact(
    ceremony_id: str,
    body: SignatureRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    from solslot_puzzles.genesis_signing import genesis_artifact_signing_typed_data

    try:
        record = store.get(ceremony_id.lower())
        if not record.get("artifact"):
            raise GenesisConflict("canonical artifact has not been created")
        members = {int(item["slot"]): item for item in record["invitations"]}
        member = members.get(body.slot)
        if member is None or not member.get("compressed_pubkey"):
            raise GenesisConflict("administrator slot is not enrolled")
        recovered = _recover_expected(
            genesis_artifact_signing_typed_data(record["artifact"]),
            body.signature,
            str(member["compressed_pubkey"]),
        )
        return _safe_state(
            store.add_artifact_signature(
                ceremony_id.lower(),
                slot=body.slot,
                artifact_hash=str(record["artifact_hash"]),
                compressed_pubkey=recovered.compressed_pubkey_hex.lower(),
                signature=body.signature.lower(),
            )
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/artifact/signatures/prepare")
async def prepare_artifact_signature(
    ceremony_id: str,
    body: SignaturePrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    from solslot_puzzles.genesis_signing import genesis_artifact_signing_typed_data

    try:
        current = store.get(ceremony_id.lower())
        members = {int(item["slot"]): item for item in current["invitations"]}
        member = members.get(body.slot)
        if member is None or not member.get("compressed_pubkey"):
            raise GenesisConflict("administrator slot is not enrolled")
        if not current.get("artifact") or not current.get("artifact_hash"):
            raise GenesisConflict("canonical artifact has not been created")
        return {
            "ceremonyId": ceremony_id.lower(),
            "slot": body.slot,
            "typedData": genesis_artifact_signing_typed_data(current["artifact"]),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/finalize", dependencies=[Depends(require_admin_token)])
async def finalize(
    ceremony_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        if record["state"] != "artifact_signed":
            raise GenesisConflict("two artifact signatures are required")
        artifact = dict(record["artifact"])
        artifact["signatures"] = [
            {
                "adminIndex": int(entry["slot"]) - 1,
                "compressedPubkey": entry["compressed_pubkey"],
                "signature": entry["signature"],
            }
            for entry in record["artifact_signatures"]
        ]

        await _run_worker({"operation": "verifyArtifact", "artifact": artifact})
        public_path = Path(settings.public_artifact_path)
        lock_path = Path(settings.bootstrap_manifest_path)
        if public_path.exists() or lock_path.exists():
            raise GenesisConflict(
                "public artifact or bootstrap lock already exists; use fresh paths"
            )
        output = Path(settings.genesis_output_dir) / ceremony_id.lower().removeprefix("0x")
        if not output.is_dir():
            raise GenesisConflict("private ceremony evidence directory is missing")
        _atomic_json(output / "public_artifact.json", artifact)
        _atomic_json(public_path, artifact)
        evidence_files = sorted(path for path in output.iterdir() if path.is_file())
        sums = "".join(
            hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
            for path in evidence_files
        )
        sums_path = output / "sha256sums.txt"
        sums_path.write_text(sums, encoding="ascii")
        with sums_path.open("rb") as handle:
            os.fsync(handle.fileno())

        # The lock manifest is intentionally the final public file written.
        lock = {
            "schemaVersion": 2,
            "protocolVersion": "solslot-v2",
            "reviewClass": artifact["reviewClass"],
            "testOnly": artifact["testOnly"],
            "auditStatus": artifact["auditStatus"],
            "ceremonyId": ceremony_id.lower(),
            "planHash": record["plan_hash"],
            "artifactHash": artifact["artifactHash"],
            "spendBundleId": record["spend_bundle_id"],
            "confirmedBlockIndex": record["confirmed_block_index"],
            "lockedAt": int(time.time()),
        }
        _atomic_json(lock_path, lock, mode=0o444)
        locked = store.mark_locked(ceremony_id.lower())
        return {
            "locked": True,
            "artifactHash": artifact["artifactHash"],
            "publicArtifactPath": str(public_path),
            "bootstrapLockPath": str(lock_path),
            "ceremony": _safe_state(locked),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/abandon", dependencies=[Depends(require_admin_token)])
async def abandon(
    ceremony_id: str,
    body: AbandonRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        return _safe_state(store.abandon(ceremony_id.lower(), body.reason))
    except GenesisStoreError as exc:
        _raise_store_error(exc)


__all__ = ["router", "get_genesis_store"]
