"""Guided, role-aware control plane for the one-time Testnet11 launch.

This router intentionally wraps the existing genesis state machine. It does
not duplicate ceremony transitions or accept operator-supplied protocol
coordinates. The browser receives plain-language tasks and decision receipts;
the underlying signed evidence remains downloadable for technical review.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping, Optional

import jwt as pyjwt
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import G2Element, SpendBundle
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings, get_settings
from .evm_auth import normalize_evm_address, recover_evm_signer
from .genesis import (
    INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    PlanRequest,
    SignaturePrepareRequest,
    SignatureRequest,
    _invitation_typed_data,
    _prepare_bundle,
    _token_hash,
    accept_invitation,
    broadcast,
    confirm,
    create_artifact,
    create_plan,
    finalize,
    freeze_roster,
    get_genesis_store,
    prepare_artifact_signature,
    prepare_plan_signature,
    sign_artifact,
    sign_plan,
)
from .genesis_funding import (
    FUNDING_NAMES,
    GENESIS_BRIDGE_BATCH_FUNDING_AMOUNT,
    plan_genesis_funding_fanout,
)
from .genesis_store import (
    COADMIN_SLOTS,
    OWNER_SLOT,
    GenesisConflict,
    GenesisExpired,
    GenesisNotFound,
    GenesisStore,
    GenesisStoreError,
)
from .launch_rehearsal import (
    HEX32_RE,
    LaunchRehearsalError,
    persist_evidence,
    rehearsal_status,
    start_rehearsal,
    submit_rehearsal_transaction,
)
from .omnichain_ownership_activation import (
    BroadcastRequest as OwnershipBroadcastRequest,
    OwnershipActivationError,
    OwnershipActivationStore,
    SignatureRequest as OwnershipSignatureRequest,
    _chain_state,
    _public_status,
    get_ownership_activation_store,
    load_authority_operation,
    record_ownership_activation_broadcast,
    record_ownership_execution_broadcast,
    sign_ownership_activation,
    sign_ownership_execution,
)


router = APIRouter(prefix="/admin/launch", tags=["admin-launch"])

LAUNCH_COOKIE_NAME = "solslot_launch_session"
LAUNCH_SCOPE = "alpha-launch"
SOURCE_KEYS = (
    "protocol",
    "evm",
    "omnichain",
    "api",
    "legacyBackend",
    "keyOfSolomon",
    "samuel",
    "customerWeb",
    "adminPortal",
)
GATE_NAMES = ("ceremonyBroadcast", "minting", "presale", "purchases")
CREATE_COIN = 51
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class OwnerClaimRequest(ApiModel):
    token: str = Field(min_length=32, max_length=512)
    display_name: str = Field("Owner", alias="displayName", min_length=2, max_length=80)
    email: Optional[str] = Field(None, max_length=254)
    timezone: str = Field("America/Chicago", min_length=1, max_length=64)


class InviteProfileRequest(ApiModel):
    display_name: str = Field(alias="displayName", min_length=2, max_length=80)
    email: Optional[str] = Field(None, max_length=254)
    timezone: str = Field("America/Chicago", min_length=1, max_length=64)
    reminders_enabled: bool = Field(True, alias="remindersEnabled")


class InvitationPrepareRequest(ApiModel):
    token: str = Field(min_length=32, max_length=512)
    wallet: str


class InvitationAcceptRequest(InvitationPrepareRequest):
    signature: str


class ResumeChallengeRequest(ApiModel):
    wallet: str


class ResumeLoginRequest(ApiModel):
    wallet: str
    nonce: str
    signature: str


class ProfileUpdateRequest(InviteProfileRequest):
    pass


class ActionPrepareRequest(ApiModel):
    action_type: Literal[
        "funding",
        "abandon",
        "gate:ceremonyBroadcast",
        "gate:minting",
        "gate:presale",
        "gate:purchases",
    ] = Field(alias="actionType")


class ActionApproveRequest(ActionPrepareRequest):
    action_id: str = Field(alias="actionId")
    payload_hash: str = Field(alias="payloadHash")
    expires_at: int = Field(alias="expiresAt")
    signature: str


class GateProposalRequest(ApiModel):
    gate: Literal["ceremonyBroadcast", "minting", "presale", "purchases"]
    starts_in_seconds: int = Field(0, alias="startsInSeconds", ge=0, le=86400)
    duration_seconds: int = Field(alias="durationSeconds", ge=300, le=86400)


class SignatureSubmission(ApiModel):
    signature: str


class AbandonPrepareRequest(ApiModel):
    reason: str = Field(min_length=8, max_length=1000)


class RailSignatureSubmission(SignatureSubmission):
    phase: Literal["schedule", "execute"]


class RailBroadcastSubmission(ApiModel):
    phase: Literal["schedule", "execute"]
    transaction_hash: str = Field(alias="transactionHash")


class RehearsalTransactionSubmission(ApiModel):
    transaction_hash: str = Field(alias="transactionHash")


@dataclass(frozen=True)
class LaunchSession:
    ceremony_id: str
    slot: int
    wallet: str | None
    setup: bool
    expires_at: int


_ephemeral_launch_secret: str | None = None


def _hash_json(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _secret(settings: Settings) -> str:
    global _ephemeral_launch_secret
    if settings.launch_session_secret:
        return settings.launch_session_secret
    if settings.bootstrap_session_secret:
        return settings.bootstrap_session_secret
    if _ephemeral_launch_secret is None:
        _ephemeral_launch_secret = secrets.token_hex(32)
    return _ephemeral_launch_secret


def _issue_session(
    settings: Settings,
    *,
    ceremony_id: str,
    slot: int,
    wallet: str | None,
    setup: bool,
) -> tuple[str, int]:
    now = int(time.time())
    expires_at = now + settings.launch_session_ttl_seconds
    token = pyjwt.encode(
        {
            "scope": LAUNCH_SCOPE,
            "ceremonyId": ceremony_id,
            "slot": slot,
            "wallet": wallet,
            "setup": setup,
            "iat": now,
            "exp": expires_at,
        },
        _secret(settings),
        algorithm="HS256",
    )
    return token, expires_at


def _set_session_cookie(
    response: Response, settings: Settings, token: str, expires_at: int
) -> None:
    response.set_cookie(
        LAUNCH_COOKIE_NAME,
        token,
        max_age=max(1, expires_at - int(time.time())),
        httponly=True,
        secure=settings.bootstrap_cookie_secure,
        samesite="strict",
        path=settings.launch_cookie_path,
    )


def _decode_session(token: str, settings: Settings) -> LaunchSession:
    try:
        payload = pyjwt.decode(
            token,
            _secret(settings),
            algorithms=["HS256"],
            options={
                "require": [
                    "scope",
                    "ceremonyId",
                    "slot",
                    "setup",
                    "iat",
                    "exp",
                ]
            },
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Administrator session expired.") from exc
    except pyjwt.InvalidTokenError as exc:
        raise HTTPException(status_code=403, detail="Administrator session is invalid.") from exc
    if payload.get("scope") != LAUNCH_SCOPE:
        raise HTTPException(status_code=403, detail="Administrator session has the wrong scope.")
    return LaunchSession(
        ceremony_id=str(payload["ceremonyId"]),
        slot=int(payload["slot"]),
        wallet=str(payload["wallet"]).lower() if payload.get("wallet") else None,
        setup=bool(payload["setup"]),
        expires_at=int(payload["exp"]),
    )


def require_launch_session(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> LaunchSession:
    if not settings.launch_control_enabled:
        raise HTTPException(status_code=503, detail="Alpha launch control is disabled.")
    token = request.cookies.get(LAUNCH_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Connect an enrolled administrator wallet.")
    session = _decode_session(token, settings)
    try:
        record = store.get(session.ceremony_id)
    except GenesisStoreError as exc:
        raise HTTPException(status_code=401, detail="Administrator launch no longer exists.") from exc
    if session.wallet:
        members = {int(item["slot"]): item for item in record["invitations"]}
        member = members.get(session.slot)
        if (
            member is None
            or not member.get("wallet_address")
            or str(member["wallet_address"]).lower() != session.wallet
        ):
            raise HTTPException(status_code=403, detail="Wallet is not in the launch roster.")
    return session


def _require_wallet_session(session: LaunchSession) -> None:
    if session.setup or not session.wallet:
        raise HTTPException(
            status_code=401,
            detail="Finish owner enrollment and reconnect the enrolled wallet.",
        )


def _require_owner(session: LaunchSession) -> None:
    _require_wallet_session(session)
    if session.slot != OWNER_SLOT:
        raise HTTPException(status_code=403, detail="This action is assigned to the owner.")


def _require_coadmin(session: LaunchSession) -> None:
    _require_wallet_session(session)
    if session.slot not in COADMIN_SLOTS:
        raise HTTPException(
            status_code=403,
            detail="This rehearsal is assigned to a coadministrator.",
        )


def _read_json_file(path_value: str | None, label: str) -> tuple[dict[str, Any], str]:
    if not path_value:
        raise GenesisConflict(f"{label} is not configured")
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise GenesisConflict(f"{label} is unavailable")
    size = path.stat().st_size
    if size <= 0 or size > MAX_EVIDENCE_BYTES:
        raise GenesisConflict(f"{label} has an invalid size")
    raw_bytes = path.read_bytes()
    try:
        value = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GenesisConflict(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise GenesisConflict(f"{label} must be a JSON object")
    return value, hashlib.sha256(raw_bytes).hexdigest()


def _load_release_evidence(settings: Settings) -> dict[str, Any]:
    evidence, digest = _read_json_file(
        settings.launch_source_evidence_path, "RC21 source evidence"
    )
    if settings.launch_source_evidence_sha256:
        expected = settings.launch_source_evidence_sha256.removeprefix("0x").lower()
        if not secrets.compare_digest(digest, expected):
            raise GenesisConflict("RC21 source evidence checksum changed")
    if (
        evidence.get("network") != "testnet11"
        or evidence.get("releaseTag") != settings.launch_release_tag
        or evidence.get("completeReleaseManifest") is not True
        or evidence.get("testOnly") is not True
    ):
        raise GenesisConflict("RC21 source evidence is incomplete or targets another release")
    source_manifest = evidence.get("sourceManifest")
    shas = source_manifest.get("sourceShas") if isinstance(source_manifest, Mapping) else None
    if not isinstance(shas, Mapping) or set(shas) != set(SOURCE_KEYS):
        raise GenesisConflict("RC21 evidence does not freeze all nine source commits")
    for key in SOURCE_KEYS:
        value = str(shas[key]).lower()
        if len(value) != 40:
            raise GenesisConflict(f"RC21 source commit {key} is not a full SHA")
        try:
            int(value, 16)
        except ValueError as exc:
            raise GenesisConflict(f"RC21 source commit {key} is invalid") from exc
    return {
        "releaseTag": evidence["releaseTag"],
        "manifestHash": evidence.get("manifestHash"),
        "fileSha256": "0x" + digest,
        "sourceShas": {key: str(shas[key]).lower() for key in SOURCE_KEYS},
        "evidence": evidence,
    }


def _resume_typed_data(
    *,
    ceremony_id: str,
    slot: int,
    wallet: str,
    nonce: str,
    expires_at: int,
) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "SolslotLaunchResume": [
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "slot", "type": "uint8"},
                {"name": "wallet", "type": "address"},
                {"name": "nonce", "type": "bytes32"},
                {"name": "expiresAt", "type": "uint64"},
            ],
        },
        "primaryType": "SolslotLaunchResume",
        "domain": {"name": "Solslot Alpha Launch", "version": "21", "chainId": 11155111},
        "message": {
            "ceremonyId": ceremony_id,
            "slot": slot,
            "wallet": normalize_evm_address(wallet, "wallet"),
            "nonce": nonce,
            "expiresAt": expires_at,
        },
    }


def _action_typed_data(
    *,
    ceremony_id: str,
    action_type: str,
    action_id: str,
    payload_hash: str,
    expires_at: int,
) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "SolslotLaunchAction": [
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "actionType", "type": "string"},
                {"name": "actionId", "type": "bytes32"},
                {"name": "payloadHash", "type": "bytes32"},
                {"name": "expiresAt", "type": "uint64"},
            ],
        },
        "primaryType": "SolslotLaunchAction",
        "domain": {"name": "Solslot Alpha Launch", "version": "21", "chainId": 11155111},
        "message": {
            "ceremonyId": ceremony_id,
            "actionType": action_type,
            "actionId": action_id,
            "payloadHash": payload_hash,
            "expiresAt": expires_at,
        },
    }


def _typed_digest(typed_data: Mapping[str, Any]) -> str:
    signable = encode_typed_data(full_message=dict(typed_data))
    return "0x" + keccak(
        b"\x19" + bytes(signable.version) + signable.header + signable.body
    ).hex()


def _funding_payload(store: GenesisStore, ceremony_id: str) -> tuple[str, str]:
    receipt = store.funding_receipt(ceremony_id)
    if not receipt:
        raise GenesisConflict("prepare the fixed ceremony funding first")
    payload_hash = str(receipt["planHash"])
    return "0x" + hashlib.sha256(
        f"{ceremony_id}:funding:{payload_hash}".encode("ascii")
    ).hexdigest(), payload_hash


def _gate_payload(
    store: GenesisStore, ceremony_id: str, gate_name: str
) -> tuple[str, str]:
    gate = store.gates(ceremony_id).get(gate_name)
    if not gate:
        raise GenesisConflict("prepare the timed gate first")
    payload_hash = str(gate["payloadHash"])
    return "0x" + hashlib.sha256(
        f"{ceremony_id}:gate:{gate_name}:{payload_hash}".encode("ascii")
    ).hexdigest(), payload_hash


def _action_payload(
    store: GenesisStore, ceremony_id: str, action_type: str
) -> tuple[str, str]:
    if action_type == "funding":
        return _funding_payload(store, ceremony_id)
    if action_type.startswith("gate:"):
        return _gate_payload(store, ceremony_id, action_type.split(":", 1)[1])
    if action_type == "abandon":
        intent = store.latest_action_intent(ceremony_id, "abandon")
        if not intent or intent["state"] != "prepared":
            raise GenesisConflict("prepare the abandonment reason first")
        return str(intent["actionId"]), str(intent["payloadHash"])
    raise GenesisConflict("the requested action is not prepared")


def _gate_open(
    settings: Settings, store: GenesisStore, ceremony_id: str, gate_name: str
) -> None:
    if not settings.alpha_writes_enabled:
        raise GenesisConflict("the server chain-write ceiling is closed")
    if gate_name == "ceremonyBroadcast" and not settings.ceremony_mode_enabled:
        raise GenesisConflict("the server ceremony ceiling is closed")
    gate = store.gates(ceremony_id).get(gate_name)
    if not gate or gate["state"] != "open":
        raise GenesisConflict(f"the signed {gate_name} window is closed")


def _funding_ceiling_open(settings: Settings) -> None:
    if not settings.alpha_writes_enabled or not settings.ceremony_mode_enabled:
        raise GenesisConflict("the server ceremony funding ceiling is closed")


def _decision_receipt(action_type: str, payload_hash: str) -> dict[str, Any]:
    labels = {
        "funding": (
            "Create the nine ceremony funding coins",
            "Moves 1,000,558 testnet mojos into nine fixed ceremony inputs. No fee.",
            "Creates fixed Testnet11 outputs; it cannot redirect funds.",
        ),
        "gate:ceremonyBroadcast": (
            "Open the launch window",
            "Allows only the exact approved Testnet11 ceremony bundle until expiry.",
            "The window closes automatically and cannot override the server ceiling.",
        ),
        "gate:minting": (
            "Open minting",
            "Temporarily permits approved collection mint operations on Testnet11.",
            "The window closes automatically.",
        ),
        "gate:presale": (
            "Open presale",
            "Temporarily permits governed refundable voucher reservations on Testnet11.",
            "The window closes automatically.",
        ),
        "gate:purchases": (
            "Open purchases",
            "Temporarily permits eligible test purchases on Testnet11.",
            "The window closes automatically.",
        ),
        "abandon": (
            "Abandon this alpha launch",
            "No payment is made. The active ceremony becomes permanently unusable.",
            "This cannot be undone. A future launch must start from a fresh ceremony.",
        ),
    }
    title, effect, reversibility = labels[action_type]
    return {
        "title": title,
        "network": "Testnet11",
        "financialEffect": effect,
        "customerImpact": "TESTNET only. No real investment or legal right.",
        "reversibility": reversibility,
        "requiredApprovers": "Owner plus either coadministrator",
        "payloadHash": payload_hash,
    }


def _rail_phase_status(
    settings: Settings, store: OwnershipActivationStore
) -> dict[str, Any]:
    schedule_package = load_authority_operation(settings, phase="schedule")
    schedule = _public_status(
        settings=settings, package=schedule_package, store=store
    )
    if schedule["state"] in {"SCHEDULED", "READY_TO_EXECUTE", "DONE"}:
        execute_package = load_authority_operation(settings, phase="execute")
        execute = _public_status(
            settings=settings, package=execute_package, store=store
        )
        if execute["state"] != "WAITING_FOR_SCHEDULE" or schedule["state"] == "DONE":
            return execute
    return schedule


def _rail_decision_receipt(status_value: Mapping[str, Any]) -> dict[str, Any]:
    phase = str(status_value["phase"])
    return {
        "title": (
            "Schedule the Base Sepolia ownership handoff"
            if phase == "schedule"
            else "Accept Base Sepolia ownership after the safety delay"
        ),
        "network": "Base Sepolia",
        "financialEffect": "No protocol or customer funds move. The submitting wallet pays test gas.",
        "customerImpact": (
            "Schedules the reviewed Safe and timelock ownership transfer."
            if phase == "schedule"
            else "Activates the reviewed Safe and timelock as the payment-rail authority."
        ),
        "reversibility": (
            "A 24-hour timelock must finish before execution."
            if phase == "schedule"
            else "Execution is final for these reviewed contracts."
        ),
        "requiredApprovers": "Owner plus either coadministrator, using fresh Safe approvals",
        "expectedResult": (
            "The 24-hour waiting period begins."
            if phase == "schedule"
            else "Payment-rail ownership becomes active and independently verifiable."
        ),
    }


def _require_rail_session_signature(
    status_value: Mapping[str, Any],
    *,
    signature: str,
    session: LaunchSession,
) -> None:
    _require_wallet_session(session)
    matches: list[str] = []
    for descriptor in status_value.get("approvals", []):
        try:
            recovered = recover_evm_signer(descriptor["typedData"], signature)
        except ValueError:
            continue
        if any(
            str(allowed).lower() == recovered.address.lower()
            for allowed in descriptor.get("allowedSigners", [])
        ):
            matches.append(recovered.address.lower())
    if len(matches) != 1 or matches[0] != session.wallet:
        raise GenesisConflict(
            "Safe approval must come from this enrolled administrator wallet"
        )


def _store_rehearsal_status(
    settings: Settings,
    store: GenesisStore,
    ceremony_id: str,
    status_value: dict[str, Any],
) -> dict[str, Any]:
    payload = dict(status_value)
    if status_value["state"] == "SUCCEEDED":
        evidence = status_value.get("evidence")
        if not isinstance(evidence, Mapping):
            raise LaunchRehearsalError("Completed rehearsal evidence is missing.")
        payload["evidenceDigest"] = persist_evidence(settings, evidence)
    return store.set_settlement_rehearsal(
        ceremony_id,
        job_id=str(status_value["jobId"]),
        config_hash=str(status_value["configHash"]),
        state=str(status_value["state"]),
        payload=payload,
    )


def _rehearsal_result(record: Mapping[str, Any] | None) -> dict[str, Any]:
    if record is None:
        status_value: dict[str, Any] = {
            "state": "NOT_STARTED",
            "step": "Ready to prepare the fixed delivery and refund rehearsal.",
            "message": "A technical coadministrator starts this check from a test wallet.",
            "assignedRole": "coadmin",
            "walletTransaction": None,
        }
    else:
        payload = record.get("payload")
        details = payload if isinstance(payload, Mapping) else {}
        status_value = {
            "jobId": record.get("jobId"),
            "state": record.get("state"),
            "step": details.get("step") or "",
            "message": details.get("message") or "",
            "walletTransaction": details.get("walletTransaction"),
            "evidenceDigest": details.get("evidenceDigest"),
            "updatedAt": record.get("updatedAt"),
        }
    return {
        "status": status_value,
        "decisionReceipt": {
            "title": "Submit the fixed Base Sepolia test purchase",
            "network": "Base Sepolia",
            "financialEffect": (
                "Uses test gas and faucet USDC only. No real funds or customer funds move."
            ),
            "customerImpact": (
                "Proves the reviewed payment, validator delivery, SmartDeed delivery, "
                "and exact-refund paths before launch."
            ),
            "reversibility": (
                "This is a bounded test purchase. The rehearsal must prove delivery "
                "or an exact automated refund."
            ),
            "requiredApprovers": "One enrolled technical coadministrator submits the test wallet transaction",
            "expectedResult": (
                "Three validators produce 2-of-3 evidence for both successful delivery "
                "and exact refund."
            ),
        },
    }


def _task_for(record: Mapping[str, Any], readiness: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = next((item for item in readiness if item["status"] == "Blocked"), None)
    if blocked:
        return {
            "title": blocked["title"],
            "body": blocked["impact"],
            "assignedRole": blocked["assignedRole"],
            "action": blocked.get("action"),
        }
    state = str(record["state"])
    enrolled = sum(bool(item.get("consumed_at")) for item in record["invitations"])
    if enrolled < 3:
        return {
            "title": "Finish administrator enrollment",
            "body": f"{enrolled} of 3 administrators are enrolled.",
            "assignedRole": "owner" if enrolled == 0 else "administrator",
            "action": "enrollment",
        }
    unfinished = next(
        (
            item
            for item in readiness
            if item["status"] in {"Needs action", "Waiting"}
        ),
        None,
    )
    if unfinished:
        return {
            "title": unfinished["title"],
            "body": unfinished["impact"],
            "assignedRole": unfinished["assignedRole"],
            "action": unfinished.get("action"),
        }
    mapping = {
        "roster_open": ("Confirm the administrator team", "technical-coadmin", "freezeRoster"),
        "roster_frozen": ("Create and review launch plan", "technical-coadmin", "buildPlan"),
        "planned": ("Approve the launch plan", "administrator", "signPlan"),
        "plan_approved": ("Run final launch check", "owner", "preflight"),
        "broadcast": ("Wait for Testnet11 confirmation", "system", "confirm"),
        "confirmed": ("Create the signed launch record", "system", "createArtifact"),
        "artifact_pending": ("Approve the launch archive", "administrator", "signArtifact"),
        "artifact_signed": ("Seal the launch archive", "owner", "finalize"),
        "locked": ("Launch complete", "owner", "openOperations"),
    }
    title, role, action = mapping.get(
        state, ("Review launch status", "administrator", "refresh")
    )
    return {"title": title, "body": "", "assignedRole": role, "action": action}


async def _readiness(
    request: Request,
    settings: Settings,
    store: GenesisStore,
    record: Mapping[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    try:
        release = _load_release_evidence(settings)
        items.append(
            {
                "id": "release",
                "title": "RC21 release identity",
                "status": "Healthy",
                "impact": f"{release['releaseTag']} is pinned to all nine source commits.",
                "assignedRole": "system",
                "evidence": {
                    "manifestHash": release["manifestHash"],
                    "fileSha256": release["fileSha256"],
                },
            }
        )
    except GenesisStoreError as exc:
        items.append(
            {
                "id": "release",
                "title": "Release package needs attention",
                "status": "Blocked",
                "impact": str(exc),
                "assignedRole": "technical-coadmin",
                "action": "replaceReleaseEvidence",
            }
        )

    try:
        provider = getattr(request.app.state, "coinset", None)
        if provider is None:
            raise RuntimeError("Chia provider is unavailable")
        provider_status = provider.status() if hasattr(provider, "status") else {}
        fallback = provider_status.get("activeProvider") == "fallback"
        items.append(
            {
                "id": "chiaNode",
                "title": "Local Chia node",
                "status": "Needs action" if fallback else "Healthy",
                "impact": (
                    "The fallback provider is active; launching should wait for the local node."
                    if fallback
                    else "The primary Testnet11 provider is available."
                ),
                "assignedRole": "technical-coadmin",
                "evidence": provider_status,
            }
        )
    except Exception as exc:  # noqa: BLE001
        items.append(
            {
                "id": "chiaNode",
                "title": "Local Chia node unavailable",
                "status": "Blocked",
                "impact": str(exc),
                "assignedRole": "technical-coadmin",
                "action": "restoreChiaNode",
            }
        )

    fee_submitter = getattr(request.app.state, "protocol_submitter", None)
    fee_funding_healthy = (
        settings.protocol_fee_funding_enabled
        and fee_submitter is not None
    )
    items.append(
        {
            "id": "networkFee",
            "title": "Network fee funding",
            "status": "Healthy" if fee_funding_healthy else "Blocked",
            "impact": (
                "The fountain till will add the current medium Testnet11 fee "
                "and confirm the launch in the local mempool."
                if fee_funding_healthy
                else "Enable the bounded fountain fee till before launch; "
                "the 530-mojo bridge coin is reserved for ceremony outputs."
            ),
            "assignedRole": "technical-coadmin",
            "action": None if fee_funding_healthy else "configureFeeTill",
            "evidence": {
                "targetSeconds": settings.protocol_medium_fee_target_seconds,
                "minimumMojos": settings.protocol_minimum_fee_mojos,
                "maximumMojos": settings.protocol_maximum_fee_mojos,
                "source": "local-full-node",
            },
        }
    )

    try:
        ownership_store = get_ownership_activation_store(settings)
        ownership = _rail_phase_status(settings, ownership_store)
        done = ownership["state"] == "DONE"
        items.append(
            {
                "id": "railOwnership",
                "title": "Base Sepolia rail ownership",
                "status": "Healthy" if done else "Waiting",
                "impact": (
                    "Safe and timelock ownership is active."
                    if done
                    else f"Rail ownership is {ownership['state'].lower().replace('_', ' ')}."
                ),
                "assignedRole": "technical-coadmin",
                "action": None if done else "railOwnership",
                "evidence": ownership,
            }
        )
    except (OwnershipActivationError, HTTPException) as exc:
        items.append(
            {
                "id": "railOwnership",
                "title": "Base Sepolia rail ownership",
                "status": "Blocked",
                "impact": str(getattr(exc, "detail", exc)),
                "assignedRole": "technical-coadmin",
                "action": "railOwnership",
            }
        )

    try:
        rehearsal_job = store.settlement_rehearsal(str(record["ceremony_id"]))
        if not rehearsal_job or rehearsal_job["state"] != "SUCCEEDED":
            state = rehearsal_job["state"] if rehearsal_job else "not started"
            raise GenesisConflict(f"settlement rehearsal is {state.lower()}")
        rehearsal, digest = _read_json_file(
            settings.launch_settlement_rehearsal_path, "settlement rehearsal evidence"
        )
        lanes = rehearsal.get("lanes")
        healthy = (
            rehearsal.get("schemaVersion") == 2
            and rehearsal.get("kind") == "solslot-rc21-settlement-rehearsal"
            and rehearsal.get("releaseTag") == settings.launch_release_tag
            and rehearsal.get("network") == "testnet11-base-sepolia"
            and rehearsal.get("success") is True
            and rehearsal.get("validatorThreshold") == 2
            and len(rehearsal.get("validators") or []) == 3
            and isinstance(lanes, Mapping)
            and lanes.get("delivery", {}).get("success") is True
            and lanes.get("refund", {}).get("success") is True
            and lanes.get("refund", {}).get("exactRefund") is True
            and rehearsal_job["payload"].get("evidenceDigest") == "0x" + digest
        )
        if not healthy:
            raise GenesisConflict(
                "settlement rehearsal evidence does not prove delivery and exact refund"
            )
        items.append(
            {
                "id": "settlement",
                "title": "Settlement rehearsal",
                "status": "Healthy",
                "impact": "Test payment, SmartDeed delivery, and return evidence passed.",
                "assignedRole": "technical-coadmin",
                "evidence": {"fileSha256": "0x" + digest},
            }
        )
    except (GenesisStoreError, AttributeError) as exc:
        items.append(
            {
                "id": "settlement",
                "title": "Complete the settlement rehearsal",
                "status": "Waiting",
                "impact": str(exc),
                "assignedRole": "technical-coadmin",
                "action": "settlementRehearsal",
            }
        )

    funding = store.funding_receipt(str(record["ceremony_id"]))
    funding_healthy = funding is not None and funding["state"] == "confirmed"
    items.append(
        {
            "id": "funding",
            "title": "Ceremony funding",
            "status": "Healthy" if funding_healthy else "Waiting",
            "impact": (
                "All nine fixed funding coins are confirmed, including the 530-mojo bridge batch."
                if funding_healthy
                else "Create and confirm the fixed nine-output funding transaction."
            ),
            "assignedRole": "owner",
            "action": None if funding_healthy else "funding",
            "evidence": funding,
        }
    )
    return items


def _public_ceremony(record: Mapping[str, Any], store: GenesisStore) -> dict[str, Any]:
    profiles = store.profiles(str(record["ceremony_id"]))
    administrators = []
    invitations = {int(item["slot"]): item for item in record["invitations"]}
    for slot in (1, 2, 3):
        invitation = invitations.get(slot, {})
        administrators.append(
            {
                "slot": slot,
                "role": "Owner" if slot == 1 else "Coadministrator",
                "profile": profiles.get(slot),
                "enrolled": bool(invitation.get("consumed_at")),
                "wallet": invitation.get("wallet_address"),
                "invitationExpiresAt": invitation.get("expires_at"),
            }
        )
    return {
        "ceremonyId": record["ceremony_id"],
        "state": record["state"],
        "network": record["network"],
        "createdAt": record["created_at"],
        "updatedAt": record["updated_at"],
        "administrators": administrators,
        "planHash": record.get("plan_hash"),
        "planExpiresAt": record.get("plan_expires_at"),
        "planSignatureSlots": [
            int(item["slot"]) for item in record.get("plan_signatures", [])
        ],
        "spendBundleId": record.get("spend_bundle_id"),
        "artifactHash": record.get("artifact_hash"),
        "artifactSignatureSlots": [
            int(item["slot"]) for item in record.get("artifact_signatures", [])
        ],
    }


@router.get("/public")
async def public_launch_status(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    return {
        "enabled": settings.launch_control_enabled,
        "network": "testnet11",
        "title": "Alpha Protocol Launch",
        "notice": "TESTNET, NO REAL INVESTMENT OR LEGAL RIGHT.",
    }


@router.post("/claim")
async def claim_owner_link(
    body: OwnerClaimRequest,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    if not settings.launch_control_enabled:
        raise HTTPException(status_code=503, detail="Alpha launch control is disabled.")
    if not settings.admin_token or not secrets.compare_digest(body.token, settings.admin_token):
        raise HTTPException(status_code=403, detail="Owner launch link is invalid.")
    try:
        if store.owner_claim_used(_token_hash(body.token)):
            raise GenesisConflict("owner launch link was already consumed")
        active = store.active()
        if active is None:
            release = _load_release_evidence(settings)
            ceremony_id = "0x" + secrets.token_hex(32)
            active = store.create_draft(
                ceremony_id,
                {
                    "schemaVersion": 2,
                    "sourceManifestVersion": 3,
                    "network": "testnet11",
                    "evmChainId": 11155111,
                    "reviewClass": INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
                    "releaseTag": release["releaseTag"],
                    "releaseEvidenceHash": release["fileSha256"],
                    "sourceShas": release["sourceShas"],
                },
            )
        ceremony_id = str(active["ceremony_id"])
        store.consume_owner_claim(ceremony_id, token_hash=_token_hash(body.token))
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + settings.genesis_invitation_ttl_seconds
        store.issue_invitation(
            ceremony_id,
            slot=OWNER_SLOT,
            token_hash=_token_hash(token),
            nonce="0x" + secrets.token_hex(32),
            expires_at=expires_at,
        )
        store.set_profile(
            ceremony_id,
            slot=OWNER_SLOT,
            display_name=body.display_name,
            role_label="Owner",
            email=str(body.email) if body.email else None,
            timezone=body.timezone,
            reminders_enabled=True,
        )
        session_token, session_expiry = _issue_session(
            settings,
            ceremony_id=ceremony_id,
            slot=OWNER_SLOT,
            wallet=None,
            setup=True,
        )
        _set_session_cookie(response, settings, session_token, session_expiry)
        return {
            "claimed": True,
            "ceremonyId": ceremony_id,
            "ownerEnrollmentToken": token,
            "enrollmentExpiresAt": expires_at,
            "sessionExpiresAt": session_expiry,
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/invitations/prepare")
async def prepare_launch_invitation(
    body: InvitationPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        invitation, typed = _invitation_typed_data(store, body.token, body.wallet)
        return {
            "ceremonyId": invitation["ceremony_id"],
            "slot": invitation["slot"],
            "expiresAt": invitation["expires_at"],
            "typedData": typed,
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/owner/enrollment")
async def reissue_owner_enrollment(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    if not session.setup or session.slot != OWNER_SLOT or session.wallet:
        raise HTTPException(status_code=403, detail="Owner setup is already complete.")
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + settings.genesis_invitation_ttl_seconds
    try:
        store.issue_invitation(
            session.ceremony_id,
            slot=OWNER_SLOT,
            token_hash=_token_hash(token),
            nonce="0x" + secrets.token_hex(32),
            expires_at=expires_at,
            replace_live=True,
        )
        return {
            "ownerEnrollmentToken": token,
            "enrollmentExpiresAt": expires_at,
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/invitations/accept")
async def accept_launch_invitation(
    body: InvitationAcceptRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    from .genesis import InvitationAcceptRequest as GenesisInvitationAcceptRequest

    return await accept_invitation(
        GenesisInvitationAcceptRequest(
            token=body.token, wallet=body.wallet, signature=body.signature
        ),
        store,
    )


@router.post("/auth/challenge")
async def resume_challenge(
    body: ResumeChallengeRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    if not settings.launch_control_enabled:
        raise HTTPException(status_code=503, detail="Alpha launch control is disabled.")
    try:
        wallet = normalize_evm_address(body.wallet, "wallet").lower()
        record = store.active()
        if record is None:
            history = store.list_ceremonies(limit=1)
            record = history[0] if history else None
        if record is None:
            raise GenesisNotFound("no active alpha launch")
        member = next(
            (
                item
                for item in record["invitations"]
                if str(item.get("wallet_address") or "").lower() == wallet
                and item.get("consumed_at")
            ),
            None,
        )
        if member is None:
            raise GenesisNotFound("wallet is not enrolled for the active launch")
        nonce = "0x" + secrets.token_hex(32)
        expires_at = int(time.time()) + min(300, settings.challenge_ttl_seconds)
        store.create_auth_challenge(
            str(record["ceremony_id"]),
            slot=int(member["slot"]),
            wallet_address=wallet,
            nonce_hash=_token_hash(nonce),
            expires_at=expires_at,
        )
        return {
            "expiresAt": expires_at,
            "nonce": nonce,
            "typedData": _resume_typed_data(
                ceremony_id=str(record["ceremony_id"]),
                slot=int(member["slot"]),
                wallet=wallet,
                nonce=nonce,
                expires_at=expires_at,
            ),
        }
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=403, detail="Wallet is not enrolled for this launch.") from exc


@router.post("/auth/login")
async def resume_login(
    body: ResumeLoginRequest,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        wallet = normalize_evm_address(body.wallet, "wallet").lower()
        challenge = store.auth_challenge(_token_hash(body.nonce))
        if challenge["consumed_at"] is not None or int(challenge["expires_at"]) < int(
            time.time()
        ):
            raise GenesisExpired("administrator challenge expired or was already used")
        typed = _resume_typed_data(
            ceremony_id=str(challenge["ceremony_id"]),
            slot=int(challenge["slot"]),
            wallet=wallet,
            nonce=body.nonce,
            expires_at=int(challenge["expires_at"]),
        )
        recovered = recover_evm_signer(typed, body.signature)
        if recovered.address.lower() != wallet:
            raise GenesisConflict("signature wallet changed")
        store.consume_auth_challenge(
            nonce_hash=_token_hash(body.nonce), wallet_address=wallet
        )
        token, expires_at = _issue_session(
            settings,
            ceremony_id=str(challenge["ceremony_id"]),
            slot=int(challenge["slot"]),
            wallet=wallet,
            setup=False,
        )
        _set_session_cookie(response, settings, token, expires_at)
        return {
            "authenticated": True,
            "slot": int(challenge["slot"]),
            "role": "owner" if int(challenge["slot"]) == 1 else "coadmin",
            "expiresAt": expires_at,
        }
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/auth/logout")
async def launch_logout(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, bool]:
    response.delete_cookie(LAUNCH_COOKIE_NAME, path=settings.launch_cookie_path)
    return {"authenticated": False}


@router.get("/workspace")
async def launch_workspace(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    record = store.get(session.ceremony_id)
    readiness = await _readiness(request, settings, store, record)
    action_approvals: dict[str, Any] = {}
    funding = store.funding_receipt(session.ceremony_id)
    if funding:
        funding_action_id, _ = _funding_payload(store, session.ceremony_id)
        action_approvals["funding"] = store.action_approvals(
            session.ceremony_id, funding_action_id
        )
    for gate_name in store.gates(session.ceremony_id):
        gate_action_id, _ = _gate_payload(store, session.ceremony_id, gate_name)
        action_approvals[f"gate:{gate_name}"] = store.action_approvals(
            session.ceremony_id, gate_action_id
        )
    abandon_intent = store.latest_action_intent(session.ceremony_id, "abandon")
    if abandon_intent and abandon_intent["state"] == "prepared":
        action_approvals["abandon"] = store.action_approvals(
            session.ceremony_id, str(abandon_intent["actionId"])
        )
    return {
        "session": {
            "slot": session.slot,
            "role": "owner" if session.slot == 1 else "coadmin",
            "wallet": session.wallet,
            "setup": session.setup,
            "expiresAt": session.expires_at,
        },
        "launch": _public_ceremony(record, store),
        "readiness": readiness,
        "nextTask": _task_for(record, readiness),
        "gates": store.gates(session.ceremony_id),
        "actionApprovals": action_approvals,
        "notice": "TESTNET, NO REAL INVESTMENT OR LEGAL RIGHT.",
    }


@router.get("/audit")
async def launch_audit(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
    after: int = 0,
) -> dict[str, Any]:
    _require_wallet_session(session)
    return {
        "events": store.audit_events(session.ceremony_id, after_event_id=after)
    }


@router.put("/profile")
async def update_launch_profile(
    body: ProfileUpdateRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    return store.set_profile(
        session.ceremony_id,
        slot=session.slot,
        display_name=body.display_name,
        role_label="Owner" if session.slot == 1 else "Coadministrator",
        email=str(body.email) if body.email else None,
        timezone=body.timezone,
        reminders_enabled=body.reminders_enabled,
    )


@router.post("/invitations/{slot}")
async def issue_launch_invitation(
    slot: int,
    body: InviteProfileRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    if slot not in COADMIN_SLOTS:
        raise HTTPException(status_code=400, detail="Only Admin 2 or Admin 3 may be invited.")
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + settings.genesis_invitation_ttl_seconds
    try:
        store.issue_invitation(
            session.ceremony_id,
            slot=slot,
            token_hash=_token_hash(token),
            nonce="0x" + secrets.token_hex(32),
            expires_at=expires_at,
            replace_live=True,
        )
        profile = store.set_profile(
            session.ceremony_id,
            slot=slot,
            display_name=body.display_name,
            role_label="Coadministrator",
            email=str(body.email) if body.email else None,
            timezone=body.timezone,
            reminders_enabled=body.reminders_enabled,
        )
        return {
            "slot": slot,
            "profile": profile,
            "expiresAt": expires_at,
            "invitationFragment": "#launch-invite=" + token,
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/roster/freeze")
async def guided_freeze_roster(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    return await freeze_roster(session.ceremony_id, store)


@router.get("/rail-ownership")
def guided_rail_ownership(
    settings: Annotated[Settings, Depends(get_settings)],
    ownership_store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        status_value = _rail_phase_status(settings, ownership_store)
        return {
            "status": status_value,
            "decisionReceipt": _rail_decision_receipt(status_value),
        }
    except OwnershipActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/rail-ownership/sign")
def guided_sign_rail_ownership(
    body: RailSignatureSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    ownership_store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    try:
        current = _rail_phase_status(settings, ownership_store)
        if current["phase"] != body.phase:
            raise GenesisConflict("rail ownership phase changed before signing")
        _require_rail_session_signature(
            current, signature=body.signature, session=session
        )
        request = OwnershipSignatureRequest(signature=body.signature)
        status_value = (
            sign_ownership_activation(request, settings, ownership_store)
            if body.phase == "schedule"
            else sign_ownership_execution(request, settings, ownership_store)
        )
        return {
            "status": status_value,
            "decisionReceipt": _rail_decision_receipt(status_value),
        }
    except (GenesisStoreError, OwnershipActivationError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/rail-ownership/broadcast")
def guided_record_rail_broadcast(
    body: RailBroadcastSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    ownership_store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        current = _rail_phase_status(settings, ownership_store)
        if current["phase"] != body.phase:
            raise GenesisConflict("rail ownership phase changed before broadcast")
        request = OwnershipBroadcastRequest(transactionHash=body.transaction_hash)
        status_value = (
            record_ownership_activation_broadcast(request, settings, ownership_store)
            if body.phase == "schedule"
            else record_ownership_execution_broadcast(
                request, settings, ownership_store
            )
        )
        return {
            "status": status_value,
            "decisionReceipt": _rail_decision_receipt(status_value),
        }
    except (GenesisStoreError, OwnershipActivationError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/settlement-rehearsal")
async def guided_settlement_rehearsal_status(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    current = store.settlement_rehearsal(session.ceremony_id)
    if current is None:
        return _rehearsal_result(None)
    if current["state"] in {"SUCCEEDED", "FAILED"}:
        return _rehearsal_result(current)
    try:
        remote = await rehearsal_status(settings, job_id=str(current["jobId"]))
        return _rehearsal_result(
            _store_rehearsal_status(
                settings, store, session.ceremony_id, remote
            )
        )
    except (GenesisStoreError, LaunchRehearsalError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/settlement-rehearsal/start")
async def guided_start_settlement_rehearsal(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_coadmin(session)
    current = store.settlement_rehearsal(session.ceremony_id)
    if current and current["state"] != "FAILED":
        return _rehearsal_result(current)
    try:
        record = store.get(session.ceremony_id)
        release_hash = str(record["draft"].get("releaseEvidenceHash") or "")
        if not HEX32_RE.fullmatch(release_hash):
            raise GenesisConflict("the RC21 release evidence hash is unavailable")
        remote = await start_rehearsal(
            settings,
            ceremony_id=session.ceremony_id,
            release_evidence_hash=release_hash,
        )
        return _rehearsal_result(
            _store_rehearsal_status(
                settings, store, session.ceremony_id, remote
            )
        )
    except (GenesisStoreError, LaunchRehearsalError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/settlement-rehearsal/transaction")
async def guided_submit_settlement_rehearsal_transaction(
    body: RehearsalTransactionSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_coadmin(session)
    current = store.settlement_rehearsal(session.ceremony_id)
    if not current:
        raise HTTPException(status_code=409, detail="Start the settlement rehearsal first.")
    try:
        remote = await submit_rehearsal_transaction(
            settings,
            job_id=str(current["jobId"]),
            transaction_hash=body.transaction_hash,
        )
        return _rehearsal_result(
            _store_rehearsal_status(
                settings, store, session.ceremony_id, remote
            )
        )
    except (GenesisStoreError, LaunchRehearsalError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/funding/prepare")
async def prepare_fixed_funding(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        faucet = getattr(request.app.state, "faucet", None)
        provider = getattr(request.app.state, "coinset", None)
        if faucet is None or provider is None:
            raise GenesisConflict("ceremony faucet or Chia provider is unavailable")
        records = await provider.get_coin_records_by_puzzle_hash(
            "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
        )
        source = faucet.select_coin(
            records,
            min_amount=1_000_558,
            max_amount=settings.faucet_max_spend_mojos,
        )
        if source is None:
            raise GenesisConflict(
                "The configured faucet needs one confirmed coin of at least "
                "1,000,558 mojos for the fixed ceremony funding."
            )
        fanout = plan_genesis_funding_fanout(
            source_coin=source,
            faucet_puzzle_hash=faucet.address_puzzle_hash,
            network="testnet11",
            fee=0,
        )
        receipt = store.set_funding_receipt(
            session.ceremony_id, plan=fanout.plan, plan_hash=fanout.digest
        )
        return {
            "receipt": receipt,
            "summary": {
                "sourceBalanceMojos": int(source.amount),
                "totalMojos": sum(item["amount"] for item in fanout.plan["outputs"]),
                "feeMojos": 0,
                "outputs": [
                    {
                        "purpose": item["name"],
                        "amountMojos": item["amount"],
                    }
                    for item in fanout.plan["outputs"]
                ],
                "bridgeBatchMojos": GENESIS_BRIDGE_BATCH_FUNDING_AMOUNT,
                "customizationAllowed": False,
            },
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/gates/propose")
async def propose_gate(
    body: GateProposalRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    if body.duration_seconds > settings.launch_gate_max_seconds:
        raise HTTPException(status_code=400, detail="Requested window exceeds the release limit.")
    opens_at = int(time.time()) + body.starts_in_seconds
    closes_at = opens_at + body.duration_seconds
    payload = {
        "ceremonyId": session.ceremony_id,
        "gate": body.gate,
        "network": "testnet11",
        "opensAt": opens_at,
        "closesAt": closes_at,
    }
    payload_hash = _hash_json(payload)
    gate = store.upsert_gate(
        session.ceremony_id,
        gate_name=body.gate,
        opens_at=opens_at,
        closes_at=closes_at,
        payload_hash=payload_hash,
        state="pending",
    )
    return {"gate": gate, "decisionReceipt": _decision_receipt(f"gate:{body.gate}", payload_hash)}


@router.post("/actions/prepare")
async def prepare_launch_action(
    body: ActionPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        action_id, payload_hash = _action_payload(
            store, session.ceremony_id, body.action_type
        )
        expires_at = int(time.time()) + 600
        typed = _action_typed_data(
            ceremony_id=session.ceremony_id,
            action_type=body.action_type,
            action_id=action_id,
            payload_hash=payload_hash,
            expires_at=expires_at,
        )
        return {
            "actionId": action_id,
            "payloadHash": payload_hash,
            "expiresAt": expires_at,
            "typedData": typed,
            "typedDataHash": _typed_digest(typed),
            "decisionReceipt": _decision_receipt(body.action_type, payload_hash),
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/actions/approve")
async def approve_launch_action(
    body: ActionApproveRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        expected_id, expected_payload = _action_payload(
            store, session.ceremony_id, body.action_type
        )
        if body.action_id != expected_id or body.payload_hash.lower() != expected_payload:
            raise GenesisConflict("launch action changed after review")
        now = int(time.time())
        if body.expires_at < now or body.expires_at > now + 600:
            raise GenesisExpired("launch action signature expired")
        typed = _action_typed_data(
            ceremony_id=session.ceremony_id,
            action_type=body.action_type,
            action_id=body.action_id,
            payload_hash=body.payload_hash.lower(),
            expires_at=body.expires_at,
        )
        recovered = recover_evm_signer(typed, body.signature)
        if recovered.address.lower() != session.wallet:
            raise GenesisConflict("launch action signer changed")
        return store.add_action_approval(
            session.ceremony_id,
            action_id=body.action_id,
            action_type=body.action_type,
            payload_hash=body.payload_hash,
            slot=session.slot,
            signer_address=session.wallet or "",
            signature=body.signature,
        )
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/abandon/prepare")
async def prepare_launch_abandonment(
    body: AbandonPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    payload = {
        "ceremonyId": session.ceremony_id,
        "reason": body.reason.strip(),
        "network": "testnet11",
    }
    payload_hash = _hash_json(payload)
    action_id = "0x" + hashlib.sha256(
        f"{session.ceremony_id}:abandon:{payload_hash}".encode("ascii")
    ).hexdigest()
    try:
        store.set_action_intent(
            session.ceremony_id,
            action_id=action_id,
            action_type="abandon",
            payload_hash=payload_hash,
            payload=payload,
        )
        expires_at = int(time.time()) + 600
        typed = _action_typed_data(
            ceremony_id=session.ceremony_id,
            action_type="abandon",
            action_id=action_id,
            payload_hash=payload_hash,
            expires_at=expires_at,
        )
        return {
            "actionId": action_id,
            "payloadHash": payload_hash,
            "expiresAt": expires_at,
            "typedData": typed,
            "typedDataHash": _typed_digest(typed),
            "decisionReceipt": _decision_receipt("abandon", payload_hash),
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/abandon/execute")
async def execute_launch_abandonment(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    try:
        intent = store.latest_action_intent(session.ceremony_id, "abandon")
        if not intent or intent["state"] != "prepared":
            raise GenesisConflict("approved abandonment is unavailable")
        approval = store.action_approvals(
            session.ceremony_id, str(intent["actionId"])
        )
        if not approval["approved"]:
            raise GenesisConflict("owner-plus-one abandonment approval is required")
        record = store.abandon(
            session.ceremony_id, str(intent["payload"]["reason"])
        )
        store.set_action_intent(
            session.ceremony_id,
            action_id=str(intent["actionId"]),
            action_type="abandon",
            payload_hash=str(intent["payloadHash"]),
            payload=dict(intent["payload"]),
            state="executed",
        )
        return {"launch": _public_ceremony(record, store), "abandoned": True}
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/gates/{gate_name}/activate")
async def activate_gate(
    gate_name: str,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    if gate_name not in GATE_NAMES:
        raise HTTPException(status_code=404, detail="Unknown launch gate.")
    action_id, _ = _gate_payload(store, session.ceremony_id, gate_name)
    approval = store.action_approvals(session.ceremony_id, action_id)
    if not approval["approved"]:
        raise HTTPException(status_code=409, detail="Owner-plus-one approval is required.")
    gate = store.gates(session.ceremony_id).get(gate_name)
    if not gate:
        raise HTTPException(status_code=409, detail="Gate proposal is missing.")
    return store.upsert_gate(
        session.ceremony_id,
        gate_name=gate_name,
        opens_at=gate["opensAt"],
        closes_at=gate["closesAt"],
        payload_hash=gate["payloadHash"],
        state="open" if gate["opensAt"] <= int(time.time()) else "pending",
    )


@router.post("/funding/execute")
async def execute_fixed_funding(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    try:
        _funding_ceiling_open(settings)
        action_id, _ = _funding_payload(store, session.ceremony_id)
        if not store.action_approvals(session.ceremony_id, action_id)["approved"]:
            raise GenesisConflict("owner-plus-one funding approval is required")
        receipt = store.funding_receipt(session.ceremony_id)
        assert receipt is not None
        from chia.types.blockchain_format.coin import Coin
        from chia_rs.sized_bytes import bytes32
        from chia_rs.sized_ints import uint64

        faucet = getattr(request.app.state, "faucet", None)
        provider = getattr(request.app.state, "coinset", None)
        if faucet is None or provider is None:
            raise GenesisConflict("ceremony faucet or Chia provider is unavailable")
        source_record = await provider.get_coin_record_by_name(
            str(receipt["plan"]["sourceCoinId"])
        )
        if not source_record:
            raise GenesisConflict("the approved funding source coin is missing")
        payload = source_record.get("coin") or source_record
        source = Coin(
            bytes32.fromhex(str(payload["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(payload["puzzle_hash"]).removeprefix("0x")),
            uint64(int(payload["amount"])),
        )
        reproduced = plan_genesis_funding_fanout(
            source_coin=source,
            faucet_puzzle_hash=faucet.address_puzzle_hash,
            network="testnet11",
            fee=0,
        )
        if (
            reproduced.digest != receipt["planHash"]
            or reproduced.plan != receipt["plan"]
            or source_record.get("spent") is True
            or int(source_record.get("spent_block_index") or 0)
        ):
            raise GenesisConflict("the approved funding source changed or was spent")
        conditions = [
            Program.to([CREATE_COIN, faucet.address_puzzle_hash, int(item["amount"])])
            for item in receipt["plan"]["outputs"]
        ]
        if int(receipt["plan"]["changeAmount"]):
            conditions.append(
                Program.to(
                    [
                        CREATE_COIN,
                        faucet.address_puzzle_hash,
                        int(receipt["plan"]["changeAmount"]),
                    ]
                )
            )
        conditions_program = Program.to(conditions)
        delegated = Program.to((1, conditions_program))
        coin_spend = make_spend(
            source,
            faucet.key.puzzle,
            Program.to([0, delegated, Program.to(0)]),
        )
        signature = G2Element.from_bytes(
            faucet.sign_delegated_spend(source, conditions_program)
        )
        bundle = SpendBundle([coin_spend], signature)
        bundle_id = "0x" + bytes(bundle.name()).hex()
        try:
            response = await provider.push_tx(bundle.to_json_dict())
        except Exception as exc:  # noqa: BLE001
            store.set_funding_receipt(
                session.ceremony_id,
                plan=receipt["plan"],
                plan_hash=receipt["planHash"],
                state="ambiguous",
                spend_bundle_id=bundle_id,
                response={"error": "provider response was ambiguous"},
            )
            raise GenesisConflict(
                "Funding submission is ambiguous. It is locked for reconciliation."
            ) from exc
        accepted = response.get("success") is True or str(
            response.get("status", "")
        ).upper() in {"SUCCESS", "PENDING"}
        if not accepted:
            raise GenesisConflict("Testnet11 rejected the fixed funding transaction")
        return store.set_funding_receipt(
            session.ceremony_id,
            plan=receipt["plan"],
            plan_hash=receipt["planHash"],
            state="broadcast",
            spend_bundle_id=bundle_id,
            response=response,
        )
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/funding/confirm")
async def confirm_fixed_funding(
    request: Request,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        provider = getattr(request.app.state, "coinset", None)
        receipt = store.funding_receipt(session.ceremony_id)
        if provider is None or receipt is None:
            raise GenesisConflict("funding transaction is not available")
        for item in receipt["plan"]["outputs"]:
            record = await provider.get_coin_record_by_name(str(item["coinId"]))
            if (
                record is None
                or int(record.get("confirmed_block_index") or 0) <= 0
                or record.get("spent") is True
                or int(record.get("spent_block_index") or 0)
            ):
                raise GenesisConflict(
                    f"{item['name']} funding coin is not confirmed and unspent"
                )
        return store.set_funding_receipt(
            session.ceremony_id,
            plan=receipt["plan"],
            plan_hash=receipt["planHash"],
            state="confirmed",
            spend_bundle_id=receipt["spendBundleId"],
            response=receipt["response"],
        )
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/plan/build")
async def build_guided_plan(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        record = store.get(session.ceremony_id)
        if record["state"] != "roster_frozen":
            raise GenesisConflict("confirm the three-administrator roster first")
        funding = store.funding_receipt(session.ceremony_id)
        if not funding or funding["state"] != "confirmed":
            raise GenesisConflict("confirm the fixed ceremony funding first")
        template, _ = _read_json_file(
            settings.launch_plan_template_path, "RC21 launch plan template"
        )
        template["fundingCoinIds"] = dict(funding["plan"]["fundingCoinIds"])
        body = PlanRequest.model_validate(template)
        return await create_plan(session.ceremony_id, body, settings, store)
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/plan/signature/prepare")
async def guided_prepare_plan_signature(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    prepared = await prepare_plan_signature(
        session.ceremony_id, SignaturePrepareRequest(slot=session.slot), store
    )
    record = store.get(session.ceremony_id)
    prepared["decisionReceipt"] = {
        "title": "Approve the fixed Testnet11 launch plan",
        "network": "Testnet11",
        "financialEffect": "No payment is made by this signature.",
        "customerImpact": "Approves the exact protocol coordinates and administrator roster.",
        "reversibility": "Expires with the plan and cannot authorize another plan.",
        "expiresAt": record["plan_expires_at"],
        "requiredApprovers": "Owner plus either coadministrator",
        "expectedResult": "Only the owner may broadcast after final readiness passes.",
    }
    return prepared


@router.post("/plan/signature")
async def guided_sign_plan(
    body: SignatureSubmission,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    return await sign_plan(
        session.ceremony_id,
        SignatureRequest(slot=session.slot, signature=body.signature),
        store,
    )


@router.post("/preflight")
async def guided_preflight(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    record = store.get(session.ceremony_id)
    readiness = await _readiness(request, settings, store, record)
    failures = [item for item in readiness if item["status"] != "Healthy"]
    if failures:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Final launch check has unfinished items.",
                "findings": failures,
            },
        )
    try:
        plan, bundle, approval, validator_health = await _prepare_bundle(
            settings, record
        )
        return {
            "ready": True,
            "planHash": plan["planHash"],
            "spendBundleId": bundle["spendBundleId"],
            "reviewApproval": approval,
            "validatorHealth": [
                item.model_dump(mode="json") for item in validator_health
            ],
            "decisionReceipt": {
                "title": "Launch the Solslot Testnet Alpha",
                "network": "Testnet11",
                "financialEffect": "Consumes only the nine fixed testnet funding coins.",
                "customerImpact": "Creates the testnet protocol used by alpha vaults and SmartDeeds.",
                "reversibility": "The chain transaction cannot be reversed. Unknown submission results abandon the launch.",
                "requiredApprovers": "Already approved by the owner and one coadministrator",
                "expectedResult": "The protocol confirms, creates a signed archive, and locks bootstrap.",
            },
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/broadcast")
async def guided_broadcast(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    try:
        _gate_open(settings, store, session.ceremony_id, "ceremonyBroadcast")
        return await broadcast(session.ceremony_id, settings, store)
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/progress")
async def progress_after_broadcast(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    record = store.get(session.ceremony_id)
    if record["state"] == "broadcast":
        return await confirm(session.ceremony_id, settings, store)
    if record["state"] == "confirmed":
        return await create_artifact(session.ceremony_id, store)
    if record["state"] == "artifact_signed":
        _require_owner(session)
        return await finalize(session.ceremony_id, settings, store)
    return {"ceremony": _public_ceremony(record, store), "waiting": True}


@router.post("/artifact/signature/prepare")
async def guided_prepare_artifact_signature(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    prepared = await prepare_artifact_signature(
        session.ceremony_id, SignaturePrepareRequest(slot=session.slot), store
    )
    prepared["decisionReceipt"] = {
        "title": "Sign the permanent launch archive",
        "network": "Testnet11",
        "financialEffect": "No payment is made.",
        "customerImpact": "Confirms the public protocol record matches the transaction.",
        "reversibility": "The signature is bound to this artifact hash only.",
        "requiredApprovers": "Owner plus either coadministrator",
    }
    return prepared


@router.post("/artifact/signature")
async def guided_sign_artifact(
    body: SignatureSubmission,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    return await sign_artifact(
        session.ceremony_id,
        SignatureRequest(slot=session.slot, signature=body.signature),
        store,
    )


@router.get("/archive")
async def launch_archive(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    ceremonies = [
        _public_ceremony(record, store)
        for record in store.list_ceremonies()
        if record["state"] in {"locked", "abandoned"}
    ]
    return {"launches": ceremonies}


__all__ = ["LAUNCH_COOKIE_NAME", "LaunchSession", "require_launch_session", "router"]
