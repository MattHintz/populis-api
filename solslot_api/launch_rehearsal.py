"""Fail-closed client for the fixed RC22 settlement rehearsal coordinator."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

import httpx

from .config import Settings
from .genesis_store import GenesisConflict, GenesisStore


MAX_RESPONSE_BYTES = 256 * 1024
HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
STATES = {
    "PREPARED",
    "AWAITING_WALLET",
    "PAYMENT_SUBMITTED",
    "VALIDATING",
    "SUCCEEDED",
    "FAILED",
}
PHASES = {
    "PREPARE",
    "APPROVE_DELIVERY",
    "PAY_DELIVERY",
    "VERIFY_DELIVERY",
    "APPROVE_REFUND",
    "PAY_REFUND",
    "VERIFY_REFUND",
    "COMPLETE",
}


class LaunchRehearsalError(RuntimeError):
    """The reviewed rehearsal coordinator or its evidence failed validation."""


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _configuration(settings: Settings) -> tuple[str, str, str, str]:
    url = str(settings.launch_rehearsal_service_url or "").rstrip("/")
    token = str(settings.launch_rehearsal_service_token or "")
    config_hash = str(settings.launch_rehearsal_config_hash or "").lower()
    evidence_secret = str(settings.launch_rehearsal_evidence_hmac_secret or "")
    if (
        not url.startswith("https://")
        or len(token) < 32
        or not HEX32_RE.fullmatch(config_hash)
        or len(evidence_secret) < 32
    ):
        raise LaunchRehearsalError(
            "The fixed settlement rehearsal service is not fully configured."
        )
    return url, token, config_hash, evidence_secret


async def _request(
    settings: Settings,
    method: str,
    path: str,
    *,
    payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    url, token, _, _ = _configuration(settings)
    try:
        async with httpx.AsyncClient(
            timeout=float(settings.launch_rehearsal_timeout_seconds),
            follow_redirects=False,
        ) as client:
            response = await client.request(
                method,
                f"{url}{path}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json=dict(payload) if payload is not None else None,
            )
    except httpx.HTTPError as exc:
        raise LaunchRehearsalError(
            "The settlement rehearsal coordinator is unavailable."
        ) from exc
    if response.is_redirect:
        raise LaunchRehearsalError("The settlement rehearsal service redirected unexpectedly.")
    if response.status_code != 200 or len(response.content) > MAX_RESPONSE_BYTES:
        raise LaunchRehearsalError(
            "The settlement rehearsal coordinator rejected the fixed job."
        )
    try:
        value = response.json()
    except ValueError as exc:
        raise LaunchRehearsalError(
            "The settlement rehearsal coordinator returned invalid JSON."
        ) from exc
    if not isinstance(value, dict):
        raise LaunchRehearsalError("The settlement rehearsal response must be an object.")
    return value


def _validate_transaction(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "chainId",
        "to",
        "value",
        "data",
    }:
        raise LaunchRehearsalError("The rehearsal wallet transaction shape changed.")
    if (
        int(value["chainId"]) != 84532
        or not ADDRESS_RE.fullmatch(str(value["to"]))
        or str(value["value"]).lower() != "0x0"
        or not re.fullmatch(r"^0x(?:[0-9a-fA-F]{2})+$", str(value["data"]))
    ):
        raise LaunchRehearsalError("The rehearsal wallet transaction is not Base Sepolia safe.")
    return {
        "chainId": 84532,
        "to": str(value["to"]),
        "value": "0x0",
        "data": str(value["data"]).lower(),
    }


def _validate_evidence(
    evidence: object,
    signature: object,
    *,
    settings: Settings,
) -> dict[str, Any]:
    _, _, config_hash, secret = _configuration(settings)
    if not isinstance(evidence, dict) or not isinstance(signature, str):
        raise LaunchRehearsalError("Completed rehearsal evidence is missing.")
    expected_hmac = hmac.new(
        secret.encode("utf-8"),
        canonical_json(evidence).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature.removeprefix("0x").lower(), expected_hmac):
        raise LaunchRehearsalError("Settlement rehearsal evidence signature is invalid.")
    validators = evidence.get("validators")
    lanes = evidence.get("lanes")
    if (
        evidence.get("schemaVersion") != 2
        or evidence.get("kind") != "solslot-rc22-settlement-rehearsal"
        or evidence.get("releaseTag") != settings.launch_release_tag
        or str(evidence.get("configHash", "")).lower() != config_hash
        or evidence.get("network") != "testnet11-base-sepolia"
        or evidence.get("success") is not True
        or evidence.get("validatorThreshold") != 2
        or not isinstance(validators, list)
        or len(validators) != 3
        or len({canonical_json(item) for item in validators}) != 3
        or not isinstance(lanes, Mapping)
        or set(lanes) != {"delivery", "refund"}
        or not isinstance(lanes["delivery"], Mapping)
        or lanes["delivery"].get("success") is not True
        or not isinstance(lanes["refund"], Mapping)
        or lanes["refund"].get("success") is not True
        or lanes["refund"].get("exactRefund") is not True
    ):
        raise LaunchRehearsalError(
            "Settlement rehearsal did not prove delivery and exact refund lanes."
        )
    return evidence


def validate_status(
    value: Mapping[str, Any],
    *,
    settings: Settings,
    expected_job_id: str | None = None,
) -> dict[str, Any]:
    job_id = str(value.get("jobId") or "")
    state = str(value.get("state") or "")
    _, _, config_hash, _ = _configuration(settings)
    if (
        not JOB_ID_RE.fullmatch(job_id)
        or (expected_job_id is not None and job_id != expected_job_id)
        or state not in STATES
        or str(value.get("configHash") or "").lower() != config_hash
    ):
        raise LaunchRehearsalError("Settlement rehearsal status changed unexpectedly.")
    phase = str(value.get("phase") or ("COMPLETE" if state == "SUCCEEDED" else "PREPARE"))
    completed_steps = value.get("completedSteps", 4 if state == "SUCCEEDED" else 0)
    if (
        phase not in PHASES
        or isinstance(completed_steps, bool)
        or not isinstance(completed_steps, int)
        or completed_steps < 0
        or completed_steps > 4
        or (state == "SUCCEEDED" and (phase != "COMPLETE" or completed_steps != 4))
    ):
        raise LaunchRehearsalError("Settlement rehearsal progress changed unexpectedly.")
    result: dict[str, Any] = {
        "jobId": job_id,
        "state": state,
        "configHash": config_hash,
        "phase": phase,
        "completedSteps": completed_steps,
        "step": str(value.get("step") or ""),
        "message": str(value.get("message") or ""),
        "walletTransaction": _validate_transaction(value.get("walletTransaction")),
    }
    if state == "SUCCEEDED":
        result["evidence"] = _validate_evidence(
            value.get("evidence"),
            value.get("evidenceHmac"),
            settings=settings,
        )
    elif value.get("evidence") is not None or value.get("evidenceHmac") is not None:
        raise LaunchRehearsalError("Incomplete rehearsal returned terminal evidence.")
    return result


async def start_rehearsal(
    settings: Settings,
    *,
    ceremony_id: str,
    release_evidence_hash: str,
    wallet_address: str,
) -> dict[str, Any]:
    _, _, config_hash, _ = _configuration(settings)
    if not ADDRESS_RE.fullmatch(wallet_address):
        raise LaunchRehearsalError(
            "The settlement rehearsal wallet address is invalid."
        )
    value = await _request(
        settings,
        "POST",
        "/v1/rehearsals",
        payload={
            "ceremonyId": ceremony_id,
            "releaseTag": settings.launch_release_tag,
            "releaseEvidenceHash": release_evidence_hash,
            "configHash": config_hash,
            "network": "testnet11-base-sepolia",
            "requiredLanes": ["delivery", "refund"],
            "walletAddress": wallet_address,
        },
    )
    return validate_status(value, settings=settings)


async def rehearsal_status(
    settings: Settings, *, job_id: str
) -> dict[str, Any]:
    if not JOB_ID_RE.fullmatch(job_id):
        raise LaunchRehearsalError("Settlement rehearsal job id is invalid.")
    value = await _request(settings, "GET", f"/v1/rehearsals/{job_id}")
    return validate_status(value, settings=settings, expected_job_id=job_id)


async def submit_rehearsal_transaction(
    settings: Settings, *, job_id: str, transaction_hash: str
) -> dict[str, Any]:
    if not JOB_ID_RE.fullmatch(job_id) or not HEX32_RE.fullmatch(transaction_hash):
        raise LaunchRehearsalError("Settlement rehearsal transaction evidence is invalid.")
    value = await _request(
        settings,
        "POST",
        f"/v1/rehearsals/{job_id}/transactions",
        payload={"transactionHash": transaction_hash.lower()},
    )
    return validate_status(value, settings=settings, expected_job_id=job_id)


def persist_evidence(settings: Settings, evidence: Mapping[str, Any]) -> str:
    path_value = settings.launch_settlement_rehearsal_path
    if not path_value:
        raise LaunchRehearsalError("Settlement rehearsal evidence path is unavailable.")
    path = Path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (canonical_json(dict(evidence)) + "\n").encode("ascii")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != encoded:
            raise LaunchRehearsalError(
                "Settlement rehearsal evidence already exists with different bytes."
            )
        return "0x" + hashlib.sha256(encoded).hexdigest()
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return "0x" + hashlib.sha256(encoded).hexdigest()


def require_completed_rehearsal(
    settings: Settings,
    store: GenesisStore,
    ceremony_id: str,
) -> tuple[dict[str, Any], str]:
    """Load the write-once rehearsal proof bound to one completed launch.

    This is the shared activation boundary for presales and purchases. Genesis
    itself does not depend on inventory that can only exist after genesis.
    """

    job = store.settlement_rehearsal(ceremony_id)
    if not job or job["state"] != "SUCCEEDED":
        state = str(job["state"]).lower() if job else "not started"
        raise GenesisConflict(f"settlement rehearsal is {state}")
    config_hash = str(settings.launch_rehearsal_config_hash or "").lower()
    if (
        not HEX32_RE.fullmatch(config_hash)
        or not hmac.compare_digest(
            str(job.get("configHash") or "").lower(),
            config_hash,
        )
    ):
        raise GenesisConflict("settlement rehearsal configuration changed")
    path_value = settings.launch_settlement_rehearsal_path
    if not path_value:
        raise GenesisConflict("settlement rehearsal evidence path is unavailable")
    path = Path(path_value)
    try:
        stat = path.lstat()
        encoded = path.read_bytes()
    except OSError as exc:
        raise GenesisConflict("settlement rehearsal evidence is unavailable") from exc
    if (
        path.is_symlink()
        or not path.is_file()
        or stat.st_size <= 0
        or stat.st_size > MAX_RESPONSE_BYTES
    ):
        raise GenesisConflict("settlement rehearsal evidence path is invalid")
    try:
        evidence = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GenesisConflict("settlement rehearsal evidence is invalid JSON") from exc
    if not isinstance(evidence, dict):
        raise GenesisConflict("settlement rehearsal evidence must be an object")
    canonical = (canonical_json(evidence) + "\n").encode("ascii")
    if not hmac.compare_digest(encoded, canonical):
        raise GenesisConflict("settlement rehearsal evidence is not canonical")
    digest = "0x" + hashlib.sha256(encoded).hexdigest()
    payload = job.get("payload")
    if (
        not isinstance(payload, Mapping)
        or not hmac.compare_digest(
            str(payload.get("evidenceDigest") or "").lower(),
            digest,
        )
    ):
        raise GenesisConflict("settlement rehearsal evidence digest changed")
    validators = evidence.get("validators")
    lanes = evidence.get("lanes")
    validator_ids = (
        [str(item.get("id") or "") for item in validators]
        if isinstance(validators, list)
        and all(isinstance(item, Mapping) for item in validators)
        else []
    )
    healthy = (
        evidence.get("schemaVersion") == 2
        and evidence.get("kind") == "solslot-rc22-settlement-rehearsal"
        and evidence.get("releaseTag") == settings.launch_release_tag
        and hmac.compare_digest(
            str(evidence.get("configHash") or "").lower(),
            config_hash,
        )
        and evidence.get("network") == "testnet11-base-sepolia"
        and evidence.get("success") is True
        and evidence.get("validatorThreshold") == 2
        and isinstance(validators, list)
        and len(validators) == 3
        and all(validator_ids)
        and len(set(validator_ids)) == 3
        and len({canonical_json(item) for item in validators}) == 3
        and isinstance(lanes, Mapping)
        and set(lanes) == {"delivery", "refund"}
        and isinstance(lanes.get("delivery"), Mapping)
        and lanes["delivery"].get("success") is True
        and isinstance(lanes.get("refund"), Mapping)
        and lanes["refund"].get("success") is True
        and lanes["refund"].get("exactRefund") is True
    )
    if not healthy:
        raise GenesisConflict(
            "settlement rehearsal does not prove delivery and exact refund"
        )
    return evidence, digest


__all__ = [
    "LaunchRehearsalError",
    "PHASES",
    "persist_evidence",
    "require_completed_rehearsal",
    "rehearsal_status",
    "start_rehearsal",
    "submit_rehearsal_transaction",
    "validate_status",
]
