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
    result: dict[str, Any] = {
        "jobId": job_id,
        "state": state,
        "configHash": config_hash,
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
) -> dict[str, Any]:
    _, _, config_hash, _ = _configuration(settings)
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


__all__ = [
    "LaunchRehearsalError",
    "persist_evidence",
    "rehearsal_status",
    "start_rehearsal",
    "submit_rehearsal_transaction",
    "validate_status",
]
