"""Fail-closed client for the fixed RC27 Stripe voucher rehearsal."""

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
from .service_urls import valid_launch_rehearsal_service_url


MAX_RESPONSE_BYTES = 256 * 1024
SETTLEMENT_REHEARSAL_KIND = "solslot-rc27-stripe-voucher-rehearsal"
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
    "WAITING_DELIVERY_PURCHASE",
    "VERIFY_DELIVERY",
    "WAITING_REFUND_PURCHASE",
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
        not valid_launch_rehearsal_service_url(url)
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


def _validate_transaction(value: object) -> None:
    if value is None:
        return None
    raise LaunchRehearsalError(
        "The Stripe voucher rehearsal must not return a wallet transaction."
    )


def _validate_review(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    expected = {
        "action",
        "lane",
        "asset",
        "amountMinor",
        "amountLabel",
        "paymentIntentId",
        "approvedVault",
        "deedLauncherId",
        "expectedOutcome",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise LaunchRehearsalError("The rehearsal review summary shape changed.")
    amount_minor = str(value["amountMinor"])
    if (
        str(value["action"]) not in {"purchase", "refund", "verify"}
        or str(value["lane"]) not in {"delivery", "refund"}
        or str(value["asset"]) != "USD"
        or not re.fullmatch(r"^[1-9][0-9]{0,15}$", amount_minor)
        or not re.fullmatch(r"^pi_[A-Za-z0-9_]{8,120}$", str(value["paymentIntentId"]))
        or not HEX32_RE.fullmatch(str(value["approvedVault"]))
        or not HEX32_RE.fullmatch(str(value["deedLauncherId"]))
        or str(value["expectedOutcome"]) not in {"DELIVERED", "REFUND"}
        or len(str(value["amountLabel"])) > 64
    ):
        raise LaunchRehearsalError("The rehearsal review summary is invalid.")
    return {
        "action": str(value["action"]),
        "lane": str(value["lane"]),
        "asset": "USD",
        "amountMinor": amount_minor,
        "amountLabel": str(value["amountLabel"]),
        "paymentIntentId": str(value["paymentIntentId"]),
        "approvedVault": str(value["approvedVault"]).lower(),
        "deedLauncherId": str(value["deedLauncherId"]).lower(),
        "expectedOutcome": str(value["expectedOutcome"]),
    }


def _required_hex32(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if not HEX32_RE.fullmatch(normalized) or normalized == "0x" + "00" * 32:
        raise LaunchRehearsalError(f"{label} is invalid.")
    return normalized


def _required_decimal(value: object, label: str, *, allow_zero: bool = True) -> int:
    text = str(value)
    pattern = (
        r"^(?:0|[1-9][0-9]{0,15})$"
        if allow_zero
        else r"^[1-9][0-9]{0,15}$"
    )
    if not re.fullmatch(pattern, text):
        raise LaunchRehearsalError(f"{label} is invalid.")
    return int(text)


def _validate_signers(value: object) -> list[int]:
    if (
        not isinstance(value, list)
        or len(value) < 2
        or len(value) > 3
        or any(isinstance(item, bool) or not isinstance(item, int) for item in value)
        or value != sorted(value)
        or len(set(value)) != len(value)
        or any(item < 0 or item > 2 for item in value)
    ):
        raise LaunchRehearsalError("Stripe validator quorum evidence is invalid.")
    return value


def _validate_voucher(value: object) -> None:
    expected = {
        "serial",
        "signerIndices",
        "issuanceBundleId",
        "voucherCoinId",
        "paymentCommitmentCoinId",
        "issuanceConfirmedHeight",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise LaunchRehearsalError("Voucher issuance evidence is incomplete.")
    if (
        isinstance(value["serial"], bool)
        or not isinstance(value["serial"], int)
        or value["serial"] < 0
        or isinstance(value["issuanceConfirmedHeight"], bool)
        or not isinstance(value["issuanceConfirmedHeight"], int)
        or value["issuanceConfirmedHeight"] < 1
    ):
        raise LaunchRehearsalError("Voucher issuance height or serial is invalid.")
    for field in ("issuanceBundleId", "voucherCoinId", "paymentCommitmentCoinId"):
        _required_hex32(value[field], f"Voucher {field}")
    _validate_signers(value["signerIndices"])


def _validate_execution(value: object, *, lane: str) -> Mapping[str, Any]:
    expected = {
        "schema",
        "mode",
        "action",
        "spendBundleId",
        "feeCoinId",
        "feeMojos",
        "mempoolObservedAt",
        "outputRoles",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise LaunchRehearsalError("KoS terminal execution evidence is incomplete.")
    expected_mode = "REDEEM" if lane == "delivery" else "REFUND_OWNER"
    if (
        value["schema"] != "solslot.stripe-voucher-terminal-execution.v1"
        or value["mode"] != expected_mode
        or value["action"] != 7
        or isinstance(value["mempoolObservedAt"], bool)
        or not isinstance(value["mempoolObservedAt"], int)
        or value["mempoolObservedAt"] < 1
    ):
        raise LaunchRehearsalError(
            "KoS terminal execution mode or mempool proof is invalid."
        )
    _required_hex32(value["spendBundleId"], "Terminal spend bundle ID")
    _required_hex32(value["feeCoinId"], "Terminal fee coin ID")
    _required_decimal(
        value["feeMojos"], "Terminal medium-speed fee", allow_zero=False
    )
    role_names = (
        {"coordination", "deed", "series", "terminalVoucher"}
        if lane == "delivery"
        else {"series", "terminalVoucher", "vault"}
    )
    roles = value["outputRoles"]
    if not isinstance(roles, Mapping) or set(roles) != role_names:
        raise LaunchRehearsalError("KoS terminal output roles are incomplete.")
    role_ids = [
        _required_hex32(roles[name], f"Terminal {name} output")
        for name in sorted(roles)
    ]
    if len(set(role_ids)) != len(role_ids):
        raise LaunchRehearsalError("KoS terminal outputs are not unique.")
    return roles


def _validate_chain(value: object, *, lane: str, roles: Mapping[str, Any]) -> None:
    expected = (
        {
            "confirmationHeight",
            "deedOutputCoinId",
            "seriesOutputCoinId",
            "terminalVoucherCoinId",
            "coordinationCoinId",
        }
        if lane == "delivery"
        else {
            "confirmationHeight",
            "seriesOutputCoinId",
            "terminalVoucherCoinId",
            "vaultOutputCoinId",
        }
    )
    if not isinstance(value, Mapping) or set(value) != expected:
        raise LaunchRehearsalError("Confirmed Chia output evidence is incomplete.")
    if (
        isinstance(value["confirmationHeight"], bool)
        or not isinstance(value["confirmationHeight"], int)
        or value["confirmationHeight"] < 1
    ):
        raise LaunchRehearsalError("Confirmed Chia height is invalid.")
    role_fields = (
        {
            "deedOutputCoinId": "deed",
            "seriesOutputCoinId": "series",
            "terminalVoucherCoinId": "terminalVoucher",
            "coordinationCoinId": "coordination",
        }
        if lane == "delivery"
        else {
            "seriesOutputCoinId": "series",
            "terminalVoucherCoinId": "terminalVoucher",
            "vaultOutputCoinId": "vault",
        }
    )
    for field, role in role_fields.items():
        coin_id = _required_hex32(value[field], f"Confirmed {field}")
        if not hmac.compare_digest(coin_id, str(roles[role]).lower()):
            raise LaunchRehearsalError(
                "Confirmed Chia outputs differ from the KoS execution."
            )


def _validate_refund(value: object, *, amount_minor: int) -> None:
    expected = {"refundId", "refundedMinor", "currency", "livemode", "observedAt"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise LaunchRehearsalError("Stripe exact-refund evidence is incomplete.")
    if (
        not re.fullmatch(r"^re_[A-Za-z0-9_]{8,120}$", str(value["refundId"]))
        or _required_decimal(value["refundedMinor"], "Stripe refunded amount")
        != amount_minor
        or value["currency"] != "usd"
        or value["livemode"] is not False
        or isinstance(value["observedAt"], bool)
        or not isinstance(value["observedAt"], int)
        or value["observedAt"] < 1
    ):
        raise LaunchRehearsalError("Stripe refund is not an exact test-mode refund.")


def _validate_lane(value: object, *, lane: str) -> Mapping[str, Any]:
    expected = {
        "success",
        "purchaseId",
        "artifactHash",
        "paymentIntentId",
        "eventId",
        "baseAmountMinor",
        "technologyFeeMinor",
        "processingChargeMinor",
        "amountMinor",
        "approvedVaultLauncherId",
        "deedLauncherId",
        "zkPassportRoot",
        "settlementReceiptHash",
        "signerIndices",
        "voucher",
        "execution",
        "chain",
    }
    if lane == "refund":
        expected |= {"exactRefund", "stripeRefund"}
    if (
        not isinstance(value, Mapping)
        or set(value) != expected
        or value["success"] is not True
    ):
        raise LaunchRehearsalError(
            f"Stripe {lane} rehearsal evidence is incomplete."
        )
    for field in (
        "purchaseId",
        "artifactHash",
        "approvedVaultLauncherId",
        "deedLauncherId",
        "zkPassportRoot",
        "settlementReceiptHash",
    ):
        _required_hex32(value[field], f"Stripe {lane} {field}")
    if (
        not re.fullmatch(
            r"^pi_[A-Za-z0-9_]{8,120}$", str(value["paymentIntentId"])
        )
        or not re.fullmatch(r"^evt_[A-Za-z0-9_]{8,120}$", str(value["eventId"]))
    ):
        raise LaunchRehearsalError(f"Stripe {lane} provider IDs are invalid.")
    base = _required_decimal(
        value["baseAmountMinor"], "Base amount", allow_zero=False
    )
    technology_fee = _required_decimal(
        value["technologyFeeMinor"], "Technology fee"
    )
    processing = _required_decimal(
        value["processingChargeMinor"], "Processing charge"
    )
    amount = _required_decimal(
        value["amountMinor"], "Stripe payment amount", allow_zero=False
    )
    if amount != base + technology_fee + processing:
        raise LaunchRehearsalError("Stripe payment arithmetic is inconsistent.")
    _validate_signers(value["signerIndices"])
    _validate_voucher(value["voucher"])
    roles = _validate_execution(value["execution"], lane=lane)
    _validate_chain(value["chain"], lane=lane, roles=roles)
    if lane == "refund":
        if value["exactRefund"] is not True:
            raise LaunchRehearsalError("Stripe refund lane is not exact.")
        _validate_refund(value["stripeRefund"], amount_minor=amount)
    return value


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
    if set(evidence) != {
        "schemaVersion",
        "kind",
        "releaseTag",
        "configHash",
        "network",
        "stripe",
        "success",
        "validatorThreshold",
        "validators",
        "lanes",
    }:
        raise LaunchRehearsalError("Settlement rehearsal evidence shape changed.")
    validators = evidence.get("validators")
    lanes = evidence.get("lanes")
    stripe = evidence.get("stripe")
    if (
        evidence.get("schemaVersion") != 3
        or evidence.get("kind") != SETTLEMENT_REHEARSAL_KIND
        or evidence.get("releaseTag") != settings.launch_release_tag
        or str(evidence.get("configHash", "")).lower() != config_hash
        or evidence.get("network") != "testnet11"
        or evidence.get("success") is not True
        or evidence.get("validatorThreshold") != 2
        or not isinstance(stripe, Mapping)
        or set(stripe) != {"accountId", "mode", "livemode", "apiVersion"}
        or not re.fullmatch(
            r"^acct_[A-Za-z0-9_]{6,120}$", str(stripe.get("accountId"))
        )
        or stripe.get("mode") != "test"
        or stripe.get("livemode") is not False
        or not re.fullmatch(
            r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}(?:\.[a-z]+)?$",
            str(stripe.get("apiVersion")),
        )
        or not isinstance(validators, list)
        or len(validators) != 3
        or any(
            not isinstance(item, Mapping) or set(item) != {"id"}
            for item in validators
        )
        or any(
            not re.fullmatch(r"^[A-Za-z0-9_-]{3,64}$", str(item["id"]))
            for item in validators
        )
        or len({canonical_json(item) for item in validators}) != 3
        or not isinstance(lanes, Mapping)
        or set(lanes) != {"delivery", "refund"}
    ):
        raise LaunchRehearsalError(
            "Stripe voucher rehearsal release or validator evidence is invalid."
        )
    delivery = _validate_lane(lanes["delivery"], lane="delivery")
    refund = _validate_lane(lanes["refund"], lane="refund")
    if (
        delivery["purchaseId"] == refund["purchaseId"]
        or delivery["paymentIntentId"] == refund["paymentIntentId"]
        or delivery["voucher"]["voucherCoinId"]
        == refund["voucher"]["voucherCoinId"]
    ):
        raise LaunchRehearsalError(
            "Delivery and refund must use distinct Stripe vouchers."
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
        "review": _validate_review(value.get("review")),
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
            "network": "testnet11",
            "rehearsalKind": SETTLEMENT_REHEARSAL_KIND,
            "requiredLanes": [
                "stripe-voucher-delivery",
                "stripe-voucher-refund",
            ],
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
        evidence.get("schemaVersion") == 3
        and evidence.get("kind") == SETTLEMENT_REHEARSAL_KIND
        and evidence.get("releaseTag") == settings.launch_release_tag
        and hmac.compare_digest(
            str(evidence.get("configHash") or "").lower(),
            config_hash,
        )
        and evidence.get("network") == "testnet11"
        and evidence.get("success") is True
        and evidence.get("validatorThreshold") == 2
        and isinstance(validators, list)
        and len(validators) == 3
        and all(validator_ids)
        and len(set(validator_ids)) == 3
        and len({canonical_json(item) for item in validators}) == 3
        and isinstance(lanes, Mapping)
        and set(lanes) == {"delivery", "refund"}
    )
    if not healthy:
        raise GenesisConflict(
            "settlement rehearsal does not prove Stripe voucher delivery and exact refund"
        )
    try:
        delivery = _validate_lane(lanes["delivery"], lane="delivery")
        refund = _validate_lane(lanes["refund"], lane="refund")
    except LaunchRehearsalError as exc:
        raise GenesisConflict(str(exc)) from exc
    if (
        delivery["purchaseId"] == refund["purchaseId"]
        or delivery["paymentIntentId"] == refund["paymentIntentId"]
        or delivery["voucher"]["voucherCoinId"]
        == refund["voucher"]["voucherCoinId"]
    ):
        raise GenesisConflict(
            "delivery and refund must use distinct Stripe vouchers"
        )
    return evidence, digest


__all__ = [
    "LaunchRehearsalError",
    "PHASES",
    "persist_evidence",
    "require_completed_rehearsal",
    "rehearsal_status",
    "start_rehearsal",
    "validate_status",
]
