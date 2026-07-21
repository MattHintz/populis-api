"""Strict remote co-signer client for governance-approved MINT execution.

KoS is intentionally *not* a coordinator wallet or a general BLS signing
service. The only request this module can make is the exact AGG_SIG_ME message
already emitted by the active governance singleton for one passed MINT bill.
The remote signer is separately operated and reached over mutual TLS; its
private key is never accepted through settings, HTTP, or a release artifact.
"""
from __future__ import annotations

import hashlib
import json
import ssl
from pathlib import Path
from typing import Any

import httpx
from chia_rs import AugSchemeMPL, G1Element, G2Element

from .config import Settings
from .mint_chain_validation import CanonicalKosMintExecution


class KosMintExecuteSignerError(RuntimeError):
    """The isolated KoS co-signer is unavailable or returned invalid data."""


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


def _request_payload(
    *,
    execution: CanonicalKosMintExecution,
    artifact_hash: str,
    proposal_id: str,
    network: str,
) -> dict[str, str]:
    return {
        "capability": "governance-mint-execute-v1",
        "network": network,
        "artifactHash": artifact_hash.lower(),
        "proposalId": proposal_id,
        "proposalHash": _hex(execution.proposal_hash),
        "governanceCoinId": _hex(execution.governance_coin_id),
        "mintExecuteCosignerPubkey": _hex(execution.cosigner_pubkey),
        "visibleMessage": _hex(execution.visible_message),
        "signingMessage": _hex(execution.signing_message),
    }


def request_hash(payload: dict[str, str]) -> str:
    """Stable audit identifier without treating it as signing authority."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _mtls_context(settings: Settings) -> ssl.SSLContext:
    paths = (
        (settings.kos_mint_execute_signer_mtls_ca_path, "KoS signer CA"),
        (settings.kos_mint_execute_signer_mtls_cert_path, "KoS signer client certificate"),
        (settings.kos_mint_execute_signer_mtls_key_path, "KoS signer client key"),
    )
    resolved: list[Path] = []
    for raw, label in paths:
        path = Path(str(raw or ""))
        if not path.is_file():
            raise KosMintExecuteSignerError(f"{label} file is unavailable")
        resolved.append(path)
    try:
        context = ssl.create_default_context(cafile=str(resolved[0]))
        context.load_cert_chain(certfile=str(resolved[1]), keyfile=str(resolved[2]))
    except (OSError, ssl.SSLError) as exc:
        raise KosMintExecuteSignerError("KoS signer mTLS credentials are invalid") from exc
    return context


def _verified_response_signature(
    *,
    body: Any,
    execution: CanonicalKosMintExecution,
    expected_request_hash: str,
) -> G2Element:
    """Parse and verify the isolated signer's narrowly-scoped response."""
    if not isinstance(body, dict):
        raise KosMintExecuteSignerError("KoS MINT execute signer response is malformed")
    if body.get("requestHash") != expected_request_hash:
        raise KosMintExecuteSignerError("KoS MINT execute signer response request hash mismatches")
    if str(body.get("mintExecuteCosignerPubkey", "")).lower() != _hex(
        execution.cosigner_pubkey
    ):
        raise KosMintExecuteSignerError("KoS MINT execute signer public key mismatches artifact")
    try:
        signature = G2Element.from_bytes(
            bytes.fromhex(str(body["signature"]).removeprefix("0x"))
        )
        public_key = G1Element.from_bytes(execution.cosigner_pubkey)
    except (KeyError, TypeError, ValueError) as exc:
        raise KosMintExecuteSignerError("KoS MINT execute signer signature is malformed") from exc
    if not AugSchemeMPL.verify(public_key, execution.signing_message, signature):
        raise KosMintExecuteSignerError("KoS MINT execute signer signature is invalid")
    return signature


async def request_kos_mint_execute_signature(
    *,
    settings: Settings,
    execution: CanonicalKosMintExecution,
    artifact_hash: str,
    proposal_id: str,
) -> tuple[G2Element, str]:
    """Return a verified signature for one canonical MINT execution.

    This fails closed when the capability is disabled, mTLS is unavailable,
    the remote response has the wrong key/message, or BLS verification fails.
    """
    if not settings.kos_mint_execute_signer_enabled:
        raise KosMintExecuteSignerError("KoS MINT execute signer is disabled")
    base_url = settings.kos_mint_execute_signer_url
    if not base_url or not base_url.startswith("https://"):
        raise KosMintExecuteSignerError("KoS MINT execute signer URL is unavailable")
    if not artifact_hash.startswith("0x") or len(artifact_hash) != 66:
        raise KosMintExecuteSignerError("signed artifact hash is malformed")

    payload = _request_payload(
        execution=execution,
        artifact_hash=artifact_hash,
        proposal_id=proposal_id,
        network=settings.network,
    )
    expected_request_hash = request_hash(payload)
    context = _mtls_context(settings)
    url = base_url.rstrip("/") + "/v1/governance/mint-execute/sign"
    try:
        async with httpx.AsyncClient(
            verify=context,
            timeout=settings.kos_mint_execute_signer_timeout_seconds,
            trust_env=False,
        ) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            body: Any = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise KosMintExecuteSignerError("KoS MINT execute signer request failed") from exc
    signature = _verified_response_signature(
        body=body,
        execution=execution,
        expected_request_hash=expected_request_hash,
    )
    return signature, expected_request_hash


__all__ = [
    "KosMintExecuteSignerError",
    "_request_payload",
    "_verified_response_signature",
    "request_hash",
    "request_kos_mint_execute_signature",
]
