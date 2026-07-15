"""Private 2-of-3 validator coordinator for Chia credential stamps."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from chia_rs import AugSchemeMPL, G1Element, G2Element
from pydantic import BaseModel, ConfigDict, Field, field_validator

from solslot_puzzles.zkpassport_bridge_driver import require_genesis_validator_set

from .config import Settings
from .faucet import AGG_SIG_ME_DATA


logger = logging.getLogger(__name__)


class ValidatorQuorumError(RuntimeError):
    """Raised when independent validator signatures cannot reach quorum."""


def _hex(value: str, size: int, field: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    if len(raw) != size:
        raise ValueError(f"{field} must be {size} bytes")
    return normalized


class ValidatorClaim(BaseModel):
    """All public evidence a signer must independently revalidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    artifact_hash: str
    vault_launcher_id: str
    current_vault_coin_id: str
    owner_key: str
    owner_auth_type: int = Field(..., ge=1, le=3)
    owner_authorization: str
    owner_authorization_hash: str
    current_timestamp: int = Field(..., ge=1)
    evm_transaction_hash: str
    evm_block_number: int = Field(..., ge=0)
    emitter_address: str
    policy_version: int = Field(..., ge=2)
    identity_attest_root: str
    attestation_leaf_hash: str
    scoped_nullifier: str
    nullifier_type: int = Field(..., ge=0)
    service_scope_hash: str
    service_subscope_hash: str
    proof_timestamp: int = Field(..., ge=1)
    bridge_policy_hash: str
    bridge_parent_id: str
    bridge_amount: int = Field(..., gt=0)
    bridge_coin_id: str
    validator_message: str

    @field_validator(
        "artifact_hash",
        "vault_launcher_id",
        "current_vault_coin_id",
        "owner_authorization_hash",
        "identity_attest_root",
        "attestation_leaf_hash",
        "scoped_nullifier",
        "service_scope_hash",
        "service_subscope_hash",
        "bridge_policy_hash",
        "bridge_parent_id",
        "bridge_coin_id",
        "validator_message",
    )
    @classmethod
    def _hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator("evm_transaction_hash")
    @classmethod
    def _tx_hash(cls, value: str) -> str:
        return _hex(value, 32, "evm_transaction_hash")

    @field_validator("emitter_address")
    @classmethod
    def _address(cls, value: str) -> str:
        return _hex(value, 20, "emitter_address")

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(f"unsupported Chia network: {self.network}")
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.bridge_coin_id[2:])
            + additional_data
        )


class ValidatorSignatureResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claimHash: str
    signerIndex: int = Field(..., ge=0)
    validatorPubkey: str
    signature: str


class ValidatorHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    signerIndex: int = Field(..., ge=0, le=2)
    validatorPubkey: str
    apiCommit: str
    protocolCommit: str
    network: str
    bridgePolicyHash: str
    evmAddresses: dict[str, str]
    artifactHash: str | None = None
    artifactReady: bool
    ledgerReady: bool


@dataclass(frozen=True)
class ValidatorQuorumResult:
    signer_indices: tuple[int, ...]
    aggregated_signature: G2Element
    claim_hash: str


def configured_validator_pubkeys(settings: Settings) -> tuple[bytes, ...]:
    try:
        pubkeys = tuple(
            bytes.fromhex(value.removeprefix("0x"))
            for value in settings.zkpassport_validator_pubkeys
        )
    except ValueError as exc:
        raise ValidatorQuorumError("validator public key configuration is invalid") from exc
    try:
        validator_set = require_genesis_validator_set(
            pubkeys,
            settings.zkpassport_validator_threshold,
        )
    except ValueError as exc:
        raise ValidatorQuorumError(str(exc)) from exc
    if len(settings.zkpassport_validator_urls) != len(validator_set.pubkeys):
        raise ValidatorQuorumError("validator URL and public key counts do not match")
    return validator_set.pubkeys


def configured_bridge_policy_hash(settings: Settings) -> str:
    pubkeys = configured_validator_pubkeys(settings)
    validator_set = require_genesis_validator_set(
        pubkeys,
        settings.zkpassport_validator_threshold,
    )
    return "0x" + bytes(validator_set.policy_hash).hex()


def _private_validator_client(settings: Settings) -> httpx.AsyncClient:
    ca_path = Path(str(settings.zkpassport_validator_mtls_ca_path or ""))
    cert_path = Path(str(settings.zkpassport_validator_mtls_cert_path or ""))
    key_path = Path(str(settings.zkpassport_validator_mtls_key_path or ""))
    for path, label in (
        (ca_path, "validator CA"),
        (cert_path, "validator client certificate"),
        (key_path, "validator client key"),
    ):
        if not path.is_file():
            raise ValidatorQuorumError(f"{label} file is unavailable")

    try:
        ssl_context = ssl.create_default_context(cafile=str(ca_path))
        ssl_context.load_cert_chain(
            certfile=str(cert_path),
            keyfile=str(key_path),
        )
    except (OSError, ssl.SSLError) as exc:
        raise ValidatorQuorumError(
            "validator mTLS client credentials are invalid"
        ) from exc

    return httpx.AsyncClient(
        verify=ssl_context,
        timeout=settings.zkpassport_validator_timeout_seconds,
        trust_env=False,
    )


async def probe_validator_health(
    settings: Settings,
    *,
    expected_api_commit: str,
    expected_protocol_commit: str,
    expected_network: str,
    expected_bridge_policy_hash: str,
    expected_evm_addresses: dict[str, str],
    client: httpx.AsyncClient | None = None,
) -> tuple[ValidatorHealthResponse, ...]:
    """Contact every private signer and bind health to the ceremony plan."""
    pubkeys = configured_validator_pubkeys(settings)
    if configured_bridge_policy_hash(settings) != expected_bridge_policy_hash.lower():
        raise ValidatorQuorumError(
            "ceremony bridge policy does not match configured validator roster"
        )
    normalized_addresses = {
        key: value.lower() for key, value in expected_evm_addresses.items()
    }
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_health(index: int, url: str) -> ValidatorHealthResponse:
        response = await client.get(url.rstrip("/") + "/health")
        response.raise_for_status()
        parsed = ValidatorHealthResponse.model_validate(response.json())
        expected_pubkey = "0x" + pubkeys[index].hex()
        checks = (
            (parsed.status, "healthy", "status"),
            (parsed.signerIndex, index, "signer index"),
            (parsed.validatorPubkey.lower(), expected_pubkey, "validator public key"),
            (parsed.apiCommit, expected_api_commit, "API commit"),
            (parsed.protocolCommit, expected_protocol_commit, "protocol commit"),
            (parsed.network, expected_network, "network"),
            (
                parsed.bridgePolicyHash.lower(),
                expected_bridge_policy_hash.lower(),
                "bridge policy",
            ),
            (
                {key: value.lower() for key, value in parsed.evmAddresses.items()},
                normalized_addresses,
                "EVM addresses",
            ),
            (parsed.ledgerReady, True, "signature ledger"),
        )
        for observed, expected, label in checks:
            if observed != expected:
                raise ValidatorQuorumError(
                    f"validator signer {index} {label} does not match ceremony"
                )
        return parsed

    try:
        results = await asyncio.gather(
            *(
                request_health(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            ),
            return_exceptions=True,
        )
    finally:
        if owns_client:
            await client.aclose()
    failures = [
        f"signer {index}: {result}"
        for index, result in enumerate(results)
        if isinstance(result, BaseException)
    ]
    if failures:
        raise ValidatorQuorumError(
            "live validator preflight failed: " + "; ".join(failures)
        )
    return tuple(result for result in results if isinstance(result, ValidatorHealthResponse))


async def collect_validator_quorum(
    settings: Settings,
    claim: ValidatorClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect and verify an exact 2-of-3 signature set over ``claim``."""

    pubkeys = configured_validator_pubkeys(settings)
    expected_policy_hash = configured_bridge_policy_hash(settings)
    if claim.bridge_policy_hash != expected_policy_hash:
        raise ValidatorQuorumError("claim bridge policy does not match configured validators")
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()

    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(index: int, url: str) -> tuple[int, G2Element] | None:
        endpoint = url.rstrip("/") + "/v1/zkpassport/sign"
        try:
            response = await client.post(
                endpoint,
                json={"claim": claim.model_dump(mode="json"), "claimHash": claim_hash},
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash:
                raise ValueError("claim hash mismatch")
            if parsed.signerIndex != index:
                raise ValueError("signer index mismatch")
            configured_pubkey = pubkeys[index]
            response_pubkey = bytes.fromhex(parsed.validatorPubkey.removeprefix("0x"))
            if response_pubkey != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            public_key = G1Element.from_bytes(configured_pubkey)
            if not AugSchemeMPL.verify(public_key, message, signature):
                raise ValueError("invalid validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001 - one signer may be unavailable
            logger.warning("validator signer %s rejected or unavailable: %s", index, exc)
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()

    valid = sorted((item for item in responses if item is not None), key=lambda item: item[0])
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            f"validator quorum unavailable: received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


__all__ = [
    "ValidatorClaim",
    "ValidatorHealthResponse",
    "ValidatorQuorumError",
    "ValidatorQuorumResult",
    "collect_validator_quorum",
    "configured_bridge_policy_hash",
    "configured_validator_pubkeys",
    "probe_validator_health",
]
