"""zkPassport gasless relayer — FastAPI router (ERC-2771 meta-transactions).

Endpoint:
  POST /zkpassport/relay — submit a user-signed ForwardRequest to the
       SolslotForwarder, paying the gas on the user's behalf.

Why this exists
---------------
Alpha testers shouldn't need Sepolia ETH to complete on-chain verification.
The user still signs an EIP-712 ``ForwardRequest`` in their wallet (a gasless
signature — no transaction), and this service relays it through the ERC-2771
forwarder while paying the gas.  The forwarder verifies the user's signature +
nonce on-chain, and the emitter attributes the event to the user via
``_msgSender()`` — so the relayer is never the logical author.

Security model
--------------
  - ``to`` is pinned to the configured emitter; any other target is rejected,
    so the funded key can only ever drive ``verifyAndEmit``.
  - Only the ``verifyAndEmit`` selector is accepted in ``data``.
  - The forwarder ``verify()`` (signature/nonce/deadline) AND the full
    ``execute()`` are simulated via ``eth_call`` before any gas is spent, so
    invalid proofs, expired signatures, and replays cost nothing.
  - SQLite-WAL budgets, nonce locks, bridge-coin uniqueness, and a circuit
    breaker protect the sponsored key across restarts and API workers.
  - Returns 503 when ``SOLSLOT_ZKPASSPORT_RELAYER_PRIVATE_KEY_HEX`` is unset.
"""
from __future__ import annotations

import hashlib
import json
import time
from functools import cache
import re

from eth_abi import decode as abi_decode
from eth_account import Account
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from web3 import Web3
from web3.exceptions import ContractLogicError

from .config import Settings
from .credential_auth import OwnerAuth, verify_owner_auth
from .credential_ledger import (
    LedgerCircuitOpen,
    LedgerConflict,
    LedgerRateLimited,
    get_credential_ledger,
)

router = APIRouter(prefix="/zkpassport", tags=["zkpassport"])

# First 4 bytes of keccak256("verifyAndEmit((bytes32,bytes32,uint64),bytes)").
_VERIFY_AND_EMIT_SELECTOR = "0xd33b3d83"
_ENROLLMENT_BINDING_ABI = "(bytes32,bytes32,uint64)"
_REVERT_SELECTOR_RE = re.compile(r"0x[0-9a-fA-F]{8}")
_KNOWN_REVERT_SELECTORS = {
    "0xd6bda275": (
        "OpenZeppelin FailedCall(): the trusted forwarder accepted the request, "
        "but the emitter call reverted. Refresh the enrollment and QR; if it "
        "persists, the proof domain/scope or bridge coin fields do not match "
        "the deployed emitter."
    ),
    "0xd611c318": "ProofVerificationFailed(): zkPassport verifier rejected the proof.",
    "0xa54999ed": "ScopeMismatch(): zkPassport proof scope does not match this vault.",
    "0x8c7f1d8f": "InvalidZkPassportProof(): emitter rejected the zkPassport proof.",
    "0x4db028fe": "InvalidBridgeCoinId(): bridge parent, amount, or policy hash mismatch.",
}

# verifyAndEmit measures ~1.05M gas; cap the forwarded gas to leave headroom
# without letting a caller drain the relayer through an oversized inner call.
_MAX_INNER_GAS = 3_000_000
# Bound the replay window: reject ForwardRequests whose deadline is further out.
_MAX_DEADLINE_WINDOW_SECONDS = 3600

_FORWARD_REQUEST_COMPONENTS = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "gas", "type": "uint256"},
    {"name": "deadline", "type": "uint48"},
    {"name": "data", "type": "bytes"},
    {"name": "signature", "type": "bytes"},
]
_FORWARDER_ABI = [
    {
        "type": "function",
        "name": "execute",
        "stateMutability": "payable",
        "inputs": [{"name": "request", "type": "tuple", "components": _FORWARD_REQUEST_COMPONENTS}],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "verify",
        "stateMutability": "view",
        "inputs": [{"name": "request", "type": "tuple", "components": _FORWARD_REQUEST_COMPONENTS}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "nonces",
        "stateMutability": "view",
        "inputs": [{"name": "owner", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]


def _load_settings() -> Settings:
    return Settings()


@cache
def _w3(rpc_url: str) -> Web3:
    return Web3(Web3.HTTPProvider(rpc_url))


# ── Request / response models ────────────────────────────────────────────────
class RelayRequest(BaseModel):
    """A user-signed OpenZeppelin ERC2771Forwarder ForwardRequestData."""

    model_config = {"populate_by_name": True}

    from_address: str = Field(alias="from")
    to: str
    value: str = "0"
    gas: str
    deadline: int
    data: str
    signature: str
    ownerAuth: OwnerAuth


class RelayResponse(BaseModel):
    tx_hash: str
    relayer: str
    signer: str


def _decode_enrollment_calldata(data: bytes) -> tuple[str, str, int]:
    """Decode the only enrollment binding accepted by the V2 emitter.

    Credential commitments are deliberately absent from this tuple: the
    emitter derives them from verifier-returned proof inputs.
    """
    expected_selector = Web3.to_bytes(hexstr=_VERIFY_AND_EMIT_SELECTOR)
    if len(data) < 4 or data[:4] != expected_selector:
        raise ValueError("calldata selector is not canonical verifyAndEmit")
    binding, _proof = abi_decode([_ENROLLMENT_BINDING_ABI, "bytes"], data[4:])
    vault_launcher_id = "0x" + bytes(binding[0]).hex()
    bridge_parent_id = "0x" + bytes(binding[1]).hex()
    bridge_amount = int(binding[2])
    if vault_launcher_id == "0x" + "00" * 32:
        raise ValueError("vaultLauncherId must be non-zero")
    if bridge_parent_id == "0x" + "00" * 32:
        raise ValueError("bridgeParentId must be non-zero")
    if bridge_amount <= 0:
        raise ValueError("bridgeAmount must be positive")
    return vault_launcher_id, bridge_parent_id, bridge_amount


def _require_relayer_account(settings: Settings):
    key = settings.zkpassport_relayer_private_key_hex
    if not key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="zkPassport relayer is not configured (SOLSLOT_ZKPASSPORT_RELAYER_PRIVATE_KEY_HEX unset).",
        )
    try:
        return Account.from_key(key)
    except Exception as exc:  # noqa: BLE001 - surfaced as a clean 503
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="zkPassport relayer key is invalid.",
        ) from exc


def _describe_revert(exc: BaseException) -> str:
    text = str(exc)
    selectors = []
    for match in _REVERT_SELECTOR_RE.findall(text):
        selector = match.lower()
        if selector not in selectors:
            selectors.append(selector)
    if not selectors:
        return text
    decoded = [
        _KNOWN_REVERT_SELECTORS.get(selector, f"Unknown EVM revert selector {selector}.")
        for selector in selectors
    ]
    return f"{'; '.join(decoded)} Raw error: {text}"


def _simulate_forwarded_inner_call(
    w3: Web3,
    *,
    forwarder_address: str,
    emitter_address: str,
    signer_address: str,
    data: bytes,
) -> str:
    """Simulate the ERC-2771 target call to expose its real revert data.

    OpenZeppelin's forwarder wraps a target revert in ``FailedCall()``.  A
    direct ``eth_call`` from the trusted forwarder with the original signer
    appended reproduces the exact calldata seen by ``ERC2771Context`` and
    preserves the emitter/verifier custom error for operator diagnostics.
    """
    forwarded_data = data + Web3.to_bytes(hexstr=signer_address)
    try:
        w3.eth.call(
            {
                "from": forwarder_address,
                "to": emitter_address,
                "value": 0,
                "data": forwarded_data,
            }
        )
    except Exception as exc:  # noqa: BLE001 - the RPC provider controls the exception type
        return _describe_revert(exc)
    return "The emitter simulation succeeded; the failure is in the forwarder execution path."


@router.post(
    "/relay",
    response_model=RelayResponse,
    summary="Relay a user-signed ForwardRequest, sponsoring the gas",
)
def relay(req: RelayRequest, request: Request) -> RelayResponse:
    settings = _load_settings()
    account = _require_relayer_account(settings)

    if not settings.zkpassport_forwarder_address or not settings.zkpassport_emitter_address:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Fresh Solslot V2 forwarder and emitter addresses are not configured.",
        )

    # ── Pin addresses; the client cannot redirect the relayer ──
    try:
        to = Web3.to_checksum_address(req.to)
        signer = Web3.to_checksum_address(req.from_address)
        forwarder_addr = Web3.to_checksum_address(settings.zkpassport_forwarder_address)
        emitter_addr = Web3.to_checksum_address(settings.zkpassport_emitter_address)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Invalid address: {exc}") from exc

    if to != emitter_addr:
        raise HTTPException(status_code=400, detail="request.to must be the configured emitter.")
    if not req.data.lower().startswith(_VERIFY_AND_EMIT_SELECTOR):
        raise HTTPException(status_code=400, detail="request.data must call verifyAndEmit.")

    try:
        data_bytes = Web3.to_bytes(hexstr=req.data)
        sig_bytes = Web3.to_bytes(hexstr=req.signature)
        vault_launcher_id, bridge_parent_id, bridge_amount = _decode_enrollment_calldata(
            data_bytes
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=422,
            detail=f"request.data is not canonical Solslot V2 enrollment calldata: {exc}",
        ) from exc

    auth_payload = req.model_dump(by_alias=True, exclude={"ownerAuth"})
    verified_owner = verify_owner_auth(
        settings,
        vault_launcher_id=vault_launcher_id,
        action="relay",
        payload=auth_payload,
        owner_auth=req.ownerAuth,
    )
    if verified_owner.vault_record.owner_evm_address and (
        verified_owner.vault_record.owner_evm_address.lower() != signer.lower()
    ):
        raise HTTPException(
            status_code=403,
            detail="ForwardRequest signer is not the registered EVM vault owner.",
        )

    ledger = get_credential_ledger(settings)
    enrollment = ledger.get_enrollment(vault_launcher_id.lower())
    if not enrollment:
        raise HTTPException(status_code=404, detail="Enrollment not found for relay binding.")
    if str(enrollment.get("status")) != "reserved":
        raise HTTPException(status_code=409, detail="Enrollment is not awaiting an EVM proof.")
    if (
        str(enrollment.get("bridgeParentId", "")).lower() != bridge_parent_id.lower()
        or int(enrollment.get("bridgeAmount", 0)) != bridge_amount
    ):
        raise HTTPException(
            status_code=409,
            detail="Relay binding does not match the reserved Chia bridge coin.",
        )

    try:
        value = int(req.value)
        gas = int(req.gas)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="value and gas must be integer strings.") from exc

    if value != 0:
        raise HTTPException(status_code=400, detail="request.value must be 0.")
    if gas <= 0 or gas > _MAX_INNER_GAS:
        raise HTTPException(status_code=400, detail=f"request.gas must be in (0, {_MAX_INNER_GAS}].")

    now = int(time.time())
    if req.deadline <= now:
        raise HTTPException(status_code=400, detail="request.deadline has already passed.")
    if req.deadline > now + _MAX_DEADLINE_WINDOW_SECONDS:
        raise HTTPException(status_code=400, detail="request.deadline is too far in the future.")

    request_tuple = (signer, to, value, gas, req.deadline, data_bytes, sig_bytes)

    w3 = _w3(settings.zkpassport_evm_rpc_url)
    try:
        observed_chain_id = int(w3.eth.chain_id)
        if observed_chain_id != settings.zkpassport_evm_chain_id:
            raise HTTPException(
                status_code=503,
                detail="Configured zkPassport RPC is on the wrong EVM chain.",
            )
        if not w3.eth.get_code(forwarder_addr) or not w3.eth.get_code(emitter_addr):
            raise HTTPException(
                status_code=503,
                detail="Fresh Solslot V2 forwarder or emitter bytecode is missing.",
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC deployment check failed: {exc}") from exc
    forwarder = w3.eth.contract(address=forwarder_addr, abi=_FORWARDER_ABI)

    # ── Free pre-checks: signature/nonce/deadline, then full inner simulation ──
    try:
        valid = forwarder.functions.verify(request_tuple).call()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC verify() failed: {exc}") from exc
    if not valid:
        raise HTTPException(status_code=400, detail="ForwardRequest signature/nonce/deadline is invalid.")

    try:
        forwarder.functions.execute(request_tuple).call({"from": account.address, "value": 0})
    except ContractLogicError as exc:
        inner_detail = _simulate_forwarded_inner_call(
            w3,
            forwarder_address=forwarder_addr,
            emitter_address=to,
            signer_address=signer,
            data=data_bytes,
        )
        raise HTTPException(
            status_code=400,
            detail=(
                f"Simulation reverted: {_describe_revert(exc)} "
                f"Inner emitter simulation: {inner_detail}"
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC simulation failed: {exc}") from exc

    try:
        forwarder_nonce = int(forwarder.functions.nonces(signer).call())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC nonce lookup failed: {exc}") from exc
    request_digest = "0x" + hashlib.sha256(
        json.dumps(auth_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    source_ip = request.client.host if request.client else "unknown"
    try:
        ledger.reserve_relay(
            request_digest=request_digest,
            vault_launcher_id=vault_launcher_id,
            owner_key=verified_owner.owner_key,
            source_ip=source_ip,
            bridge_coin_id=str(enrollment["bridgeCoinId"]),
            forwarder_nonce=forwarder_nonce,
            inner_gas=gas,
            per_ip_per_minute=settings.zkpassport_relay_per_ip_per_minute,
            per_owner_per_minute=settings.zkpassport_relay_per_owner_per_minute,
            per_vault_per_hour=settings.zkpassport_relay_per_vault_per_hour,
            global_gas_per_day=settings.zkpassport_relay_global_gas_per_day,
        )
    except LedgerRateLimited as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except LedgerCircuitOpen as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except LedgerConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    # ── Build, sign, and broadcast the sponsored transaction ──
    try:
        estimated = forwarder.functions.execute(request_tuple).estimate_gas(
            {"from": account.address, "value": 0}
        )
        tx = forwarder.functions.execute(request_tuple).build_transaction(
            {
                "from": account.address,
                "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                "value": 0,
                "chainId": settings.zkpassport_evm_chain_id,
                "gas": int(estimated * 1.25),
            }
        )
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    except Exception as exc:  # noqa: BLE001
        ledger.finish_relay(
            request_digest=request_digest,
            tx_hash=None,
            error=str(exc),
            failure_threshold=settings.zkpassport_relay_circuit_failure_threshold,
            cooldown_seconds=settings.zkpassport_relay_circuit_cooldown_seconds,
        )
        raise HTTPException(status_code=502, detail=f"Relay submission failed: {exc}") from exc

    tx_hash_hex = w3.to_hex(tx_hash)
    ledger.finish_relay(
        request_digest=request_digest,
        tx_hash=tx_hash_hex,
        error=None,
        failure_threshold=settings.zkpassport_relay_circuit_failure_threshold,
        cooldown_seconds=settings.zkpassport_relay_circuit_cooldown_seconds,
    )
    return RelayResponse(tx_hash=tx_hash_hex, relayer=account.address, signer=signer)
