"""zkPassport gasless relayer — FastAPI router (ERC-2771 meta-transactions).

Endpoint:
  POST /zkpassport/relay — submit a user-signed ForwardRequest to the
       PopulisForwarder, paying the gas on the user's behalf.

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
  - A per-signer in-memory rate limit guards the relayer key.
  - Returns 503 when ``POPULIS_ZKPASSPORT_RELAYER_PRIVATE_KEY_HEX`` is unset.
"""
from __future__ import annotations

import time
from functools import cache
import re
from threading import Lock

from eth_account import Account
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from web3 import Web3
from web3.exceptions import ContractLogicError

from .config import Settings

router = APIRouter(prefix="/zkpassport", tags=["zkpassport"])

# First 4 bytes of keccak256("verifyAndEmit((bytes32,bytes32,uint16,bytes32,
# bytes32,uint64,bytes32,bytes32,bytes32,uint64,bytes32,bytes32),bytes)").
_VERIFY_AND_EMIT_SELECTOR = "0x7fca187c"
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


# ── Per-signer sliding-window rate limiter (in-memory, best-effort) ──────────
_rate_lock = Lock()
_rate_hits: dict[str, list[float]] = {}


def _enforce_rate_limit(signer: str, per_minute: int) -> None:
    if per_minute <= 0:
        return
    now = time.monotonic()
    window_start = now - 60.0
    with _rate_lock:
        hits = [t for t in _rate_hits.get(signer, ()) if t >= window_start]
        if len(hits) >= per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many relay requests for this signer; retry shortly.",
            )
        hits.append(now)
        _rate_hits[signer] = hits


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


class RelayResponse(BaseModel):
    tx_hash: str
    relayer: str
    signer: str


def _require_relayer_account(settings: Settings):
    key = settings.zkpassport_relayer_private_key_hex
    if not key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="zkPassport relayer is not configured (POPULIS_ZKPASSPORT_RELAYER_PRIVATE_KEY_HEX unset).",
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


@router.post(
    "/relay",
    response_model=RelayResponse,
    summary="Relay a user-signed ForwardRequest, sponsoring the gas",
)
def relay(req: RelayRequest) -> RelayResponse:
    settings = _load_settings()
    account = _require_relayer_account(settings)

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

    _enforce_rate_limit(signer, settings.zkpassport_relay_per_signer_per_minute)

    try:
        data_bytes = Web3.to_bytes(hexstr=req.data)
        sig_bytes = Web3.to_bytes(hexstr=req.signature)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"data/signature must be hex: {exc}") from exc

    request_tuple = (signer, to, value, gas, req.deadline, data_bytes, sig_bytes)

    w3 = _w3(settings.zkpassport_evm_rpc_url)
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
        raise HTTPException(status_code=400, detail=f"Simulation reverted: {_describe_revert(exc)}") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC simulation failed: {exc}") from exc

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
        raise HTTPException(status_code=502, detail=f"Relay submission failed: {exc}") from exc

    return RelayResponse(tx_hash=w3.to_hex(tx_hash), relayer=account.address, signer=signer)
