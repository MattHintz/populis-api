"""zkPassport validator signer — FastAPI router.

Endpoints:
  GET  /zkpassport/validator        — returns BLS pubkey + config (503 when unset)
  POST /zkpassport/sign             — sign an indexed bridge AGG_SIG_ME message

The validator node holds a BLS keypair whose pubkey is curried into the
``zkpassport_bridge_message.clsp`` puzzle on the Chia side (the bridge policy
hash).  When a user completes a zkPassport proof on EVM the portal polls this
endpoint to collect the threshold signatures needed to spend the bridge coin.

Security model:
  - The signing endpoint is unauthenticated intentionally, but fail-closed: the
    validator message and bridge coin must come from the indexed canonical EVM
    event for the supplied vault launcher. The signature includes the bridge
    coin id and network additional data required by Chia AGG_SIG_ME.
  - Rate-limiting / IP filtering is left to a reverse-proxy layer.
"""

from __future__ import annotations

from functools import cache

from chia_rs import AugSchemeMPL, G1Element, PrivateKey
from chia_rs.sized_bytes import bytes32
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from .config import Settings
from .faucet import AGG_SIG_ME_DATA
from .zkpassport_enrollments import (
    _normalize_hex32,
    indexed_validator_signing_context,
)

router = APIRouter(prefix="/zkpassport", tags=["zkpassport"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_settings() -> Settings:
    return Settings()


@cache
def _validator_sk(seed_hex: str) -> PrivateKey:
    """Derive BLS PrivateKey from a 32-byte hex seed.  Cached per seed value."""
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise ValueError("zkpassport_validator_seed_hex must be exactly 32 bytes (64 hex chars)")
    return AugSchemeMPL.key_gen(seed)


def _get_sk() -> PrivateKey:
    settings = _load_settings()
    if not settings.zkpassport_validator_seed_hex:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="zkPassport validator is not configured (POPULIS_ZKPASSPORT_VALIDATOR_SEED_HEX unset).",
        )
    return _validator_sk(settings.zkpassport_validator_seed_hex)


# ---------------------------------------------------------------------------
# Response / request models
# ---------------------------------------------------------------------------

class ValidatorInfoResponse(BaseModel):
    pubkey_hex: str
    threshold: int


class SignRequest(BaseModel):
    validator_message_hex: str
    vault_launcher_id: str


class SignResponse(BaseModel):
    pubkey_hex: str
    signature_hex: str
    validator_message_hex: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "/validator",
    response_model=ValidatorInfoResponse,
    summary="Return the validator BLS public key",
)
def get_validator_info() -> ValidatorInfoResponse:
    """Return the BLS pubkey of this validator node and the signing threshold.

    Clients use this to verify that the pubkey matches the one curried into
    the ``zkpassport_bridge_message.clsp`` puzzle (bridge policy hash).
    Returns 503 when ``POPULIS_ZKPASSPORT_VALIDATOR_SEED_HEX`` is not set.
    """
    sk = _get_sk()
    pk: G1Element = sk.get_g1()
    return ValidatorInfoResponse(
        pubkey_hex=bytes(pk).hex(),
        threshold=1,
    )


@router.post(
    "/sign",
    response_model=SignResponse,
    summary="Sign a validatorMessage with the BLS validator key",
)
def sign_validator_message(req: SignRequest) -> SignResponse:
    """Sign an indexed validator message for its exact Chia bridge coin.

    The ``validator_message_hex`` must be the 64-char hex of the 32-byte
    ``validatorMessage`` field returned by the portal's EVM attestation poller
    (computed as ``sha256-tree-hash`` of the 12 attestation fields as defined
    in ``zkpassport_bridge_message.clsp``).

    Returns the 96-byte BLS signature over
    ``validatorMessage || bridgeCoinId || networkAdditionalData``.
    """
    sk = _get_sk()
    try:
        raw = bytes.fromhex(req.validator_message_hex.removeprefix("0x"))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="validator_message_hex must be a valid hex string.",
        )
    if len(raw) != 32:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"validator_message_hex must decode to exactly 32 bytes, got {len(raw)}.",
        )
    msg = bytes32(raw)
    try:
        vault_launcher_id = _normalize_hex32(req.vault_launcher_id, "vault_launcher_id")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    indexed = indexed_validator_signing_context(vault_launcher_id)
    if indexed is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No indexed zkPassport proof exists for this vault.",
        )
    indexed_message, bridge_coin_id, network = indexed
    if indexed_message.lower() != ("0x" + msg.hex()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="validator_message_hex does not match the indexed vault proof.",
        )
    additional_data = AGG_SIG_ME_DATA.get(network)
    if additional_data is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The indexed enrollment uses an unsupported Chia network.",
        )
    bridge_coin = bytes.fromhex(bridge_coin_id.removeprefix("0x"))
    sig = AugSchemeMPL.sign(sk, bytes(msg) + bridge_coin + additional_data)
    pk: G1Element = sk.get_g1()
    return SignResponse(
        pubkey_hex=bytes(pk).hex(),
        signature_hex=bytes(sig).hex(),
        validator_message_hex="0x" + msg.hex(),
    )
