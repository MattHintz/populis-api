"""zkPassport validator public metadata router.

Endpoint:
  GET /zkpassport/validator — returns the public BLS key and threshold.

The validator node holds a BLS keypair whose pubkey is curried into the Chia
bridge policy. Clients use this read-only endpoint to verify that public key.

Validator signatures are created only inside the owner-authenticated enrollment
state machine after the EVM event, one-time bridge coin, and Chia vault owner
have all been verified. No public signing endpoint exists.
"""

from __future__ import annotations

from functools import cache

from chia_rs import AugSchemeMPL, G1Element, PrivateKey
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from .config import Settings

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
            detail="zkPassport validator is not configured (SOLSLOT_ZKPASSPORT_VALIDATOR_SEED_HEX unset).",
        )
    return _validator_sk(settings.zkpassport_validator_seed_hex)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class ValidatorInfoResponse(BaseModel):
    pubkey_hex: str
    threshold: int


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
    Returns 503 when ``SOLSLOT_ZKPASSPORT_VALIDATOR_SEED_HEX`` is not set.
    """
    sk = _get_sk()
    pk: G1Element = sk.get_g1()
    return ValidatorInfoResponse(
        pubkey_hex=bytes(pk).hex(),
        threshold=1,
    )
