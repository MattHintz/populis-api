"""EVM / EIP-712 helpers for the Populis API.

Two responsibilities:

1. **Typed data builders** — emit the exact EIP-712 payload the frontend should
   pass to `signTypedData_v4`.  One for *vault registration* (onboarding, when
   no vault coin id exists yet) and one that mirrors the in-puzzle
   `PopulisVaultSpend` typehash for actual vault operations.

2. **Signature verification + pubkey recovery** — given an EIP-712 typed data
   and a 65-byte signature, recover the 33-byte compressed secp256k1 pubkey
   and the 20-byte Ethereum address.  The recovered address is checked
   against the expected one; the pubkey is what we curry into the vault
   singleton as `OWNER_PUBKEY`.

Audit history:

- v1 → v2 (CANON_POPULIS_API_AUDIT_2026_04_26 POP-CANON-002 / SIGCOV-1):
  registration envelope expanded from {owner, nonce} to additionally include
  poolLauncherId, authType, chiaNetwork.  This closes Strategy 2 snapshot
  drift (operator changing pool config between /auth/challenge and
  /vault/register/evm) and SIGN-1 intent-display divergence (user wallet
  now shows the pool/network/auth-type binding before signing).
"""
from __future__ import annotations

from typing import Any

from eth_account.messages import encode_typed_data
from eth_keys import keys as eth_keys
from eth_utils import keccak, to_checksum_address

from .config import get_settings

REGISTER_PRIMARY_TYPE = "PopulisVaultRegister"
# v2 envelope (post POP-CANON-002 fix).  ``eip712_version`` in Settings is
# pinned to "2" so v1 signatures cannot replay against this expanded type.
REGISTER_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
    ],
    REGISTER_PRIMARY_TYPE: [
        {"name": "owner", "type": "address"},
        {"name": "nonce", "type": "bytes32"},
        # New in v2: bind the user's signature to the exact pool / network /
        # auth_type the vault will be registered under.  These are surfaced
        # at /auth/challenge time and snapshotted into the ChallengeStore
        # entry; /vault/register/evm uses the SNAPSHOTTED values (not
        # current settings) to reconstruct the digest, so an operator
        # changing config between challenge and register cannot cause
        # signature drift.
        {"name": "poolLauncherId", "type": "bytes32"},
        {"name": "authType", "type": "string"},
        {"name": "chiaNetwork", "type": "string"},
    ],
}

# Mirrors `POPULIS_VAULT_TYPEHASH_STRING` in populis_puzzles/vault_driver.py.
# Kept as a module constant so tests can assert both sides agree.
VAULT_SPEND_TYPEHASH_STRING = (
    "PopulisVaultSpend(bytes32 spend_case,bytes32 deed_launcher_id,bytes32 vault_coin_id)"
)


def eip712_domain() -> dict[str, Any]:
    s = get_settings()
    return {
        "name": s.eip712_name,
        "version": s.eip712_version,
        "chainId": s.eip712_chain_id,
    }


def registration_typed_data(
    owner_address: str,
    nonce_hex: str,
    pool_launcher_id_hex: str,
    auth_type: str,
    chia_network: str,
) -> dict[str, Any]:
    """Build the EIP-712 envelope the user signs to onboard.

    Arguments:
        owner_address: 0x-prefixed checksummed Ethereum address of the
            wallet that will own the vault.
        nonce_hex: 0x-prefixed 32-byte random nonce previously issued by
            ``ChallengeStore.issue()`` (bound to ``owner_address``).
        pool_launcher_id_hex: 0x-prefixed 32-byte launcher id of the pool
            the vault will join.  Pass an all-zero bytes32 for vaults
            registered before a pool has been deployed.
        auth_type: ``"secp256k1"`` for EVM wallets, ``"bls"`` for Chia,
            ``"secp256r1"`` for passkeys.  Surfaced verbatim in the wallet
            UI so the user can verify the auth path.
        chia_network: ``"testnet11"`` or ``"mainnet"``.  Prevents a user
            from accidentally signing a testnet registration that an
            attacker could replay against mainnet.

    The returned dict is what the frontend passes to
    ``window.ethereum.request({method: "eth_signTypedData_v4", ...})``.
    """
    return {
        "types": REGISTER_TYPES,
        "primaryType": REGISTER_PRIMARY_TYPE,
        "domain": eip712_domain(),
        "message": {
            "owner": to_checksum_address(owner_address),
            "nonce": nonce_hex,
            "poolLauncherId": pool_launcher_id_hex,
            "authType": auth_type,
            "chiaNetwork": chia_network,
        },
    }


def recover_evm_signer(typed_data: dict[str, Any], signature_hex: str) -> EvmRecovery:
    """Recover the Ethereum address + compressed secp256k1 pubkey.

    Raises ValueError if the signature is malformed.
    """
    sig = _strip0x(signature_hex)
    if len(sig) != 130:
        raise ValueError(
            f"EIP-712 signature must be 65 bytes (130 hex chars), got {len(sig)}"
        )
    r = int(sig[0:64], 16)
    s = int(sig[64:128], 16)
    v = int(sig[128:130], 16)
    # Normalise v: Ethereum signatures use 27/28 historically; eth-keys wants 0/1.
    if v >= 27:
        v -= 27
    signature = eth_keys.Signature(vrs=(v, r, s))

    digest = _eip712_digest(typed_data)

    pubkey = signature.recover_public_key_from_msg_hash(digest)
    address = pubkey.to_checksum_address()
    compressed = pubkey.to_compressed_bytes()
    return EvmRecovery(address=address, compressed_pubkey=compressed, digest=digest)


def _eip712_digest(typed_data: dict[str, Any]) -> bytes:
    """Compute the 32-byte EIP-712 digest that was actually signed.

    eth_account.encode_typed_data returns a SignableMessage(version, header, body)
    where:
      - version  = 0x01  (EIP-712 version byte)
      - header   = 32-byte domain separator
      - body     = 32-byte hashStruct(message)
    The signed digest is:
      keccak256(0x19 || version || header || body)
    """
    signable = encode_typed_data(full_message=typed_data)
    prefix = b"\x19"
    return keccak(prefix + bytes(signable.version) + signable.header + signable.body)


class EvmRecovery:
    """Result of recovering an EVM signer."""

    __slots__ = ("address", "compressed_pubkey", "digest")

    def __init__(self, address: str, compressed_pubkey: bytes, digest: bytes) -> None:
        self.address = address
        self.compressed_pubkey = compressed_pubkey
        self.digest = digest

    @property
    def compressed_pubkey_hex(self) -> str:
        return "0x" + self.compressed_pubkey.hex()


def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


__all__ = [
    "REGISTER_PRIMARY_TYPE",
    "REGISTER_TYPES",
    "VAULT_SPEND_TYPEHASH_STRING",
    "eip712_domain",
    "registration_typed_data",
    "recover_evm_signer",
    "EvmRecovery",
    "keccak",
]
