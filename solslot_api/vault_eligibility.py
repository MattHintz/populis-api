"""One fail-closed definition of a zkPassport-approved purchase vault."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from fastapi import HTTPException, status

from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
from chia_rs.sized_bytes import bytes32

from .config import Settings


@dataclass(frozen=True)
class ApprovedVault:
    launcher_id: str
    p2_puzzle_hash: str
    current_coin_id: str
    identity_attest_root: str
    confirmed_block_index: int
    enrollment: Any


def require_current_approved_vault(
    settings: Settings,
    vault_launcher_id: str,
    *,
    expected_current_coin_id: Optional[str] = None,
    expected_identity_attest_root: Optional[str] = None,
    sync_enrollment: Optional[Callable[[Settings, str], Any]] = None,
) -> ApprovedVault:
    """Return current chain evidence or reject the vault for every purchase rail."""
    from .zkpassport_enrollments import _normalize_hex32, _sync_chia_stamp

    launcher = _normalize_hex32(vault_launcher_id, "vault_launcher_id")
    sync = sync_enrollment or _sync_chia_stamp
    try:
        enrollment = sync(settings, launcher)
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Vault credential receipt is not chain-confirmed: {exc.detail}",
        ) from exc
    receipt = enrollment.receipt
    if (
        enrollment.status != "chia_confirmed"
        or receipt is None
        or receipt.vaultLauncherId != launcher
        or receipt.policyVersion != settings.zkpassport_policy_version
        or receipt.network != settings.network
        or receipt.bridgePolicyHash != settings.zkpassport_bridge_policy_hash
        or not receipt.chiaVaultCoinId
        or receipt.confirmedBlockIndex is None
        or receipt.identityAttestRoot == "0x" + "00" * 32
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A current, server-confirmed zkPassport Chia vault credential is required.",
        )
    coin_id = _normalize_hex32(receipt.chiaVaultCoinId, "receipt.chiaVaultCoinId")
    identity_root = _normalize_hex32(
        receipt.identityAttestRoot, "receipt.identityAttestRoot"
    )
    coin_matches = expected_current_coin_id is None or coin_id == _normalize_hex32(
        expected_current_coin_id, "current_vault_coin_id"
    )
    root_matches = (
        expected_identity_attest_root is None
        or identity_root
        == _normalize_hex32(expected_identity_attest_root, "identity_attest_root")
    )
    if not coin_matches or not root_matches:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The requested vault coin or identity root is no longer current.",
        )
    p2 = puzzle_hash_for_p2_vault(
        bytes32.fromhex(launcher.removeprefix("0x"))
    )
    return ApprovedVault(
        launcher_id=launcher,
        p2_puzzle_hash="0x" + p2.hex(),
        current_coin_id=coin_id,
        identity_attest_root=identity_root,
        confirmed_block_index=int(receipt.confirmedBlockIndex),
        enrollment=enrollment,
    )


__all__ = ["ApprovedVault", "require_current_approved_vault"]
