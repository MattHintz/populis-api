"""Off-chain reader for the on-chain admin-authority v2 singleton.

The v2 singleton (``admin_authority_v2_inner.clsp``) replaces v1's flat
BLS allowlist with CHIP-0043 MIPS composition: each admin slot holds a
`OneOfN` of personal authentication methods (BLS, EIP-712, passkey, ...)
under a protocol-level `MofN` quorum.

What this module does (Phase 2-informational-only, parallel to v1):

  * Surfaces the launcher coin id, MIPS root hash, admins hash, pending
    ops hash, and authority version on a ``/admin/auth/authority_v2``
    endpoint so admins and external auditors can independently verify
    operator config matches on-chain state by walking the singleton
    lineage on coinset.org.
  * Computes the deterministic ``state_hash`` from settings, mirroring
    what the on-chain ``state-hash`` defun emits in
    ``CREATE_PUZZLE_ANNOUNCEMENT``. This is the cross-repo binding
    point between off-chain monitoring and on-chain singleton state.

What this module does NOT do yet (Phase 2.5+):

  * Replace the v1 admin authority as the gating source for
    ``require_admin_jwt``. Until v2's full MIPS authentication flow
    lands in the API (including the EIP-712 / passkey / BLS member
    dispatch), the admin desk continues to enforce via v1's BLS
    allowlist; the v2 singleton is informational only.

The Chialisp puzzle and its driver live in
``populis_protocol/populis_puzzles/admin_authority_v2_inner.clsp`` and
``populis_protocol/populis_puzzles/admin_authority_v2_driver.py``. The
test suite in ``populis_protocol/tests/test_admin_authority_v2.py``
enforces the cross-repo state-hash contract end-to-end.

Migration story: see ``research/POPULIS_ADMIN_AUTHORITY_V2_DESIGN.md``
section 7 for the operator playbook.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from chia_rs.sized_bytes import bytes32

from populis_puzzles.admin_authority_v2_driver import (
    EMPTY_LIST_HASH,
    compute_state_hash as _compute_state_hash,
)

from .config import Settings


@dataclass(frozen=True)
class AdminAuthorityV2Snapshot:
    """Deterministic snapshot of the v2 admin-authority singleton state.

    All fields are hex-encoded / JSON-friendly so the API can return
    this dataclass directly without leaking ``chia`` / ``chia_rs``
    imports out to API consumers.

    Cross-repo contract: ``state_hash_hex`` here MUST equal what the
    on-chain ``state-hash`` defun produces. The populis_protocol test
    ``test_state_hash_via_dataclass_matches_off_chain_compute``
    enforces this end-to-end against the puzzle's actual Chialisp
    output, so changes to either side that drift will fail CI.
    """

    enabled: bool
    """``False`` when the operator has not configured v2.

    All other fields are still populated for diagnostic display when
    enabled is False (e.g., the operator might have computed the
    launcher ID but not yet broadcast the launch spend — useful for
    "ready to deploy" UI states)."""

    launcher_id_hex: Optional[str]
    """0x-prefixed launcher coin id of the on-chain v2 singleton, or
    ``None`` when ``POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID``
    is unset. Frontends locate the singleton on coinset.org via this
    id."""

    mips_root_hash_hex: Optional[str]
    """0x-prefixed sha256-tree hash of the MIPS m_of_n quorum tree.
    Off-chain monitors verify this matches the curried MIPS_ROOT_HASH
    by uncurrying the v2 inner puzzle (see
    ``admin_authority_v2_driver.parse_inner_puzzle``)."""

    admins_hash_hex: Optional[str]
    """0x-prefixed sha256-tree hash of the admins list (each entry is
    ``(admin_idx, leaves_list, m_within)``). The full admins list
    travels in the solution at every state-changing spend; off-chain
    monitors decode it from those solutions and verify the hash
    matches what's curried into the singleton's inner puzzle."""

    pending_ops_hash_hex: Optional[str]
    """0x-prefixed sha256-tree hash of the pending-ops list (each
    entry is ``(admin_idx, op_kind, target_hash, activates_at)``).
    Equals ``EMPTY_LIST_HASH`` when no key-rotation ops are pending.
    """

    authority_version: int
    """Monotonic uint64. Replay protection across all spend tags
    (including OPERATIONAL — defence in depth so a compromised key
    spending the singleton is visible in the version history)."""

    state_hash_hex: Optional[str]
    """0x-prefixed sha256-tree hash of the state tuple
    ``(mips_root_hash, admins_hash, pending_ops_hash, authority_version)``.

    This is what the on-chain singleton emits via
    ``CREATE_PUZZLE_ANNOUNCEMENT`` after the protocol prefix
    ``0x50`` (PROTOCOL_PREFIX) and the spend-tag byte. Off-chain
    monitors recompute this from settings and verify it matches the
    on-chain announcement.

    ``None`` when no state values are configured (no singleton).
    """

    phase: str
    """Migration phase indicator. Mirrors v1's ``phase`` field for
    consumers that need to know whether the singleton is the gating
    source for admin auth. Possible values:

      * ``"1-not-deployed"`` — operator hasn't launched the v2 singleton.
      * ``"2-informational-only"`` — singleton is on-chain but admin
        auth still goes through v1 BLS allowlist (current state).
      * ``"3-migration-in-progress"`` — v1 has emitted MIGRATED_TO_V2;
        downstream consumers should switch to asserting against v2.
      * ``"4-gating-source"`` — admin desk authenticates via v2's
        MIPS quorum (EIP-712 / BLS / passkey leaves).
    """


def _resolve_phase(
    enabled: bool,
    v1_authority_version: int,
    v2_authority_version: int,
) -> str:
    """Heuristic phase resolver based on operator config.

    Real migration tracking would walk the singleton lineage and look
    for the v1 ``MIGRATED_TO_V2`` announcement; this is a settings-
    based approximation that serves as a public hint until the lineage
    walker lands.
    """
    if not enabled:
        return "1-not-deployed"
    # If v2 version is meaningfully higher than v1's (typical migration
    # bumps v2 to v1 + 1), treat it as informational. The
    # "3-migration-in-progress" and "4-gating-source" phases require
    # explicit operator opt-in via a separate setting (TBD).
    return "2-informational-only"


def build_admin_authority_v2_snapshot(
    settings: Settings,
) -> AdminAuthorityV2Snapshot:
    """Construct a deterministic v2 snapshot from live settings.

    Returns an ``enabled=False`` snapshot when the v2 launcher id is
    unset (the "v2 disabled" state); callers can use this as the
    "show /admin/auth/authority_v2 skeleton" signal without
    special-casing.

    Raises:
        ValueError: if any v2 hash setting is malformed (non-hex,
            wrong length). Surface as a 500 on the endpoint so
            operators see misconfiguration immediately.
    """
    launcher_id = settings.protocol_admin_authority_v2_launcher_id
    mips_root = _decode_hash_setting(
        settings.protocol_admin_authority_v2_mips_root_hash,
        "protocol_admin_authority_v2_mips_root_hash",
    )
    admins = _decode_hash_setting(
        settings.protocol_admin_authority_v2_admins_hash,
        "protocol_admin_authority_v2_admins_hash",
    )
    pending = _decode_hash_setting(
        settings.protocol_admin_authority_v2_pending_ops_hash,
        "protocol_admin_authority_v2_pending_ops_hash",
    )
    version = settings.protocol_admin_authority_v2_version

    enabled = bool(
        launcher_id or mips_root or admins or pending
    )

    state_hash_hex: Optional[str] = None
    if mips_root and admins:
        # Pending ops hash defaults to EMPTY_LIST_HASH when not set.
        # This matches what a freshly-launched singleton with no
        # pending ops carries.
        pending_for_hash = pending if pending else EMPTY_LIST_HASH
        state_hash = _compute_state_hash(
            mips_root_hash=mips_root,
            admins_hash=admins,
            pending_ops_hash=pending_for_hash,
            authority_version=version,
        )
        state_hash_hex = "0x" + state_hash.hex()

    return AdminAuthorityV2Snapshot(
        enabled=enabled,
        launcher_id_hex=launcher_id,
        mips_root_hash_hex=("0x" + mips_root.hex()) if mips_root else None,
        admins_hash_hex=("0x" + admins.hex()) if admins else None,
        pending_ops_hash_hex=("0x" + pending.hex()) if pending else None,
        authority_version=version,
        state_hash_hex=state_hash_hex,
        phase=_resolve_phase(
            enabled,
            v1_authority_version=settings.protocol_admin_authority_version,
            v2_authority_version=version,
        ),
    )


def _decode_hash_setting(value: Optional[str], field_name: str) -> Optional[bytes32]:
    """Decode a 0x-prefixed 32-byte hex string into bytes32, or None
    when the setting is unset / blank.

    Raises:
        ValueError: with the field name embedded if the value is
            non-hex or wrong length.
    """
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None
    # Tolerate both ``0x``-prefixed and bare hex.
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as e:
        raise ValueError(
            f"{field_name} is not valid hex: {e}"
        ) from e
    if len(decoded) != 32:
        raise ValueError(
            f"{field_name} must be 32 bytes (64 hex chars), got {len(decoded)} bytes"
        )
    return bytes32(decoded)


__all__ = [
    "AdminAuthorityV2Snapshot",
    "build_admin_authority_v2_snapshot",
]
