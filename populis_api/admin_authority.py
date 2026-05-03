"""Off-chain reader for the on-chain admin-authority singleton (A.2).

The admin-authority singleton (``admin_authority_inner.clsp``) is the
on-chain replacement for the off-chain admin allowlist trust roots:

  POPULIS_ADMIN_PUBKEY_ALLOWLIST  -> singleton ALLOWLIST (curried)
  POPULIS_ADMIN_JWT_SECRET        -> auditable rotation events on-chain

What this module does (Phase 2):
  * Computes the deterministic ``state_hash`` from the operator's
    settings, mirroring the on-chain ``state-hash`` defun exactly.
  * Surfaces the launcher coin id, the allowlist (as pubkey hashes for
    privacy), the quorum threshold, and the authority version on the
    new ``/admin/auth/authority`` endpoint so admins and external
    auditors can independently verify operator config matches on-chain
    state by walking the singleton lineage on coinset.org.

What this module does NOT do yet (Phase 2.5):
  * Replace ``admin_pubkey_allowlist_set()`` as the gating source for
    ``require_admin_jwt``.  Until that lands, the admin desk continues
    to enforce via env var; the on-chain singleton is informational
    only.  The hand-off lands when the API has a coinset.org indexer
    that walks the singleton lineage and parses curried state.

The Chialisp puzzle and its tests live in
``populis_protocol/populis_puzzles/admin_authority_inner.clsp`` and
``populis_protocol/tests/test_admin_authority.py``.  The off-chain
helpers (``compute_state_hash`` etc.) live in
``populis_protocol/populis_puzzles/admin_authority_driver.py``; we
re-export the state-hash helper here so the API doesn't need to know
about the populis_puzzles package layout.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from populis_puzzles.admin_authority_driver import (
    compute_state_hash as _compute_state_hash,
)

from .config import Settings


@dataclass(frozen=True)
class AdminAuthoritySnapshot:
    """Deterministic snapshot of the admin-authority singleton state.

    All fields are hex-encoded / JSON-friendly so the API can return
    this dataclass directly without leaking chia / chia_rs imports
    out to API consumers.

    The cross-repo contract is that ``state_hash_hex`` here MUST equal
    what the Chialisp ``state-hash`` defun produces; the test suite
    enforces this end-to-end (the API helper round-trips through the
    populis_puzzles driver, which is in turn pinned against the puzzle
    via ``test_state_hash_matches_on_chain``).
    """

    enabled: bool
    """``False`` when the operator has not configured the A.2 singleton.

    All other fields are still populated for diagnostic display when
    enabled is False (e.g., the pubkeys list might be set but no
    launcher id yet — useful for "ready to deploy" UI states)."""

    launcher_id_hex: Optional[str]
    """0x-prefixed launcher coin id of the on-chain singleton, or
    ``None`` when ``POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID`` is
    unset.  Frontends locate the singleton on coinset.org via this id.
    """

    allowlist_pubkey_hashes_hex: list[str]
    """SHA-256 hashes of each BLS pubkey, in declaration order.

    We expose hashes rather than the raw pubkeys because:
      * The full pubkeys are 48 bytes each — unnecessary bandwidth on
        every API hit.
      * Hashes are sufficient to verify "is THIS pubkey in the
        allowlist?" via simple comparison.
      * Reduces accidental leakage of the operator team's cold-key
        identifiers in client logs.

    Each entry is 0x-prefixed 32 bytes hex.  Order matches
    ``Settings.admin_authority_pubkeys_list()`` so signer indices line
    up with the on-chain singleton's ``ALLOWLIST``.
    """

    quorum_m: int
    """The M in m-of-n rotation quorum.  Mirrors
    ``Settings.protocol_admin_authority_quorum_m``."""

    authority_version: int
    """Monotonic version (replay-attack guard).  Mirrors
    ``Settings.protocol_admin_authority_version``."""

    state_hash_hex: Optional[str]
    """0x-prefixed sha256-tree hash of (allowlist, quorum_m, version).

    ``None`` when no pubkeys are configured (without an allowlist, the
    state is undefined and there's no meaningful hash to publish).
    Otherwise this is the canonical value every signer's AGG_SIG_ME
    commits to during a rotation spend, and what the singleton emits
    via ``CREATE_PUZZLE_ANNOUNCEMENT``.
    """


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_admin_authority_snapshot(settings: Settings) -> AdminAuthoritySnapshot:
    """Construct a deterministic snapshot from the live settings.

    Returns an ``enabled=False`` snapshot when neither the launcher id
    nor the pubkeys list are configured (the "A.2 disabled" state);
    callers can use this as the "show /admin/auth/authority skeleton"
    signal without special-casing.

    Raises:
        ValueError: if ``protocol_admin_authority_pubkeys`` is malformed
            (non-hex, wrong length).  Surface as a 500 on the endpoint
            so operators see misconfiguration immediately.
    """
    pubkeys = settings.admin_authority_pubkeys_list()  # may raise ValueError
    launcher_id = settings.protocol_admin_authority_launcher_id
    enabled = bool(pubkeys) or bool(launcher_id)

    pubkey_hashes_hex = [
        "0x" + _sha256(pk).hex() for pk in pubkeys
    ]

    state_hash_hex: Optional[str] = None
    if pubkeys:
        state_hash = _compute_state_hash(
            allowlist=pubkeys,
            quorum_m=settings.protocol_admin_authority_quorum_m,
            authority_version=settings.protocol_admin_authority_version,
        )
        state_hash_hex = "0x" + state_hash.hex()

    return AdminAuthoritySnapshot(
        enabled=enabled,
        launcher_id_hex=launcher_id,
        allowlist_pubkey_hashes_hex=pubkey_hashes_hex,
        quorum_m=settings.protocol_admin_authority_quorum_m,
        authority_version=settings.protocol_admin_authority_version,
        state_hash_hex=state_hash_hex,
    )


__all__ = [
    "AdminAuthoritySnapshot",
    "build_admin_authority_snapshot",
]
