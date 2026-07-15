"""Off-chain reader for the current Solslot admin-authority singleton.

The V2 singleton (``admin_authority_v2_inner.clsp``) uses CHIP-0043 MIPS
composition: each admin slot holds a
`OneOfN` of personal authentication methods (BLS, EIP-712, passkey, ...)
under a protocol-level `MofN` quorum.

This module:

  * Surfaces the launcher coin id, MIPS root hash, admins hash, pending
    ops hash, and authority version on a ``/admin/auth/authority_v2``
    endpoint so admins and external auditors can independently verify
    operator config matches on-chain state by walking the singleton
    lineage on coinset.org.
  * Computes the deterministic ``state_hash`` from settings, mirroring
    what the on-chain ``state-hash`` defun emits in
    ``CREATE_PUZZLE_ANNOUNCEMENT``. This is the cross-repo binding
    point between off-chain monitoring and on-chain singleton state.

  * Reports whether a hash-verified records file currently gates API
    authentication. No environment-only authority fallback exists.

The Chialisp puzzle and its driver live in
``solslot_protocol/solslot_puzzles/admin_authority_v2_inner.clsp`` and
``solslot_protocol/solslot_puzzles/admin_authority_v2_driver.py``. The
test suite in ``solslot_protocol/tests/test_admin_authority_v2.py``
enforces the cross-repo state-hash contract end-to-end.

"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v2_driver import (
    EMPTY_LIST_HASH,
    compute_state_hash as _compute_state_hash,
)

from .config import Settings
from .public_artifact import (
    PublicArtifactError,
    PublicArtifactMissing,
    load_signed_public_artifact,
)


@dataclass(frozen=True)
class AdminAuthorityV2Snapshot:
    """Deterministic snapshot of the v2 admin-authority singleton state.

    All fields are hex-encoded / JSON-friendly so the API can return
    this dataclass directly without leaking ``chia`` / ``chia_rs``
    imports out to API consumers.

    Cross-repo contract: ``state_hash_hex`` here MUST equal what the
    on-chain ``state-hash`` defun produces. The solslot_protocol test
    ``test_state_hash_via_dataclass_matches_off_chain_compute``
    enforces this end-to-end against the puzzle's actual Chialisp
    output, so changes to either side that drift will fail CI.
    """

    enabled: bool
    """``True`` only when the operator publishes a v2 launcher id.

    Hash-only config is not enough to claim an enabled/deployed
    singleton because auditors need a launcher id to locate and verify
    the on-chain state."""

    launcher_id_hex: Optional[str]
    """0x-prefixed launcher coin id of the on-chain v2 singleton, or
    ``None`` when ``SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID``
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
    ``0x53`` (PROTOCOL_PREFIX) and the spend-tag byte. Off-chain
    monitors recompute this from settings and verify it matches the
    on-chain announcement.

    ``None`` when no state values are configured (no singleton).
    """

    phase: str
    """Authority state: ``not-deployed``, ``incomplete``,
    ``chain-published-not-gating``, or ``gating-source``."""

    deployment_status: str
    """Operator configuration status.

    Values are ``"not-configured"``, ``"hash-config-only"``,
    ``"launcher-only"``, or ``"deployed-configured"``.  Hash-only
    settings are explicitly not chain-verifiable because auditors need
    a launcher id to locate the singleton.
    """

    chain_verifiable: bool
    """``True`` only when launcher id plus required state hashes are
    present."""


def _resolve_phase(enabled: bool, chain_verifiable: bool, gating: bool) -> str:
    """Return the honest release state of the only active authority."""
    if not enabled:
        return "not-deployed"
    if not chain_verifiable:
        return "incomplete"
    return "gating-source" if gating else "chain-published-not-gating"


def build_admin_authority_v2_snapshot(
    settings: Settings,
) -> AdminAuthorityV2Snapshot:
    """Construct a deterministic V2 snapshot from the signed artifact.

    The explicit test environment retains the old settings-driven fixture
    path so historical puzzle-hash tests remain isolated. Deployed runtimes
    never read mutable launcher/hash settings for this snapshot.

    Raises:
        ValueError: if any hash setting is malformed (non-hex,
            wrong length). Surface as a 500 on the endpoint so
            operators see misconfiguration immediately.
    """
    if settings.runtime_environment == "test":
        launcher_id = settings.effective_protocol_admin_authority_v2_launcher_id()
        mips_root = _decode_hash_setting(
            settings.effective_protocol_admin_authority_v2_mips_root_hash(),
            "protocol_admin_authority_v2_mips_root_hash",
        )
        admins = _decode_hash_setting(
            settings.effective_protocol_admin_authority_v2_admins_hash(),
            "protocol_admin_authority_v2_admins_hash",
        )
        pending = _decode_hash_setting(
            settings.protocol_admin_authority_v2_pending_ops_hash,
            "protocol_admin_authority_v2_pending_ops_hash",
        )
        version = settings.effective_protocol_admin_authority_v2_version()
        gating = bool(settings.effective_admin_records_path())
    else:
        try:
            artifact = load_signed_public_artifact(settings)
        except PublicArtifactMissing:
            artifact = None
        except PublicArtifactError as exc:
            raise ValueError(f"signed V2 public artifact is invalid: {exc}") from exc
        if artifact is None:
            launcher_id = None
            mips_root = None
            admins = None
            pending = None
            version = 1
            gating = False
        else:
            authority = artifact["adminAuthority"]
            launcher_id = str(artifact["launcherIds"]["adminAuthority"])
            mips_root = _decode_hash_setting(
                str(authority["mipsRootHash"]),
                "public_artifact.adminAuthority.mipsRootHash",
            )
            admins = _decode_hash_setting(
                str(authority["rosterHash"]),
                "public_artifact.adminAuthority.rosterHash",
            )
            pending = EMPTY_LIST_HASH
            version = int(artifact["stateVersions"]["adminAuthority"])
            gating = True

    enabled = bool(launcher_id)
    has_hash_config = bool(mips_root or admins or pending)
    chain_verifiable = bool(launcher_id and mips_root and admins)
    if chain_verifiable:
        deployment_status = "deployed-configured"
    elif launcher_id:
        deployment_status = "launcher-only"
    elif has_hash_config:
        deployment_status = "hash-config-only"
    else:
        deployment_status = "not-configured"

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
            chain_verifiable,
            gating,
        ),
        deployment_status=deployment_status,
        chain_verifiable=chain_verifiable,
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
