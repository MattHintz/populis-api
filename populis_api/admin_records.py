"""On-chain-verified admin records loader (Phase 2.5).

The Populis admin desk's authority is held by an on-chain
``admin_authority_v2`` singleton whose state commits to an
``admins_hash`` (sha256tree of the admin records list).  However, the
chain stores ONLY hashes — to recover the actual EVM addresses needed
for EIP-712 sig recovery comparison, the API needs the off-chain
"expanded form" of the admin records.

This module loads + validates that expanded form from a JSON file and
computes its ``admins_hash`` so the operator can independently verify
the records bind to the same singleton state visible on chain.

**Trust model:**

* The on-chain ``admins_hash`` is the trust root.  An attacker who
  modifies the JSON file MUST also modify the chain to match — and
  rotating the on-chain singleton requires a quorum of admin
  signatures.
* The JSON file is convenience storage; its contents MUST hash to
  the on-chain ``admins_hash`` or the API refuses to boot
  (``verify_against_admins_hash``).
* When ``POPULIS_ADMIN_RECORDS_PATH`` is set AND the JSON-derived
  ``admins_hash`` matches the operator-supplied
  ``POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH`` env (which
  itself reflects the on-chain singleton state), Phase 2.5b promotes
  this records list above ``POPULIS_ADMIN_PUBKEY_ALLOWLIST`` for
  gating ``/admin/*`` routes.

**JSON schema (v1):**

.. code-block:: json

    {
      "$schema": "https://populis.io/schemas/admin_records_v1.json",
      "version": 1,
      "launcher_id": "0x...",
      "admin_records": [
        {
          "admin_idx": 0,
          "m_within": 1,
          "leaves": [
            {
              "kind": "eip712_member",
              "leaf_hash": "0x...",
              "evm_address": "0x...",
              "secp256k1_pubkey": "0x...",
              "type_hash": "0x...",
              "prefix_and_domain_separator": "0x..."
            }
          ]
        }
      ]
    }

Phase 3+ will add ``kind: "bls_member"`` and ``kind: "passkey"`` leaf
types; the current loader rejects anything other than ``eip712_member``
to make the unsupported-leaf path loud.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from chia_rs.sized_bytes import bytes32

# Re-use the canonical hash function from populis_protocol so we
# never drift from the on-chain Chialisp definition.
from populis_puzzles.admin_authority_v2_driver import (
    AdminRecord as ProtocolAdminRecord,
    compute_admins_hash as _protocol_compute_admins_hash,
)


# ──────────────────────────────────────────────────────────────────────
# Schema dataclasses
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Eip712LeafSpec:
    """One Eip712Member leaf inside an admin record.

    The ``leaf_hash`` is the sha256tree of the Eip712Member puzzle
    curried with ``(prefix_and_domain_separator, type_hash,
    secp256k1_pubkey)``.  The protocol's MIPS m_of_n quorum sees only
    this hash; the off-chain metadata (EVM address, raw pubkey) lets
    the API map an EIP-712 signature back to a specific admin slot.
    """

    leaf_hash: bytes32
    """32-byte tree-hash of the curried Eip712Member puzzle.

    This is what the on-chain MIPS m_of_n curry sees.  We recompute it
    from the curry args during launch verification (Phase 2.5b-2);
    today the loader trusts the JSON value.
    """

    evm_address: str
    """0x-prefixed lowercase 20-byte EVM address.

    Used by ``require_admin_jwt`` to gate sign-ins: the JWT subject
    (recovered from the EIP-712 signature) must equal this for at
    least one admin's leaf.
    """

    secp256k1_pubkey: bytes
    """33-byte compressed secp256k1 public key.

    The ``Eip712Member`` puzzle is curried with this exact pubkey, so
    every spend that authenticates as this admin must sign the
    EIP-712 envelope under this key.  The off-chain stored pubkey
    must match what's curried into the leaf.
    """

    type_hash: bytes32
    """CHIP-0037 EIP-712 type hash.

    Currently always ``keccak256("ChiaCoinSpend(bytes32 coin_id,
    bytes32 delegated_puzzle_hash)")`` for the canonical CHIP-0037
    envelope, but kept per-leaf for forward-compat.
    """

    prefix_and_domain_separator: bytes
    """34-byte EIP-712 prefix + domain separator: ``0x1901 ||
    keccak256(domain_separator_components)``.

    Bound to the Chia network's genesis challenge, so it differs
    between mainnet and testnet11 admins.
    """


@dataclass(frozen=True)
class AdminRecordSpec:
    """One admin slot's expanded record.

    Maps 1:1 to ``populis_protocol.admin_authority_v2_driver.AdminRecord``
    with the additional metadata needed for off-chain EVM address
    resolution.
    """

    admin_idx: int
    """Admin slot index.  Stable for the lifetime of the singleton —
    this admin's slot can be empty (after a remove-quorum spend) but
    its index never changes."""

    m_within: int
    """Quorum threshold within this admin's leaves.

    For typical EIP-712-only admins this is 1 (any of their EIP-712
    keys can authenticate).  Multi-key admins (e.g. EIP-712 hot key
    + BLS recovery key) can use m_within > 1.
    """

    leaves: tuple[Eip712LeafSpec, ...]
    """Member leaves.  Currently only ``eip712_member`` kind is
    supported; loader rejects others with a clear error so unsupported
    paths fail loudly rather than silently dropping leaves."""


@dataclass(frozen=True)
class AdminRecordsConfig:
    """Operator-supplied admin records, validated against on-chain state.

    Loaded from ``POPULIS_ADMIN_RECORDS_PATH`` JSON file.  The
    ``admins_hash`` derived from these records MUST match the on-chain
    singleton's ``admins_hash``; ``verify_against_admins_hash``
    enforces this at boot.
    """

    version: int
    """Schema version.  Currently 1; bumped when the JSON shape
    changes incompatibly."""

    launcher_id: bytes32
    """Launcher coin id of the singleton these records bind to.

    Pinned in the JSON so an operator can't accidentally mix records
    from a different deployment / network.  Cross-checked at boot
    against ``POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID``.
    """

    admin_records: tuple[AdminRecordSpec, ...]
    """Ordered list of admin slots; order matches the on-chain MIPS
    m_of_n curry's admin index order, so reordering invalidates the
    admins_hash."""

    # ── Helpers ──────────────────────────────────────────────────────

    def to_protocol_records(self) -> list[ProtocolAdminRecord]:
        """Convert to the protocol's ``AdminRecord`` shape for hashing.

        Strips off the off-chain metadata (EVM address etc.); the
        protocol's hash function only sees ``(admin_idx, leaves,
        m_within)`` where leaves are leaf hashes only.
        """
        return [
            ProtocolAdminRecord(
                admin_idx=r.admin_idx,
                leaves=tuple(leaf.leaf_hash for leaf in r.leaves),
                m_within=r.m_within,
            )
            for r in self.admin_records
        ]

    def compute_admins_hash(self) -> bytes32:
        """Recompute ``admins_hash`` from the records.

        Delegates to the protocol's canonical hash function so we
        cannot drift from the on-chain Chialisp definition.
        """
        return _protocol_compute_admins_hash(self.to_protocol_records())

    def eip712_evm_address_set(self) -> set[str]:
        """Return the lowercase EVM-address allowlist derived from records.

        This is what gates ``/admin/*`` once Phase 2.5b-3 promotes
        on-chain records above the env var.  Membership: any leaf in
        any admin record contributes its EVM address.
        """
        return {
            leaf.evm_address.lower()
            for record in self.admin_records
            for leaf in record.leaves
        }


# ──────────────────────────────────────────────────────────────────────
# Loader
# ──────────────────────────────────────────────────────────────────────


class AdminRecordsLoadError(ValueError):
    """Raised when admin records JSON is malformed or unsupported."""


def load_admin_records_from_path(path: str | Path) -> AdminRecordsConfig:
    """Read + parse admin records JSON.

    Strictly validates the schema; surfaces clear error messages
    referencing the offending field path so operators can find typos
    without needing to grok the loader source.

    Does NOT verify against on-chain ``admins_hash`` — call
    :func:`verify_against_admins_hash` after loading.
    """
    p = Path(path)
    if not p.exists():
        raise AdminRecordsLoadError(
            f"admin records path {path!r} does not exist"
        )
    try:
        raw = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        raise AdminRecordsLoadError(
            f"admin records {path!r}: invalid JSON at line {e.lineno}: {e.msg}"
        ) from e

    if not isinstance(raw, dict):
        raise AdminRecordsLoadError(
            f"admin records {path!r}: top-level must be a JSON object"
        )

    version = raw.get("version")
    if version != 1:
        raise AdminRecordsLoadError(
            f"admin records {path!r}: unsupported schema version {version!r} "
            f"(supported: 1)"
        )

    launcher_id_hex = raw.get("launcher_id")
    if not isinstance(launcher_id_hex, str):
        raise AdminRecordsLoadError(
            f"admin records {path!r}: launcher_id must be a 0x-hex string"
        )
    launcher_id = _parse_hex32(launcher_id_hex, field_path="launcher_id")

    records_raw = raw.get("admin_records")
    if not isinstance(records_raw, list) or not records_raw:
        raise AdminRecordsLoadError(
            f"admin records {path!r}: admin_records must be a non-empty list"
        )

    records = tuple(
        _parse_admin_record(r, idx)
        for idx, r in enumerate(records_raw)
    )

    return AdminRecordsConfig(
        version=version,
        launcher_id=launcher_id,
        admin_records=records,
    )


def _parse_admin_record(raw: object, position: int) -> AdminRecordSpec:
    """Parse one admin_records[i] entry, surfacing field-path errors."""
    if not isinstance(raw, dict):
        raise AdminRecordsLoadError(
            f"admin_records[{position}] must be an object"
        )

    admin_idx = raw.get("admin_idx")
    if not isinstance(admin_idx, int) or admin_idx < 0:
        raise AdminRecordsLoadError(
            f"admin_records[{position}].admin_idx must be a non-negative integer"
        )

    m_within = raw.get("m_within")
    if not isinstance(m_within, int) or m_within < 1:
        raise AdminRecordsLoadError(
            f"admin_records[{position}].m_within must be a positive integer"
        )

    leaves_raw = raw.get("leaves")
    if not isinstance(leaves_raw, list) or not leaves_raw:
        raise AdminRecordsLoadError(
            f"admin_records[{position}].leaves must be a non-empty list"
        )
    if m_within > len(leaves_raw):
        raise AdminRecordsLoadError(
            f"admin_records[{position}].m_within ({m_within}) exceeds "
            f"leaf count ({len(leaves_raw)})"
        )

    leaves = tuple(
        _parse_leaf(leaf_raw, position, leaf_idx)
        for leaf_idx, leaf_raw in enumerate(leaves_raw)
    )

    return AdminRecordSpec(
        admin_idx=admin_idx,
        m_within=m_within,
        leaves=leaves,
    )


def _parse_leaf(raw: object, record_pos: int, leaf_pos: int) -> Eip712LeafSpec:
    """Parse one admin_records[i].leaves[j] entry.

    The ``leaf_hash`` field is optional: when omitted the loader
    computes it from the curry args via the protocol's canonical
    ``compute_eip712_member_leaf_hash``.  When supplied, the loader
    cross-checks the value matches what would be computed; mismatch
    raises (catches typos and trojan records).
    """
    base_path = f"admin_records[{record_pos}].leaves[{leaf_pos}]"
    if not isinstance(raw, dict):
        raise AdminRecordsLoadError(f"{base_path} must be an object")

    kind = raw.get("kind")
    if kind != "eip712_member":
        raise AdminRecordsLoadError(
            f"{base_path}.kind={kind!r} is not supported "
            f"(supported: 'eip712_member' — bls_member/passkey land in Phase 3+)"
        )

    type_hash = _parse_hex32(raw.get("type_hash"), f"{base_path}.type_hash")

    evm_address = raw.get("evm_address")
    if not isinstance(evm_address, str) or not _looks_like_evm_address(evm_address):
        raise AdminRecordsLoadError(
            f"{base_path}.evm_address must be a 0x-prefixed 20-byte hex string"
        )

    pubkey = _parse_hex(raw.get("secp256k1_pubkey"), f"{base_path}.secp256k1_pubkey")
    if len(pubkey) != 33:
        raise AdminRecordsLoadError(
            f"{base_path}.secp256k1_pubkey must be 33 bytes (compressed), "
            f"got {len(pubkey)}"
        )

    domain = _parse_hex(
        raw.get("prefix_and_domain_separator"),
        f"{base_path}.prefix_and_domain_separator",
    )
    if len(domain) != 34:
        raise AdminRecordsLoadError(
            f"{base_path}.prefix_and_domain_separator must be 34 bytes "
            f"(0x1901 || domain), got {len(domain)}"
        )
    if domain[:2] != b"\x19\x01":
        raise AdminRecordsLoadError(
            f"{base_path}.prefix_and_domain_separator must start with "
            f"0x1901 (EIP-712 prefix), got 0x{domain[:2].hex()}"
        )

    # Compute the canonical leaf hash from the curry args, then either
    # verify the JSON-supplied value matches OR use the computed value
    # if leaf_hash is omitted.  Importing lazily so the loader doesn't
    # eagerly load the Eip712Member puzzle for every test that touches
    # the schema.
    from populis_puzzles.eip712_helpers import compute_eip712_member_leaf_hash
    try:
        computed_leaf = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=pubkey,
            prefix_and_domain_separator=domain,
            type_hash=type_hash,
        )
    except ValueError as e:
        raise AdminRecordsLoadError(
            f"{base_path}: failed to compute leaf hash: {e}"
        ) from e

    raw_leaf_hash = raw.get("leaf_hash")
    if raw_leaf_hash is None:
        leaf_hash = computed_leaf
    else:
        leaf_hash = _parse_hex32(raw_leaf_hash, f"{base_path}.leaf_hash")
        if leaf_hash != computed_leaf:
            raise AdminRecordsLoadError(
                f"{base_path}.leaf_hash mismatch:\n"
                f"  JSON-supplied: 0x{leaf_hash.hex()}\n"
                f"  computed from curry args: 0x{computed_leaf.hex()}\n"
                f"\n"
                f"The leaf_hash field, when present, must match the "
                f"sha256tree of the Eip712Member puzzle curried with "
                f"(prefix_and_domain_separator, type_hash, secp256k1_pubkey).  "
                f"Either drop leaf_hash from the JSON (loader will compute "
                f"it) or fix the curry args."
            )

    return Eip712LeafSpec(
        leaf_hash=leaf_hash,
        evm_address=evm_address.lower(),
        secp256k1_pubkey=pubkey,
        type_hash=type_hash,
        prefix_and_domain_separator=domain,
    )


def _parse_hex(raw: object, field_path: str) -> bytes:
    """Parse a 0x-prefixed (or bare) hex string to bytes; raise with field path on error."""
    if not isinstance(raw, str):
        raise AdminRecordsLoadError(
            f"{field_path} must be a 0x-hex string"
        )
    s = raw[2:] if raw.startswith(("0x", "0X")) else raw
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise AdminRecordsLoadError(
            f"{field_path} is not valid hex: {e}"
        ) from e


def _parse_hex32(raw: object, field_path: str) -> bytes32:
    """Parse a 0x-prefixed 32-byte hex value; raise with field path on error."""
    b = _parse_hex(raw, field_path)
    if len(b) != 32:
        raise AdminRecordsLoadError(
            f"{field_path} must be 32 bytes, got {len(b)}"
        )
    return bytes32(b)


def _looks_like_evm_address(s: str) -> bool:
    """Cheap shape check: 0x + 40 hex chars."""
    if not s.startswith(("0x", "0X")):
        return False
    body = s[2:]
    if len(body) != 40:
        return False
    try:
        bytes.fromhex(body)
    except ValueError:
        return False
    return True


# ──────────────────────────────────────────────────────────────────────
# Verification
# ──────────────────────────────────────────────────────────────────────


class AdminRecordsDriftError(RuntimeError):
    """Raised when admin records JSON disagrees with on-chain state.

    Drift is a CRITICAL fault — it means either:
      1. The operator's JSON is stale (an on-chain rotation happened
         and the JSON wasn't updated), OR
      2. Someone tampered with the JSON to add an unauthorised admin.

    Either way, the API refuses to boot until resolved.
    """


def verify_against_admins_hash(
    config: AdminRecordsConfig,
    expected_admins_hash: bytes32,
) -> None:
    """Assert ``config``'s recomputed ``admins_hash`` matches expected.

    ``expected_admins_hash`` should be sourced from the on-chain
    singleton state (Phase 2.5b-2 will fetch it directly via
    coinset.org).  For now the operator supplies it via
    ``POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH``.

    Raises:
        AdminRecordsDriftError: with a clear message comparing the
            two hashes side-by-side.
    """
    actual = config.compute_admins_hash()
    if actual != expected_admins_hash:
        raise AdminRecordsDriftError(
            f"admin records drift detected:\n"
            f"  records JSON hashes to: 0x{actual.hex()}\n"
            f"  on-chain singleton has: 0x{expected_admins_hash.hex()}\n"
            f"\n"
            f"Either the JSON is stale (rotate happened on chain — "
            f"regenerate from the latest singleton state) or the JSON "
            f"was tampered with.  Refusing to boot until resolved."
        )


def verify_against_launcher_id(
    config: AdminRecordsConfig,
    expected_launcher_id_hex: Optional[str],
) -> None:
    """Assert ``config.launcher_id`` matches the operator-configured launcher.

    Catches the "JSON pasted from a different deployment" footgun.

    Raises:
        AdminRecordsDriftError: when the launcher ids disagree.
    """
    if expected_launcher_id_hex is None:
        # No env launcher id configured → JSON binds to whichever id
        # the operator wrote in the file.  Phase 2.5b-2 will require
        # both env + JSON to be set when this gating source is enabled.
        return
    expected = _parse_hex32(expected_launcher_id_hex, "launcher_id env var")
    if config.launcher_id != expected:
        raise AdminRecordsDriftError(
            f"admin records launcher id mismatch:\n"
            f"  records JSON binds to: 0x{config.launcher_id.hex()}\n"
            f"  env var POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID: "
            f"{expected_launcher_id_hex}\n"
            f"\n"
            f"The records were generated for a different singleton "
            f"deployment.  Use the records JSON that matches your "
            f"configured launcher id."
        )


__all__ = [
    "AdminRecordsConfig",
    "AdminRecordSpec",
    "Eip712LeafSpec",
    "AdminRecordsLoadError",
    "AdminRecordsDriftError",
    "load_admin_records_from_path",
    "verify_against_admins_hash",
    "verify_against_launcher_id",
    "get_admin_records_for_settings",
    "clear_admin_records_cache",
]


# ──────────────────────────────────────────────────────────────────────
# mtime-keyed cache (so per-request callers don't re-read the JSON)
# ──────────────────────────────────────────────────────────────────────
#
# An operator editing the JSON file sees the new state on the next
# request without restarting the API.  Drift is still caught at
# request time because the boot validator's hash check ran at startup
# OR (Phase 2.5b-2) the per-request validator re-fetches the chain.
#
# We deliberately use a tuple-keyed dict rather than ``functools.lru_cache``
# so tests can reset it via ``clear_admin_records_cache()`` without
# poking at private cache state.
_records_cache: dict[tuple[str, float], AdminRecordsConfig] = {}


def clear_admin_records_cache() -> None:
    """Drop the mtime-keyed records cache.  Tests call this in between
    cases that touch ``admin_records_path``."""
    _records_cache.clear()


def get_admin_records_for_settings(settings: object) -> Optional[AdminRecordsConfig]:
    """Resolve the admin records for a Settings instance, with caching.

    Returns ``None`` when ``admin_records_path`` is unset.  Otherwise
    loads + caches the records keyed by ``(path, mtime)`` so a file
    edit invalidates the entry on next access.

    Takes ``settings`` as ``object`` (rather than ``Settings``) to
    avoid a circular import — the ``Settings`` class is what calls
    *us*.  We only read ``settings.admin_records_path``.
    """
    path_str = getattr(settings, "admin_records_path", None)
    if not path_str:
        return None
    p = Path(path_str)
    try:
        mtime = p.stat().st_mtime
    except FileNotFoundError as e:
        raise AdminRecordsLoadError(
            f"admin records path {path_str!r} does not exist"
        ) from e

    key = (str(p.resolve()), mtime)
    cached = _records_cache.get(key)
    if cached is not None:
        return cached

    config = load_admin_records_from_path(p)
    _records_cache[key] = config
    return config
