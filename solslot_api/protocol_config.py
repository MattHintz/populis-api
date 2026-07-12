"""Off-chain reader for the on-chain protocol-config singleton (A.3).

This module is the API's binding point against the
``protocol_config_inner.clsp`` singleton — the on-chain replacement for
the three trust-root environment variables (``SOLSLOT_POOL_LAUNCHER_ID``,
``SOLSLOT_GOVERNANCE_LAUNCHER_ID``, ``SOLSLOT_NETWORK``) the API
previously had to take on faith.

This module:
  * Computes the deterministic ``content_hash`` from the values currently
    in ``Settings`` (or the deployment manifest, transitively).  This is
    the SAME hash the on-chain singleton publishes via its
    ``CREATE_PUZZLE_ANNOUNCEMENT`` on every update spend.
  * Surfaces the launcher coin id when the operator has launched the
    singleton, so the frontend / external auditors can independently
    walk the singleton lineage on coinset.org and verify the operator's
    settings match the on-chain state.

The signed V2 artifact is the API coordinate source. Independent clients must
recompute this hash from the singleton lineage before authorizing spends.

The Chialisp puzzle and its tests live in
``solslot_protocol/solslot_puzzles/protocol_config_inner.clsp`` and
``solslot_protocol/tests/test_protocol_config.py``.  The Python helpers
``compute_content_hash`` / ``parse_inner_puzzle`` live in
``solslot_protocol/solslot_puzzles/protocol_config_driver.py``; we
re-export the content-hash helper here so the API doesn't need to know
about the solslot_puzzles package layout.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from chia_rs.sized_bytes import bytes32

from solslot_puzzles.protocol_config_driver import (
    NETWORK_ID_MAINNET,
    NETWORK_ID_TESTNET11,
)

from .clvm_hash import list_hash, positive_clvm_int
from .config import Settings


def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def _network_id(network: str) -> bytes32:
    """Map ``Settings.network`` to the bytes32 network discriminator
    used by the singleton's curried state.
    """
    if network == "mainnet":
        return NETWORK_ID_MAINNET
    if network == "testnet11":
        return NETWORK_ID_TESTNET11
    raise ValueError(
        f"unknown network {network!r}; supported: 'mainnet', 'testnet11'"
    )


@dataclass(frozen=True)
class ProtocolConfigSnapshot:
    """Deterministic snapshot of the four config fields the singleton commits to.

    Distinct from ``solslot_puzzles.protocol_config_driver.ProtocolConfigState``
    in that it carries hex-encoded fields ready to be embedded in JSON
    (the API surface) without any chia / chia_rs imports leaking out
    to API consumers.

    The ``content_hash_hex`` field is the canonical binding point:
    EIP-712 envelopes that bind to ``protocolConfigHash`` MUST use this
    exact value.  Frontends can independently verify it by computing
    ``sha256tree([pool, gov_tracker, network, version])`` against the
    singleton's puzzle reveal.
    """

    pool_launcher_id_hex: Optional[str]
    governance_launcher_id_hex: Optional[str]
    chia_network: str
    config_version: int
    content_hash_hex: Optional[str]
    """sha256tree of the four fields above, ``0x``-prefixed.

    ``None`` when the operator has not configured ``pool_launcher_id``
    or ``governance_launcher_id`` — without both, the singleton cannot
    be deployed and there's no meaningful content hash to publish.
    """

    protocol_config_launcher_id_hex: Optional[str]
    """``0x``-prefixed launcher coin id of the on-chain singleton, if the
    operator has launched one (i.e. ``SOLSLOT_PROTOCOL_CONFIG_LAUNCHER_ID``
    is set). ``None`` means the V2 ceremony is incomplete.
    """


def build_snapshot(
    settings: Settings,
    *,
    pool_launcher_id_hex: Optional[str],
    governance_launcher_id_hex: Optional[str],
) -> ProtocolConfigSnapshot:
    """Construct a deterministic snapshot from the live settings.

    Both ``pool_launcher_id_hex`` and ``governance_launcher_id_hex`` are
    threaded in by the caller so the API can use either the manifest
    values from the validated V2 deployment artifact.

    Returns a snapshot whose ``content_hash_hex`` is non-None iff both
    launcher ids are present.  Callers can therefore use
    ``snapshot.content_hash_hex is None`` as the "config not yet
    deployable" signal and skip the EIP-712 binding entirely.
    """
    if not pool_launcher_id_hex or not governance_launcher_id_hex:
        return ProtocolConfigSnapshot(
            pool_launcher_id_hex=pool_launcher_id_hex,
            governance_launcher_id_hex=governance_launcher_id_hex,
            chia_network=settings.network,
            config_version=settings.protocol_config_version,
            content_hash_hex=None,
            protocol_config_launcher_id_hex=settings.protocol_config_launcher_id,
        )

    pool = bytes32.fromhex(_strip0x(pool_launcher_id_hex))
    gov = bytes32.fromhex(_strip0x(governance_launcher_id_hex))
    network = _network_id(settings.network)
    version = settings.protocol_config_version

    content_hash = list_hash(
        (bytes(pool), bytes(gov), bytes(network), positive_clvm_int(version))
    )

    return ProtocolConfigSnapshot(
        pool_launcher_id_hex="0x" + pool.hex(),
        governance_launcher_id_hex="0x" + gov.hex(),
        chia_network=settings.network,
        config_version=version,
        content_hash_hex="0x" + content_hash.hex(),
        protocol_config_launcher_id_hex=settings.protocol_config_launcher_id,
    )


__all__ = [
    "ProtocolConfigSnapshot",
    "build_snapshot",
]
