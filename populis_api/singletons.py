"""Off-chain reader for the A.1 + A.4 singletons (mint proposal +
property registry).

Whereas A.3 protocol-config and A.2 admin-authority publish a SINGLE
canonical ``state_hash`` per singleton (the curried state never has
parameters that vary per-spend), the A.1 mint-proposal singleton is
*per-proposal* — each proposal is its own launcher coin, with its own
state machine, and the protocol-level API only needs to expose the
canonical mod-hashes that let clients locate and identify these
singletons on-chain.

For A.4 we DO publish the launcher id, so off-chain indexers can find
the registry on coinset.org, walk its lineage, and rebuild the full
list of registered property ids by replaying the
``CREATE_PUZZLE_ANNOUNCEMENT`` payloads.

What this module exposes:
  * :class:`SingletonsSnapshot` — the protocol-level view of A.1 +
    A.4 (consumed by the ``/protocol`` endpoint).
  * :func:`build_singletons_snapshot` — the snapshot builder.

Phase 3.5 work (deferred) will add a coinset.org-driven indexer that:
  * Walks the property-registry singleton lineage and parses each
    spend's ``CREATE_PUZZLE_ANNOUNCEMENT`` body to rebuild the
    registered-property set.
  * Walks each mint-proposal singleton's lineage and decodes its
    state-machine transitions, replacing ``MintProposalStore`` as
    the gating source for ``/admin/mints/*`` endpoints.

Until then, the on-chain singletons are *informational* — they make
the off-chain ``MintProposalStore`` and ``POPULIS_ADMIN_PUBKEY_ALLOWLIST``-
backed registries auditable, but not yet *replaceable*.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from populis_puzzles.mint_proposal_driver import (
    mint_proposal_inner_mod_hash,
)
from populis_puzzles.property_registry_driver import (
    property_registry_inner_mod_hash,
)

from .config import Settings


# Pre-compute mod-hash hex strings at import time.  The driver
# helpers internally walk a chia ``Program`` (LazyNode) — reading them
# from a request worker thread panics with
# ``chia_protocol::lazy_node::LazyNode is unsendable``.  Materialising
# them here, on the import thread, makes ``build_singletons_snapshot``
# a pure dict construction.
_PROPERTY_REGISTRY_MOD_HASH_HEX: str = (
    "0x" + property_registry_inner_mod_hash().hex()
)
_MINT_PROPOSAL_MOD_HASH_HEX: str = (
    "0x" + mint_proposal_inner_mod_hash().hex()
)


@dataclass(frozen=True)
class SingletonsSnapshot:
    """Protocol-level view of the A.1 + A.4 singletons.

    All fields are hex-encoded for direct JSON inclusion on
    ``/protocol``.  The mod-hashes are derived from the compiled
    populis_puzzles bundle and are static across the deployment;
    they're cached at import time.

    The launcher id is operator-configurable and may be ``None`` if
    A.4 hasn't been deployed yet — in that case clients should treat
    the protocol as "registry-less" and fall back to the off-chain
    ``MintProposalStore`` view.
    """

    property_registry_launcher_id_hex: Optional[str]
    """0x-prefixed launcher coin id of the A.4 singleton, or ``None``
    when ``POPULIS_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID`` is unset."""

    property_registry_mod_hash_hex: str
    """0x-prefixed tree hash of the uncurried
    ``property_registry_inner.clsp`` mod.  Static across deploys;
    bumps only when the puzzle source is changed (which would be a
    breaking protocol upgrade requiring re-deployment of every
    downstream consumer)."""

    mint_proposal_mod_hash_hex: str
    """0x-prefixed tree hash of the uncurried
    ``mint_proposal_inner.clsp`` mod.  Same versioning semantics as
    ``property_registry_mod_hash_hex``."""


def build_singletons_snapshot(settings: Settings) -> SingletonsSnapshot:
    """Build the protocol-level A.1 + A.4 snapshot from settings + puzzles."""
    return SingletonsSnapshot(
        property_registry_launcher_id_hex=(
            settings.protocol_property_registry_launcher_id
        ),
        property_registry_mod_hash_hex=_PROPERTY_REGISTRY_MOD_HASH_HEX,
        mint_proposal_mod_hash_hex=_MINT_PROPOSAL_MOD_HASH_HEX,
    )


__all__ = [
    "SingletonsSnapshot",
    "build_singletons_snapshot",
]
