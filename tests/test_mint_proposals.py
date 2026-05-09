"""Unit tests for ``populis_api.mint_proposals``.

In-memory SQLite (``:memory:``) is sufficient for the schema, state
machine, and uniqueness invariants — no chia_rs imports required.
Each test gets its own fresh store via the ``store`` fixture.
"""
from __future__ import annotations

import os

import pytest

from populis_api.mint_proposals import (
    ALL_STATES,
    ALLOWED_TRANSITIONS,
    DuplicateProperty,
    DuplicateProposalHash,
    InvalidTransition,
    MintProposalStore,
    ProposalNotFound,
    SCHEMA_VERSION,
)


# ── fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture
def store() -> MintProposalStore:
    s = MintProposalStore(":memory:")
    yield s
    s.close()


def _b32(byte_value: int) -> bytes:
    """Make a synthetic bytes32 with all bytes equal to ``byte_value``."""
    return bytes([byte_value]) * 32


def _new_args(*, suffix: int = 0, owner: str = "0xowner") -> dict:
    """Return a kwargs dict suitable for ``store.create``.

    DRAFT proposals carry only operator-supplied metadata.  All four
    computed puzzle hashes are populated atomically at the DRAFT →
    PROPOSED transition by ``set_published``.
    """
    return dict(
        owner_pubkey=owner,
        par_value=1_000_000_000 + suffix,
        asset_class="RWA-RE-RES",
        property_id=f"US-TX-Travis-{suffix:04d}",
        jurisdiction="US-TX-Travis",
        royalty_puzhash=_b32(0xAA),
        royalty_bps=200,
        quorum_required=500_000,
    )


def _publish_args(*, suffix: int = 0) -> dict:
    """Return a kwargs dict suitable for ``store.set_published`` after id."""
    return dict(
        smart_deed_inner_puzhash=_b32(0xB0 + (suffix & 0x0F)),
        eve_inner_puzhash=_b32(0xC0 + (suffix & 0x0F)),
        deed_full_puzhash=_b32(0xD0 + (suffix & 0x0F)),
        proposal_hash=_b32(0xE0 + (suffix & 0x0F)),
        proposal_tracker_coin_id=_b32(0x11),
        pgt_lock_coin_id=_b32(0x22),
        published_bundle_id="bundle",
        deadline=2_000_000_000,
    )


# ── schema + opens ───────────────────────────────────────────────────────────
class TestSchemaAndOpen:
    def test_schema_version_matches_constant(self, store):
        assert store.schema_version() == SCHEMA_VERSION

    def test_open_creates_tables(self, store):
        cur = store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row["name"] for row in cur}
        assert "mint_proposals" in tables
        assert "property_metadata" in tables

    def test_close_is_idempotent(self):
        s = MintProposalStore(":memory:")
        s.close()
        s.close()  # must not raise

    def test_context_manager(self, tmp_path):
        path = tmp_path / "ctx.db"
        with MintProposalStore(path) as s:
            assert s.count() == 0
        # File must exist + be a non-empty SQLite db.
        assert path.exists()
        assert path.stat().st_size > 0

    def test_count_states_constant(self):
        assert set(ALL_STATES) == {
            "DRAFT", "PROPOSED", "VOTING", "PASSED",
            "FAILED", "EXECUTED", "MINTED", "CANCELED",
        }


# ── create + roundtrip ───────────────────────────────────────────────────────
class TestCreate:
    def test_create_returns_draft(self, store):
        rec = store.create(**_new_args(suffix=1))
        assert rec.state == "DRAFT"
        assert rec.id.startswith("mp_")
        assert rec.vote_tally == 0
        assert rec.deadline is None
        assert rec.published_at is None
        assert rec.minted_at is None
        assert rec.deed_launcher_id is None

    def test_get_returns_inserted_record(self, store):
        rec = store.create(**_new_args(suffix=2))
        got = store.get(rec.id)
        assert got == rec

    def test_get_unknown_returns_none(self, store):
        assert store.get("mp_nonexistent") is None

    def test_count_increments(self, store):
        assert store.count() == 0
        store.create(**_new_args(suffix=3))
        assert store.count() == 1
        store.create(**_new_args(suffix=4))
        assert store.count() == 2

    def test_get_by_property_id_returns_active(self, store):
        rec = store.create(**_new_args(suffix=5))
        got = store.get_by_property_id(rec.property_id)
        assert got is not None
        assert got.id == rec.id

    def test_create_persists_off_chain_metadata(self, store):
        meta = {"description": "lakefront", "square_footage": 2400}
        args = _new_args(suffix=6)
        args["off_chain_metadata"] = meta
        rec = store.create(**args)
        assert rec.off_chain_metadata == meta
        # Re-fetched record carries the same metadata after JSON round-trip.
        assert store.get(rec.id).off_chain_metadata == meta


# ── validation errors ───────────────────────────────────────────────────────
class TestCreateValidation:
    def test_non_bytes32_royalty_puzhash_rejected(self, store):
        args = _new_args(suffix=10)
        args["royalty_puzhash"] = b"\x00" * 31  # one byte short
        with pytest.raises(ValueError, match="bytes32"):
            store.create(**args)

    def test_non_positive_par_value_rejected(self, store):
        args = _new_args(suffix=11)
        args["par_value"] = 0
        with pytest.raises(ValueError, match="par_value"):
            store.create(**args)

    @pytest.mark.parametrize("bps", [-1, 10_001, 100_000])
    def test_royalty_bps_out_of_range_rejected(self, store, bps):
        args = _new_args(suffix=12)
        args["royalty_bps"] = bps
        with pytest.raises(ValueError, match="royalty_bps"):
            store.create(**args)

    def test_zero_quorum_rejected(self, store):
        args = _new_args(suffix=13)
        args["quorum_required"] = 0
        with pytest.raises(ValueError, match="quorum_required"):
            store.create(**args)


# ── uniqueness ───────────────────────────────────────────────────────────────
class TestUniqueness:
    def test_duplicate_active_property_rejected(self, store):
        store.create(**_new_args(suffix=20))
        # Same property_id → blocked because the first proposal is
        # still in DRAFT (active).
        with pytest.raises(DuplicateProperty):
            store.create(**_new_args(suffix=20))

    def test_property_re_attempt_after_cancel(self, store):
        rec = store.create(**_new_args(suffix=21))
        store.cancel(rec.id)
        # Same property_id is OK now because the first proposal is
        # CANCELED (terminal/excluded by the partial index).
        rec2 = store.create(**_new_args(suffix=21))
        assert rec2.state == "DRAFT"
        assert rec2.id != rec.id

    def test_property_re_attempt_after_minted_rejected(self, store):
        rec = store.create(**_new_args(suffix=29))
        rec = store.set_published(rec.id, **_publish_args(suffix=29))
        rec = store.set_voting(rec.id)
        rec = store.set_passed(rec.id)
        rec = store.set_executed(rec.id, executed_bundle_id="bundle-executed")
        rec = store.set_minted(rec.id, deed_launcher_id=_b32(0x29))
        assert rec.state == "MINTED"
        assert store.get_by_property_id(" us-tx-travis-0029 ").id == rec.id

        with pytest.raises(DuplicateProperty):
            store.create(**_new_args(suffix=29))

    def test_duplicate_proposal_hash_rejected_at_publish(self, store):
        # The proposal_hash uniqueness check fires at set_published,
        # because that's when the field is first populated.  Two
        # DRAFTs with no proposal_hash coexist freely.
        a = store.create(**_new_args(suffix=22))
        b = store.create(**_new_args(suffix=23))
        store.set_published(a.id, **_publish_args(suffix=22))
        # Re-using the same proposal_hash on a different proposal must fail.
        with pytest.raises(DuplicateProposalHash):
            store.set_published(b.id, **_publish_args(suffix=22))

    # POP-CANON-014: property_id is canonicalised by strip().upper()
    # before the active-proposal uniqueness check.  Without the
    # canonicalisation, two byte-distinct property_ids that refer to
    # the same real-world property would create independent active
    # proposals, breaking the "no two deeds for the same property"
    # invariant.
    @pytest.mark.parametrize("variant", [
        "us-tx-travis-9001",      # lowercase
        "US-TX-TRAVIS-9001 ",     # trailing space
        " US-TX-TRAVIS-9001",     # leading space
        "  us-tx-travis-9001\t",  # mixed whitespace and case
    ])
    def test_property_id_canonicalised_blocks_lookalike_duplicates(
        self, store, variant,
    ):
        canonical = "US-TX-TRAVIS-9001"
        args = _new_args(suffix=24)
        args["property_id"] = canonical
        first = store.create(**args)
        assert first.property_id == canonical

        # Same property under any case/whitespace variant must be
        # blocked, not silently accepted as a "different" property.
        args2 = _new_args(suffix=25)  # different suffix → different par_value etc.
        args2["property_id"] = variant
        with pytest.raises(DuplicateProperty):
            store.create(**args2)

    def test_property_id_canonicalised_on_create(self, store):
        # The stored row carries the canonical (upper, stripped) form,
        # not whatever the caller happened to pass in.
        args = _new_args(suffix=26)
        args["property_id"] = "  us-tx-travis-9100  "
        rec = store.create(**args)
        assert rec.property_id == "US-TX-TRAVIS-9100"

    def test_property_id_empty_after_strip_rejected(self, store):
        args = _new_args(suffix=27)
        args["property_id"] = "   "
        with pytest.raises(ValueError, match="non-empty"):
            store.create(**args)

    def test_get_by_property_id_canonicalises_lookup(self, store):
        # Callers can pass any case/whitespace variant; the lookup
        # finds the active proposal on the canonical form.
        rec = store.create(**{
            **_new_args(suffix=28),
            "property_id": "US-TX-TRAVIS-9200",
        })
        assert store.get_by_property_id("us-tx-travis-9200").id == rec.id
        assert store.get_by_property_id("  US-TX-TRAVIS-9200  ").id == rec.id


# ── state machine ────────────────────────────────────────────────────────────
class TestStateMachine:
    def test_happy_path_full_lifecycle(self, store):
        rec = store.create(**_new_args(suffix=30))
        # DRAFT — all four computed hashes are still None.
        assert rec.smart_deed_inner_puzhash is None
        assert rec.eve_inner_puzhash is None
        assert rec.deed_full_puzhash is None
        assert rec.proposal_hash is None

        rec = store.set_published(rec.id, **_publish_args(suffix=30))
        assert rec.state == "PROPOSED"
        # set_published populated all launcher-id-dependent commitments.
        assert rec.smart_deed_inner_puzhash == _b32(0xB0 + (30 & 0x0F))
        assert rec.eve_inner_puzhash == _b32(0xC0 + (30 & 0x0F))
        assert rec.deed_full_puzhash == _b32(0xD0 + (30 & 0x0F))
        assert rec.proposal_hash == _b32(0xE0 + (30 & 0x0F))
        assert rec.proposal_tracker_coin_id == _b32(0x11)
        assert rec.pgt_lock_coin_id == _b32(0x22)
        assert rec.published_bundle_id == "bundle"
        assert rec.deadline == 2_000_000_000
        assert rec.published_at is not None

        rec = store.set_voting(rec.id)
        assert rec.state == "VOTING"

        rec = store.set_passed(rec.id)
        assert rec.state == "PASSED"

        rec = store.set_executed(rec.id, executed_bundle_id="bundle-executed")
        assert rec.state == "EXECUTED"
        assert rec.executed_bundle_id == "bundle-executed"
        assert rec.executed_at is not None

        rec = store.set_minted(rec.id, deed_launcher_id=_b32(0x33))
        assert rec.state == "MINTED"
        assert rec.deed_launcher_id == _b32(0x33)
        assert rec.minted_at is not None

    def test_skipping_states_rejected(self, store):
        rec = store.create(**_new_args(suffix=31))
        # DRAFT → VOTING is illegal (must go through PROPOSED).
        with pytest.raises(InvalidTransition):
            store.set_voting(rec.id)
        # DRAFT → EXECUTED is illegal.
        with pytest.raises(InvalidTransition):
            store.set_executed(rec.id, executed_bundle_id="x")

    def test_backwards_transition_rejected(self, store):
        rec = store.create(**_new_args(suffix=32))
        rec = store.set_published(rec.id, **_publish_args(suffix=32))
        # PROPOSED → DRAFT not in ALLOWED_TRANSITIONS.
        # Use cancel() since cancel is DRAFT-only.
        with pytest.raises(InvalidTransition):
            store.cancel(rec.id)

    def test_terminal_states_have_no_further_transitions(self, store):
        for terminal in ("FAILED", "MINTED", "CANCELED"):
            assert ALLOWED_TRANSITIONS[terminal] == set(), (
                f"{terminal} must be terminal in ALLOWED_TRANSITIONS"
            )

    def test_failed_blocks_further_transitions(self, store):
        rec = store.create(**_new_args(suffix=33))
        rec = store.set_published(rec.id, **_publish_args(suffix=33))
        rec = store.set_failed(rec.id)
        assert rec.state == "FAILED"
        with pytest.raises(InvalidTransition):
            store.set_executed(rec.id, executed_bundle_id="x")
        with pytest.raises(InvalidTransition):
            store.set_passed(rec.id)

    def test_set_failed_allowed_from_proposed_or_voting(self, store):
        # PROPOSED → FAILED
        a = store.create(**_new_args(suffix=40))
        a = store.set_published(a.id, **_publish_args(suffix=40))
        a = store.set_failed(a.id)
        assert a.state == "FAILED"

        # VOTING → FAILED
        b = store.create(**_new_args(suffix=41))
        b = store.set_published(b.id, **_publish_args(suffix=41))
        b = store.set_voting(b.id)
        b = store.set_failed(b.id)
        assert b.state == "FAILED"

    def test_set_failed_rejected_from_draft(self, store):
        rec = store.create(**_new_args(suffix=42))
        with pytest.raises(InvalidTransition):
            store.set_failed(rec.id)

    def test_cancel_only_from_draft(self, store):
        rec = store.create(**_new_args(suffix=43))
        rec = store.set_published(rec.id, **_publish_args(suffix=43))
        with pytest.raises(InvalidTransition):
            store.cancel(rec.id)

    def test_transitions_on_unknown_id_raise(self, store):
        with pytest.raises(ProposalNotFound):
            store.cancel("mp_unknown")
        with pytest.raises(ProposalNotFound):
            store.set_published("mp_unknown", **_publish_args(suffix=99))


# ── vote tally ──────────────────────────────────────────────────────────────
class TestVoteTally:
    def test_tally_updates_in_proposed(self, store):
        rec = store.create(**_new_args(suffix=50))
        rec = store.set_published(rec.id, **_publish_args(suffix=50))
        rec = store.update_vote_tally(rec.id, vote_tally=10_000)
        assert rec.vote_tally == 10_000
        rec = store.update_vote_tally(rec.id, vote_tally=20_000)
        assert rec.vote_tally == 20_000

    def test_tally_must_monotonically_increase(self, store):
        rec = store.create(**_new_args(suffix=51))
        rec = store.set_published(rec.id, **_publish_args(suffix=51))
        rec = store.update_vote_tally(rec.id, vote_tally=10_000)
        with pytest.raises(InvalidTransition, match="monotonically"):
            store.update_vote_tally(rec.id, vote_tally=9_000)

    def test_tally_negative_rejected(self, store):
        rec = store.create(**_new_args(suffix=52))
        rec = store.set_published(rec.id, **_publish_args(suffix=52))
        with pytest.raises(ValueError):
            store.update_vote_tally(rec.id, vote_tally=-1)

    def test_tally_in_draft_rejected(self, store):
        rec = store.create(**_new_args(suffix=53))
        with pytest.raises(InvalidTransition, match="PROPOSED/VOTING"):
            store.update_vote_tally(rec.id, vote_tally=10)

    def test_tally_in_passed_rejected(self, store):
        rec = store.create(**_new_args(suffix=54))
        rec = store.set_published(rec.id, **_publish_args(suffix=54))
        rec = store.set_voting(rec.id)
        rec = store.set_passed(rec.id)
        with pytest.raises(InvalidTransition):
            store.update_vote_tally(rec.id, vote_tally=99_999_999)


# ── list / filter ────────────────────────────────────────────────────────────
class TestList:
    def test_list_empty(self, store):
        assert store.list() == []

    def test_list_orders_newest_first(self, store):
        a = store.create(**_new_args(suffix=60))
        b = store.create(**_new_args(suffix=61))
        c = store.create(**_new_args(suffix=62))
        rows = store.list()
        # ORDER BY created_at DESC, id DESC — same-second creations
        # tie-break by id (random suffix), so we just check the set.
        assert {r.id for r in rows} == {a.id, b.id, c.id}

    def test_list_filter_by_state(self, store):
        draft = store.create(**_new_args(suffix=70, owner="0xa"))
        published = store.create(**_new_args(suffix=71, owner="0xb"))
        store.set_published(published.id, **_publish_args(suffix=71))
        drafts = store.list(states=["DRAFT"])
        assert {r.id for r in drafts} == {draft.id}
        proposed = store.list(states=["PROPOSED"])
        assert {r.id for r in proposed} == {published.id}

    def test_list_filter_by_owner(self, store):
        a1 = store.create(**_new_args(suffix=80, owner="0xalice"))
        a2 = store.create(**_new_args(suffix=81, owner="0xalice"))
        store.create(**_new_args(suffix=82, owner="0xbob"))
        alice = store.list(owner_pubkey="0xalice")
        assert {r.id for r in alice} == {a1.id, a2.id}

    def test_list_limit_offset(self, store):
        ids = []
        for i in range(5):
            r = store.create(**_new_args(suffix=90 + i))
            ids.append(r.id)
        first_two = store.list(limit=2)
        assert len(first_two) == 2
        next_two = store.list(limit=2, offset=2)
        assert len(next_two) == 2
        assert {r.id for r in first_two}.isdisjoint({r.id for r in next_two})

    def test_list_limit_validation(self, store):
        with pytest.raises(ValueError):
            store.list(limit=0)
        with pytest.raises(ValueError):
            store.list(limit=10_000)

    def test_count_by_state(self, store):
        store.create(**_new_args(suffix=100))
        published = store.create(**_new_args(suffix=101))
        store.set_published(published.id, **_publish_args(suffix=101))
        assert store.count() == 2
        assert store.count(state="DRAFT") == 1
        assert store.count(state="PROPOSED") == 1
        assert store.count(state="MINTED") == 0


# ── property metadata ────────────────────────────────────────────────────────
class TestPropertyMetadata:
    def test_set_and_get(self, store):
        launcher = _b32(0x55)
        payload = {"description": "Sunny lake home", "square_footage": 2400}
        store.set_property_metadata(launcher, payload)
        assert store.get_property_metadata(launcher) == payload

    def test_overwrite_replaces(self, store):
        launcher = _b32(0x66)
        store.set_property_metadata(launcher, {"a": 1})
        store.set_property_metadata(launcher, {"b": 2})
        assert store.get_property_metadata(launcher) == {"b": 2}

    def test_unknown_returns_none(self, store):
        assert store.get_property_metadata(_b32(0x77)) is None

    def test_non_bytes32_launcher_rejected(self, store):
        with pytest.raises(ValueError, match="bytes32"):
            store.set_property_metadata(b"\x00" * 31, {"x": 1})


# ── public dict shape ────────────────────────────────────────────────────────
class TestPublicDict:
    def test_to_public_dict_shape(self, store):
        rec = store.create(**_new_args(suffix=200))
        d = rec.to_public_dict()

        # Top-level keys
        assert d["id"] == rec.id
        assert d["state"] == "DRAFT"
        assert d["par_value"] == rec.par_value
        # Royalty puzhash is hex-encoded with 0x prefix
        assert d["royalty_puzhash"].startswith("0x")
        assert len(d["royalty_puzhash"]) == 2 + 64

        # Computed sub-dict — at DRAFT, all four hashes are None.
        # They become populated at the DRAFT → PROPOSED transition
        # because they all depend on the launcher coin id (via the
        # SINGLETON_STRUCT curried into smart_deed_inner).
        c = d["computed"]
        assert c["smart_deed_inner_puzhash"] is None
        assert c["eve_inner_puzhash"] is None
        assert c["deed_full_puzhash"] is None
        assert c["proposal_hash"] is None

        # On-chain sub-dict starts entirely null in DRAFT
        assert d["on_chain"] == {
            "proposal_tracker_coin_id": None,
            "pgt_lock_coin_id": None,
            "deed_launcher_id": None,
            "published_bundle_id": None,
            "executed_bundle_id": None,
        }

        # Timestamps sub-dict
        ts = d["timestamps"]
        assert ts["created_at"] == rec.created_at
        assert ts["published_at"] is None
        assert ts["executed_at"] is None
        assert ts["minted_at"] is None

    def test_to_public_dict_after_publish_includes_chain(self, store):
        rec = store.create(**_new_args(suffix=201))
        # In DRAFT all four computed commitments are null.
        d_draft = rec.to_public_dict()
        for k in ("smart_deed_inner_puzhash", "eve_inner_puzhash",
                  "deed_full_puzhash", "proposal_hash"):
            assert d_draft["computed"][k] is None

        rec = store.set_published(rec.id, **_publish_args(suffix=201))
        d = rec.to_public_dict()
        assert d["state"] == "PROPOSED"
        for k in ("smart_deed_inner_puzhash", "eve_inner_puzhash",
                  "deed_full_puzhash", "proposal_hash"):
            assert d["computed"][k].startswith("0x")
            assert len(d["computed"][k]) == 2 + 64
        assert d["on_chain"]["proposal_tracker_coin_id"].endswith("11" * 32)
        assert d["on_chain"]["pgt_lock_coin_id"].endswith("22" * 32)
        assert d["on_chain"]["published_bundle_id"] == "bundle"
        assert d["timestamps"]["published_at"] is not None


# ── persistence across reopens (file-backed) ─────────────────────────────────
class TestPersistence:
    def test_records_survive_reopen(self, tmp_path):
        path = tmp_path / "persist.db"
        s1 = MintProposalStore(path)
        rec = s1.create(**_new_args(suffix=300))
        s1.close()

        s2 = MintProposalStore(path)
        try:
            got = s2.get(rec.id)
            assert got is not None
            assert got.id == rec.id
            assert got.state == "DRAFT"
        finally:
            s2.close()

    def test_wal_files_present_after_open(self, tmp_path):
        path = tmp_path / "wal.db"
        s = MintProposalStore(path)
        try:
            # WAL pragma materializes -wal/-shm sidecars after the first
            # transaction (the migration counts).
            assert path.exists()
            wal = path.with_suffix(".db-wal")
            shm = path.with_suffix(".db-shm")
            assert wal.exists() or shm.exists() or os.environ.get("CI"), (
                "expected WAL/SHM sidecar files to be present"
            )
        finally:
            s.close()
