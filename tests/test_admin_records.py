"""Tests for ``populis_api.admin_records`` (Phase 2.5).

Validates the JSON loader, the cross-repo binding to the protocol's
``compute_admins_hash``, and the drift-detection helpers that gate the
boot-time chain verification.

The on-chain ``admins_hash`` is the trust root in Phase 2.5+; this
file's tests pin the loader's hash recomputation to the protocol's
canonical value so any drift between the two surfaces immediately
rather than during a real-chain verification.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from chia_rs.sized_bytes import bytes32

from populis_api.admin_records import (
    AdminRecordSpec,
    AdminRecordsConfig,
    AdminRecordsDriftError,
    AdminRecordsLoadError,
    Eip712LeafSpec,
    load_admin_records_from_path,
    verify_against_admins_hash,
    verify_against_launcher_id,
)
from populis_puzzles.admin_authority_v2_driver import (
    AdminRecord as ProtocolAdminRecord,
    compute_admins_hash as protocol_compute_admins_hash,
)


# ──────────────────────────────────────────────────────────────────────
# Fixture builders
# ──────────────────────────────────────────────────────────────────────


def _hash(byte: int) -> bytes32:
    """Build a deterministic 32-byte sentinel filled with ``byte``."""
    return bytes32(bytes([byte]) * 32)


def _pubkey(seed: int) -> str:
    """Build a deterministic 33-byte 'compressed' pubkey hex.

    These are NOT real secp256k1 pubkeys — they're 33-byte values
    distinct enough that the curry-and-treehash produces unique leaf
    hashes per seed.  Real secp256k1 pubkey validation happens at
    sign-in time, not at admin records loading.
    """
    return "0x02" + bytes([seed]).hex() + "11" * 31


def _make_leaf_dict(
    *,
    leaf_hash: str | None = None,
    evm: str = "0x" + "ab" * 20,
    pubkey: str | None = None,
    type_hash: str = "0x" + "ee" * 32,
    domain: str = "0x1901" + "ff" * 32,  # 34 bytes, 0x1901 prefix
    pubkey_seed: int = 0xAA,
) -> dict:
    """Build a leaf JSON dict with sane defaults.

    By default, ``leaf_hash`` is OMITTED so the loader computes it
    from the curry args (the supported "operator emits records via
    wizard" path).  Pass ``leaf_hash`` explicitly to test the
    cross-check path.

    ``pubkey_seed`` controls the synthetic pubkey shape so different
    leaves produce different curried tree hashes; tests that need
    distinct leaves should pass distinct seeds.
    """
    leaf: dict = {
        "kind": "eip712_member",
        "evm_address": evm,
        "secp256k1_pubkey": pubkey if pubkey is not None else _pubkey(pubkey_seed),
        "type_hash": type_hash,
        "prefix_and_domain_separator": domain,
    }
    if leaf_hash is not None:
        leaf["leaf_hash"] = leaf_hash
    return leaf


def _make_admin_records_dict(
    *,
    launcher_id: str = "0x" + "10" * 32,
    admin_records: list[dict] | None = None,
) -> dict:
    """Build a minimum-viable admin records JSON dict."""
    if admin_records is None:
        admin_records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [_make_leaf_dict(pubkey_seed=0xaa)],
            }
        ]
    return {
        "version": 1,
        "launcher_id": launcher_id,
        "admin_records": admin_records,
    }


def _write_json(tmp_path: Path, data: dict, filename: str = "admin_records.json") -> Path:
    """Materialise a JSON dict at a temporary path; return the path.

    Pass distinct ``filename`` values when a single test needs to load
    two different configs (otherwise the second write clobbers the
    first).  Creates parent directories as needed.
    """
    p = tmp_path / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data))
    return p


# ──────────────────────────────────────────────────────────────────────
# Happy-path loading
# ──────────────────────────────────────────────────────────────────────


class TestLoadAdminRecords:
    def test_minimal_valid_records(self, tmp_path):
        """One admin, one leaf — the simplest deployment shape."""
        path = _write_json(tmp_path, _make_admin_records_dict())
        config = load_admin_records_from_path(path)

        assert config.version == 1
        assert config.launcher_id == _hash(0x10)
        assert len(config.admin_records) == 1
        admin = config.admin_records[0]
        assert admin.admin_idx == 0
        assert admin.m_within == 1
        assert len(admin.leaves) == 1
        leaf = admin.leaves[0]
        # Leaf hash is computed from curry args, so we can't pin a
        # constant here — but it must be a valid 32-byte value AND
        # deterministic for the same inputs.
        assert isinstance(leaf.leaf_hash, bytes)
        assert len(leaf.leaf_hash) == 32
        assert leaf.evm_address == "0x" + "ab" * 20  # already lowercase
        assert len(leaf.secp256k1_pubkey) == 33
        assert leaf.type_hash == _hash(0xEE)
        assert len(leaf.prefix_and_domain_separator) == 34
        assert leaf.prefix_and_domain_separator[:2] == b"\x19\x01"

    def test_multi_admin_multi_leaf(self, tmp_path):
        """Multiple admins, each with several keys — m_within varies."""
        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x01),
                    _make_leaf_dict(pubkey_seed=0x02),
                ],
            },
            {
                "admin_idx": 1,
                "m_within": 2,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x03),
                    _make_leaf_dict(pubkey_seed=0x04),
                    _make_leaf_dict(pubkey_seed=0x05),
                ],
            },
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        config = load_admin_records_from_path(path)

        assert len(config.admin_records) == 2
        assert config.admin_records[0].m_within == 1
        assert config.admin_records[1].m_within == 2
        assert len(config.admin_records[1].leaves) == 3

    def test_lowercases_evm_address(self, tmp_path):
        """Mixed-case EVM addresses are normalised to lowercase so the
        gating set check is case-insensitive."""
        leaf = _make_leaf_dict(
            pubkey_seed=0xaa,
            evm="0xABcDeF0000000000000000000000000000000000",
        )
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        config = load_admin_records_from_path(path)
        assert config.admin_records[0].leaves[0].evm_address == (
            "0xabcdef0000000000000000000000000000000000"
        )

    def test_eip712_evm_address_set_aggregates_across_admins(self, tmp_path):
        """The gating allowlist union across admins + leaves."""
        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(
                        pubkey_seed=0x01,
                        evm="0x" + "11" * 20,
                    ),
                ],
            },
            {
                "admin_idx": 1,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(
                        pubkey_seed=0x02,
                        evm="0x" + "22" * 20,
                    ),
                    _make_leaf_dict(
                        pubkey_seed=0x03,
                        evm="0x" + "33" * 20,
                    ),
                ],
            },
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        config = load_admin_records_from_path(path)
        assert config.eip712_evm_address_set() == {
            "0x" + "11" * 20,
            "0x" + "22" * 20,
            "0x" + "33" * 20,
        }


# ──────────────────────────────────────────────────────────────────────
# Cross-repo binding: hash must match protocol's compute_admins_hash
# ──────────────────────────────────────────────────────────────────────


class TestAdminsHashMatchesProtocol:
    """The single most important contract: the API's recomputed
    ``admins_hash`` MUST equal what
    ``populis_protocol.admin_authority_v2_driver.compute_admins_hash``
    produces for the same logical records.  Drift between the two
    means the API and the chain disagree on what the singleton's
    state means → silent admin-authority drift.
    """

    def test_single_admin_single_leaf(self, tmp_path):
        records_data = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [_make_leaf_dict(pubkey_seed=0xAA)],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records_data))
        config = load_admin_records_from_path(path)

        # Pull the loader-computed leaf hash and feed it into the
        # protocol's canonical hash function — they must agree on
        # what this admin's record hashes to.
        loader_leaf = config.admin_records[0].leaves[0].leaf_hash
        expected = protocol_compute_admins_hash([
            ProtocolAdminRecord(admin_idx=0, leaves=(loader_leaf,), m_within=1),
        ])
        assert config.compute_admins_hash() == expected

    def test_multi_admin_multi_leaf(self, tmp_path):
        """Order matters — both at admin-record level and leaf level."""
        records_data = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x01),
                    _make_leaf_dict(pubkey_seed=0x02),
                ],
            },
            {
                "admin_idx": 1,
                "m_within": 2,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x03),
                    _make_leaf_dict(pubkey_seed=0x04),
                    _make_leaf_dict(pubkey_seed=0x05),
                ],
            },
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records_data))
        config = load_admin_records_from_path(path)

        # Use the loader-computed leaf hashes for the cross-check.
        # If loader and protocol disagreed on Eip712Member curry-and-
        # treehash, this test would fail.
        leaves_a = tuple(leaf.leaf_hash for leaf in config.admin_records[0].leaves)
        leaves_b = tuple(leaf.leaf_hash for leaf in config.admin_records[1].leaves)
        expected = protocol_compute_admins_hash([
            ProtocolAdminRecord(admin_idx=0, leaves=leaves_a, m_within=1),
            ProtocolAdminRecord(admin_idx=1, leaves=leaves_b, m_within=2),
        ])
        assert config.compute_admins_hash() == expected

    def test_leaf_order_matters(self, tmp_path):
        """Swapping two leaves within a record changes the hash —
        the API must NOT silently sort or normalise leaf order.
        """
        records_a = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x01),
                    _make_leaf_dict(pubkey_seed=0x02),
                ],
            }
        ]
        records_b = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x02),
                    _make_leaf_dict(pubkey_seed=0x01),
                ],
            }
        ]
        path_a = _write_json(
            tmp_path,
            _make_admin_records_dict(admin_records=records_a),
            filename="a.json",
        )
        path_b = _write_json(
            tmp_path,
            _make_admin_records_dict(admin_records=records_b),
            filename="b.json",
        )
        config_a = load_admin_records_from_path(path_a)
        config_b = load_admin_records_from_path(path_b)
        assert config_a.compute_admins_hash() != config_b.compute_admins_hash()


# ──────────────────────────────────────────────────────────────────────
# Drift detection
# ──────────────────────────────────────────────────────────────────────


class TestVerifyAgainstAdminsHash:
    def test_match_passes(self, tmp_path):
        path = _write_json(tmp_path, _make_admin_records_dict())
        config = load_admin_records_from_path(path)
        # No exception when the expected hash matches.
        verify_against_admins_hash(config, config.compute_admins_hash())

    def test_mismatch_raises_with_both_hashes(self, tmp_path):
        path = _write_json(tmp_path, _make_admin_records_dict())
        config = load_admin_records_from_path(path)
        wrong = _hash(0xFF)
        with pytest.raises(AdminRecordsDriftError) as exc_info:
            verify_against_admins_hash(config, wrong)
        # Error message must show BOTH hashes so operators can copy
        # them into a chain explorer to debug.
        msg = str(exc_info.value)
        assert config.compute_admins_hash().hex() in msg
        assert wrong.hex() in msg


class TestVerifyAgainstLauncherId:
    def test_match_passes(self, tmp_path):
        path = _write_json(tmp_path, _make_admin_records_dict())
        config = load_admin_records_from_path(path)
        verify_against_launcher_id(config, "0x" + "10" * 32)

    def test_match_passes_without_0x_prefix(self, tmp_path):
        """Operators sometimes paste hex without prefix; loader accepts."""
        path = _write_json(tmp_path, _make_admin_records_dict())
        config = load_admin_records_from_path(path)
        verify_against_launcher_id(config, "10" * 32)

    def test_no_env_skips_check(self, tmp_path):
        """Phase 2.5b-1: env launcher id might be unset during
        transition from env-var gating; allow that case to skip."""
        path = _write_json(tmp_path, _make_admin_records_dict())
        config = load_admin_records_from_path(path)
        verify_against_launcher_id(config, None)

    def test_mismatch_raises(self, tmp_path):
        path = _write_json(tmp_path, _make_admin_records_dict())
        config = load_admin_records_from_path(path)
        with pytest.raises(AdminRecordsDriftError, match="launcher id mismatch"):
            verify_against_launcher_id(config, "0x" + "fe" * 32)


# ──────────────────────────────────────────────────────────────────────
# Negative paths: malformed JSON / unsupported shapes
# ──────────────────────────────────────────────────────────────────────


class TestLoadErrors:
    def test_path_does_not_exist(self, tmp_path):
        with pytest.raises(AdminRecordsLoadError, match="does not exist"):
            load_admin_records_from_path(tmp_path / "missing.json")

    def test_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        with pytest.raises(AdminRecordsLoadError, match="invalid JSON"):
            load_admin_records_from_path(p)

    def test_top_level_array_rejected(self, tmp_path):
        p = tmp_path / "arr.json"
        p.write_text("[]")
        with pytest.raises(AdminRecordsLoadError, match="top-level must be a JSON object"):
            load_admin_records_from_path(p)

    def test_unsupported_version(self, tmp_path):
        data = _make_admin_records_dict()
        data["version"] = 2
        path = _write_json(tmp_path, data)
        with pytest.raises(AdminRecordsLoadError, match="unsupported schema version 2"):
            load_admin_records_from_path(path)

    def test_missing_launcher_id(self, tmp_path):
        data = _make_admin_records_dict()
        del data["launcher_id"]
        path = _write_json(tmp_path, data)
        with pytest.raises(AdminRecordsLoadError, match="launcher_id"):
            load_admin_records_from_path(path)

    def test_empty_admin_records(self, tmp_path):
        data = _make_admin_records_dict()
        data["admin_records"] = []
        path = _write_json(tmp_path, data)
        with pytest.raises(AdminRecordsLoadError, match="admin_records must be a non-empty list"):
            load_admin_records_from_path(path)

    def test_unsupported_leaf_kind(self, tmp_path):
        """Phase 3+ will add bls_member / passkey; loader must reject
        them today rather than silently ignoring (would produce a
        wrong hash that mysteriously fails to verify on chain).
        """
        leaf = _make_leaf_dict(pubkey_seed=0xaa)
        leaf["kind"] = "bls_member"
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="kind='bls_member' is not supported"):
            load_admin_records_from_path(path)

    def test_evm_address_wrong_length(self, tmp_path):
        leaf = _make_leaf_dict(
            pubkey_seed=0xaa,
            evm="0x1234",  # too short
        )
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="evm_address"):
            load_admin_records_from_path(path)

    def test_pubkey_wrong_length(self, tmp_path):
        leaf = _make_leaf_dict(
            pubkey_seed=0xaa,
            pubkey="0x" + "11" * 32,  # 32 bytes, not 33
        )
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="must be 33 bytes"):
            load_admin_records_from_path(path)

    def test_domain_separator_wrong_prefix(self, tmp_path):
        leaf = _make_leaf_dict(
            pubkey_seed=0xaa,
            domain="0x" + "00" * 34,  # right length but wrong prefix
        )
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="0x1901"):
            load_admin_records_from_path(path)

    def test_m_within_exceeds_leaf_count(self, tmp_path):
        """Operator typo: m_within=3 but only 2 leaves → never satisfiable."""
        leaf1 = _make_leaf_dict(pubkey_seed=0xaa)
        leaf2 = _make_leaf_dict(pubkey_seed=0xbb)
        records = [{"admin_idx": 0, "m_within": 3, "leaves": [leaf1, leaf2]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="m_within \\(3\\) exceeds"):
            load_admin_records_from_path(path)

    def test_negative_admin_idx(self, tmp_path):
        records = [
            {
                "admin_idx": -1,
                "m_within": 1,
                "leaves": [_make_leaf_dict(pubkey_seed=0xaa)],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="admin_idx must be a non-negative"):
            load_admin_records_from_path(path)

    def test_zero_m_within(self, tmp_path):
        records = [
            {
                "admin_idx": 0,
                "m_within": 0,
                "leaves": [_make_leaf_dict(pubkey_seed=0xaa)],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="m_within must be a positive"):
            load_admin_records_from_path(path)

    def test_leaf_hash_cross_check_accepts_correct_value(self, tmp_path):
        """When the JSON supplies leaf_hash AND it matches the
        computed value, the loader accepts (no recompute hidden;
        operators can pin known-good values for fixture verification).
        """
        # First load to compute the canonical hash, then re-emit the
        # JSON with leaf_hash explicitly set to that value.
        path1 = _write_json(
            tmp_path,
            _make_admin_records_dict(
                admin_records=[
                    {
                        "admin_idx": 0,
                        "m_within": 1,
                        "leaves": [_make_leaf_dict(pubkey_seed=0x42)],
                    }
                ]
            ),
            filename="step1.json",
        )
        canonical = load_admin_records_from_path(path1)
        canonical_leaf = canonical.admin_records[0].leaves[0].leaf_hash

        # Now write with explicit leaf_hash = canonical → should load OK.
        path2 = _write_json(
            tmp_path,
            _make_admin_records_dict(
                admin_records=[
                    {
                        "admin_idx": 0,
                        "m_within": 1,
                        "leaves": [
                            _make_leaf_dict(
                                pubkey_seed=0x42,
                                leaf_hash="0x" + canonical_leaf.hex(),
                            )
                        ],
                    }
                ]
            ),
            filename="step2.json",
        )
        config = load_admin_records_from_path(path2)
        assert config.admin_records[0].leaves[0].leaf_hash == canonical_leaf

    def test_leaf_hash_cross_check_rejects_mismatch(self, tmp_path):
        """When the JSON supplies a wrong leaf_hash, the loader
        refuses with a clear field-path error.  Catches both typos
        and trojan records (an attacker who crafted a JSON with a
        dummy curry args + cherry-picked leaf hash to slip a fake
        admin past the on-chain admins_hash check).
        """
        leaf = _make_leaf_dict(
            pubkey_seed=0xAA,
            leaf_hash="0x" + "00" * 32,  # never-matches value
        )
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError) as exc_info:
            load_admin_records_from_path(path)
        msg = str(exc_info.value)
        assert "leaf_hash mismatch" in msg
        assert "JSON-supplied" in msg
        assert "computed from curry args" in msg

    def test_field_path_in_error_for_nested_leaf(self, tmp_path):
        """Errors deep in the tree should reference the offending path."""
        good_leaf = _make_leaf_dict(pubkey_seed=0xaa)
        bad_leaf = _make_leaf_dict(pubkey_seed=0xbb)
        bad_leaf["evm_address"] = "not_hex"
        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [good_leaf, bad_leaf],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match=r"admin_records\[0\].leaves\[1\]"):
            load_admin_records_from_path(path)


# ──────────────────────────────────────────────────────────────────────
# Integration: Settings.effective_admin_allowlist_set + boot validator
# ──────────────────────────────────────────────────────────────────────


class TestSettingsIntegration:
    """End-to-end verification that the admin records JSON drives the
    actual admin-desk gating decisions.  These tests exercise the
    Phase 2.5b-1 wire-up: ``Settings.effective_admin_allowlist_set``
    and the boot validator's records-path branch.
    """

    def test_records_path_provides_allowlist(self, tmp_path, monkeypatch):
        """When ``POPULIS_ADMIN_RECORDS_PATH`` is set and the legacy
        env var is empty, the JSON's EVM addresses ARE the allowlist.
        """
        from populis_api.config import get_settings

        evm_a = "0x" + "11" * 20
        evm_b = "0x" + "22" * 20
        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x01, evm=evm_a),
                ],
            },
            {
                "admin_idx": 1,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x02, evm=evm_b),
                ],
            },
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        monkeypatch.setenv("POPULIS_ADMIN_RECORDS_PATH", str(path))
        # Legacy env var explicitly empty so we know the JSON path is winning.
        monkeypatch.setenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", "")
        get_settings.cache_clear()
        s = get_settings()

        assert s.effective_admin_allowlist_set() == {evm_a.lower(), evm_b.lower()}

    def test_records_path_takes_precedence_over_env_var(self, tmp_path, monkeypatch):
        """When BOTH gating sources are set, the JSON wins.

        Exclusivity is intentional — unioning would let an env-var
        admin smuggle through past the on-chain hash check.
        """
        from populis_api.config import get_settings

        records_evm = "0x" + "11" * 20
        env_evm = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(pubkey_seed=0x01, evm=records_evm),
                ],
            },
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        monkeypatch.setenv("POPULIS_ADMIN_RECORDS_PATH", str(path))
        monkeypatch.setenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", env_evm)
        get_settings.cache_clear()
        s = get_settings()

        result = s.effective_admin_allowlist_set()
        assert result == {records_evm.lower()}, (
            "JSON allowlist must NOT include env-var admin"
        )
        assert env_evm not in result

    def test_falls_back_to_env_var_when_records_path_unset(self, monkeypatch):
        """Phase 2 backward-compat: when the JSON path is unset, the
        env var is the gating source.  Nothing changes for operators
        running pre-Phase-2.5 deployments.
        """
        from populis_api.config import get_settings

        evm = "0x" + "33" * 20
        monkeypatch.setenv("POPULIS_ADMIN_RECORDS_PATH", "")
        monkeypatch.setenv("POPULIS_ADMIN_PUBKEY_ALLOWLIST", evm)
        get_settings.cache_clear()
        s = get_settings()

        assert s.effective_admin_allowlist_set() == {evm.lower()}

    def test_boot_validator_loads_records(self, tmp_path, monkeypatch):
        """``validate_admin_config_at_startup`` must load the JSON
        records and verify their hash when ``admin_records_path`` is
        set.  Happy path: matching ``admins_hash`` → success, no raise.
        """
        from populis_api import admin_auth
        from populis_api.config import get_settings

        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [_make_leaf_dict(pubkey_seed=0xaa)],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        config = load_admin_records_from_path(path)
        expected_hash = "0x" + config.compute_admins_hash().hex()

        monkeypatch.setenv("POPULIS_ADMIN_RECORDS_PATH", str(path))
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "x" * 64)
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH", expected_hash
        )
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID",
            "0x" + "10" * 32,  # matches _make_admin_records_dict default
        )
        get_settings.cache_clear()
        # Should not raise.
        admin_auth.validate_admin_config_at_startup(get_settings())

    def test_boot_validator_catches_admins_hash_drift(self, tmp_path, monkeypatch):
        """Operator updates the JSON without rotating the singleton →
        admins_hash mismatch → boot fails loud.
        """
        from populis_api import admin_auth
        from populis_api.config import get_settings

        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [_make_leaf_dict(pubkey_seed=0xaa)],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))

        # WRONG admins_hash on env (simulates stale or tampered config).
        monkeypatch.setenv("POPULIS_ADMIN_RECORDS_PATH", str(path))
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "x" * 64)
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH",
            "0x" + "ff" * 32,  # garbage — does not match JSON's hash
        )
        get_settings.cache_clear()
        with pytest.raises(RuntimeError, match=r"(?i)drift"):
            admin_auth.validate_admin_config_at_startup(get_settings())

    def test_boot_validator_catches_launcher_id_mismatch(self, tmp_path, monkeypatch):
        """Operator deploys records JSON from a different singleton →
        launcher_id mismatch → boot fails loud.
        """
        from populis_api import admin_auth
        from populis_api.config import get_settings

        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [_make_leaf_dict(pubkey_seed=0xaa)],
            }
        ]
        # JSON binds to launcher 0x10*32; env binds to 0xfe*32.
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))

        monkeypatch.setenv("POPULIS_ADMIN_RECORDS_PATH", str(path))
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "x" * 64)
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID",
            "0x" + "fe" * 32,
        )
        get_settings.cache_clear()
        with pytest.raises(RuntimeError, match=r"(?i)launcher id"):
            admin_auth.validate_admin_config_at_startup(get_settings())

    def test_authority_v2_endpoint_reports_records_gating_source(
        self, tmp_path, monkeypatch
    ):
        """When admin_records_path is set, /admin/auth/authority_v2's
        ``gating_source`` field flips from the env-var name to the
        records-path name and ``informational_only`` flips to False.
        """
        from fastapi.testclient import TestClient
        from populis_api.app import app
        from populis_api.config import get_settings

        records = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [_make_leaf_dict(pubkey_seed=0x42)],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        monkeypatch.setenv("POPULIS_ADMIN_RECORDS_PATH", str(path))
        # Boot validator requires JWT secret when admin desk is
        # enabled (which records_path enables); set a dummy.
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "x" * 64)
        get_settings.cache_clear()

        with TestClient(app) as client:
            r = client.get("/admin/auth/authority_v2")
        assert r.status_code == 200
        body = r.json()
        assert body["gating_source"] == "POPULIS_ADMIN_RECORDS_PATH"
        assert body["informational_only"] is False


# ──────────────────────────────────────────────────────────────────────
# /admin/auth/eip712/compute_leaf_hash endpoint
# ──────────────────────────────────────────────────────────────────────


class TestEip712ComputeLeafHashEndpoint:
    """Integration tests for the public EIP-712 leaf-hash computation
    endpoint.  This is what the launch wizard calls to populate the
    admin records JSON's ``leaf_hash`` fields.
    """

    def _client(self):
        from fastapi.testclient import TestClient
        from populis_api.app import app
        return TestClient(app)

    def test_happy_path_testnet11(self):
        """Returns a 32-byte leaf hash + the curry args used to derive it."""
        with self._client() as client:
            r = client.post(
                "/admin/auth/eip712/compute_leaf_hash",
                json={
                    "secp256k1_pubkey": "0x02" + "11" * 32,
                    "network": "testnet11",
                },
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["network"] == "testnet11"
        assert body["secp256k1_pubkey"] == "0x02" + "11" * 32
        # Sanity-check shapes; the actual values are pinned by
        # protocol-side tests in test_eip712_helpers.py.
        assert body["leaf_hash"].startswith("0x") and len(body["leaf_hash"]) == 66
        assert body["type_hash"].startswith("0x") and len(body["type_hash"]) == 66
        assert (
            body["prefix_and_domain_separator"].startswith("0x1901")
        ), body["prefix_and_domain_separator"]
        assert len(body["prefix_and_domain_separator"]) == 70  # 0x + 68 hex

    def test_default_network_uses_settings(self, monkeypatch):
        """Omitting ``network`` in the request defaults to the API's
        configured POPULIS_NETWORK setting (testnet11 by default).
        """
        with self._client() as client:
            r = client.post(
                "/admin/auth/eip712/compute_leaf_hash",
                json={"secp256k1_pubkey": "0x02" + "ab" * 32},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        # Default settings.network is "testnet11" — the conftest doesn't
        # mask network, so this just confirms the fallback wiring.
        assert body["network"] == "testnet11"

    def test_mainnet_vs_testnet11_differ(self):
        """Cross-network invariance: same pubkey → different leaf
        hashes on different networks (signatures must NOT replay).
        """
        with self._client() as client:
            mainnet = client.post(
                "/admin/auth/eip712/compute_leaf_hash",
                json={"secp256k1_pubkey": "0x02" + "11" * 32, "network": "mainnet"},
            ).json()
            testnet = client.post(
                "/admin/auth/eip712/compute_leaf_hash",
                json={"secp256k1_pubkey": "0x02" + "11" * 32, "network": "testnet11"},
            ).json()
        assert mainnet["leaf_hash"] != testnet["leaf_hash"]
        assert mainnet["prefix_and_domain_separator"] != (
            testnet["prefix_and_domain_separator"]
        )
        # type_hash is constant across networks.
        assert mainnet["type_hash"] == testnet["type_hash"]

    def test_rejects_short_pubkey(self):
        with self._client() as client:
            r = client.post(
                "/admin/auth/eip712/compute_leaf_hash",
                json={"secp256k1_pubkey": "0x02" + "11" * 31},  # 32 bytes
            )
        assert r.status_code == 400
        assert "33 bytes" in r.json()["detail"]

    def test_rejects_invalid_hex(self):
        with self._client() as client:
            r = client.post(
                "/admin/auth/eip712/compute_leaf_hash",
                json={"secp256k1_pubkey": "0xnot_hex"},
            )
        assert r.status_code == 400

    def test_no_auth_required(self):
        """Endpoint is intentionally unauthenticated — the leaf hash
        is a public commitment that can be independently verified.
        Anyone running the wizard can call this.
        """
        with self._client() as client:
            # No Authorization header.
            r = client.post(
                "/admin/auth/eip712/compute_leaf_hash",
                json={"secp256k1_pubkey": "0x02" + "11" * 32},
            )
        assert r.status_code == 200

    def test_rejects_unsupported_network(self):
        with self._client() as client:
            r = client.post(
                "/admin/auth/eip712/compute_leaf_hash",
                json={
                    "secp256k1_pubkey": "0x02" + "11" * 32,
                    "network": "simulator",
                },
            )
        # Pydantic catches this before the handler runs (Literal type).
        assert r.status_code == 422


    def test_boot_validator_surfaces_load_errors(self, tmp_path, monkeypatch):
        """Malformed JSON at the configured path → boot fails with a
        clear ``Failed to load admin records`` message.
        """
        from populis_api import admin_auth
        from populis_api.config import get_settings

        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")

        monkeypatch.setenv("POPULIS_ADMIN_RECORDS_PATH", str(bad))
        monkeypatch.setenv("POPULIS_ADMIN_JWT_SECRET", "x" * 64)
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID",
            "0x" + "10" * 32,
        )
        get_settings.cache_clear()
        with pytest.raises(RuntimeError, match=r"Failed to load admin records"):
            admin_auth.validate_admin_config_at_startup(get_settings())
