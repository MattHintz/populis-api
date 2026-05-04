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


def _make_leaf_dict(
    *,
    leaf_hash: str,
    evm: str = "0x" + "ab" * 20,
    pubkey: str = "0x02" + "11" * 32,  # 33 bytes (compressed)
    type_hash: str = "0x" + "ee" * 32,
    domain: str = "0x1901" + "ff" * 32,  # 34 bytes, 0x1901 prefix
) -> dict:
    """Build a leaf JSON dict with sane defaults; override one field
    at a time in negative-path tests."""
    return {
        "kind": "eip712_member",
        "leaf_hash": leaf_hash,
        "evm_address": evm,
        "secp256k1_pubkey": pubkey,
        "type_hash": type_hash,
        "prefix_and_domain_separator": domain,
    }


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
                "leaves": [_make_leaf_dict(leaf_hash="0x" + "aa" * 32)],
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
        assert leaf.leaf_hash == _hash(0xAA)
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
                    _make_leaf_dict(leaf_hash="0x" + "01" * 32),
                    _make_leaf_dict(leaf_hash="0x" + "02" * 32),
                ],
            },
            {
                "admin_idx": 1,
                "m_within": 2,
                "leaves": [
                    _make_leaf_dict(leaf_hash="0x" + "03" * 32),
                    _make_leaf_dict(leaf_hash="0x" + "04" * 32),
                    _make_leaf_dict(leaf_hash="0x" + "05" * 32),
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
            leaf_hash="0x" + "aa" * 32,
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
                        leaf_hash="0x" + "01" * 32,
                        evm="0x" + "11" * 20,
                    ),
                ],
            },
            {
                "admin_idx": 1,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(
                        leaf_hash="0x" + "02" * 32,
                        evm="0x" + "22" * 20,
                    ),
                    _make_leaf_dict(
                        leaf_hash="0x" + "03" * 32,
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
        leaf_hash = _hash(0xAA)
        records_data = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [_make_leaf_dict(leaf_hash="0x" + leaf_hash.hex())],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records_data))
        config = load_admin_records_from_path(path)

        # Protocol-side recomputation from the same leaves.
        expected = protocol_compute_admins_hash([
            ProtocolAdminRecord(admin_idx=0, leaves=(leaf_hash,), m_within=1),
        ])
        assert config.compute_admins_hash() == expected

    def test_multi_admin_multi_leaf(self, tmp_path):
        """Order matters — both at admin-record level and leaf level."""
        leaves_a = (_hash(0x01), _hash(0x02))
        leaves_b = (_hash(0x03), _hash(0x04), _hash(0x05))
        records_data = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(leaf_hash="0x" + h.hex())
                    for h in leaves_a
                ],
            },
            {
                "admin_idx": 1,
                "m_within": 2,
                "leaves": [
                    _make_leaf_dict(leaf_hash="0x" + h.hex())
                    for h in leaves_b
                ],
            },
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records_data))
        config = load_admin_records_from_path(path)

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
                    _make_leaf_dict(leaf_hash="0x" + ("01" * 32)),
                    _make_leaf_dict(leaf_hash="0x" + ("02" * 32)),
                ],
            }
        ]
        records_b = [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(leaf_hash="0x" + ("02" * 32)),
                    _make_leaf_dict(leaf_hash="0x" + ("01" * 32)),
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
        leaf = _make_leaf_dict(leaf_hash="0x" + "aa" * 32)
        leaf["kind"] = "bls_member"
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="kind='bls_member' is not supported"):
            load_admin_records_from_path(path)

    def test_evm_address_wrong_length(self, tmp_path):
        leaf = _make_leaf_dict(
            leaf_hash="0x" + "aa" * 32,
            evm="0x1234",  # too short
        )
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="evm_address"):
            load_admin_records_from_path(path)

    def test_pubkey_wrong_length(self, tmp_path):
        leaf = _make_leaf_dict(
            leaf_hash="0x" + "aa" * 32,
            pubkey="0x" + "11" * 32,  # 32 bytes, not 33
        )
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="must be 33 bytes"):
            load_admin_records_from_path(path)

    def test_domain_separator_wrong_prefix(self, tmp_path):
        leaf = _make_leaf_dict(
            leaf_hash="0x" + "aa" * 32,
            domain="0x" + "00" * 34,  # right length but wrong prefix
        )
        records = [{"admin_idx": 0, "m_within": 1, "leaves": [leaf]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="0x1901"):
            load_admin_records_from_path(path)

    def test_m_within_exceeds_leaf_count(self, tmp_path):
        """Operator typo: m_within=3 but only 2 leaves → never satisfiable."""
        leaf1 = _make_leaf_dict(leaf_hash="0x" + "aa" * 32)
        leaf2 = _make_leaf_dict(leaf_hash="0x" + "bb" * 32)
        records = [{"admin_idx": 0, "m_within": 3, "leaves": [leaf1, leaf2]}]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="m_within \\(3\\) exceeds"):
            load_admin_records_from_path(path)

    def test_negative_admin_idx(self, tmp_path):
        records = [
            {
                "admin_idx": -1,
                "m_within": 1,
                "leaves": [_make_leaf_dict(leaf_hash="0x" + "aa" * 32)],
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
                "leaves": [_make_leaf_dict(leaf_hash="0x" + "aa" * 32)],
            }
        ]
        path = _write_json(tmp_path, _make_admin_records_dict(admin_records=records))
        with pytest.raises(AdminRecordsLoadError, match="m_within must be a positive"):
            load_admin_records_from_path(path)

    def test_field_path_in_error_for_nested_leaf(self, tmp_path):
        """Errors deep in the tree should reference the offending path."""
        good_leaf = _make_leaf_dict(leaf_hash="0x" + "aa" * 32)
        bad_leaf = _make_leaf_dict(leaf_hash="0x" + "bb" * 32)
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
                    _make_leaf_dict(leaf_hash="0x" + "01" * 32, evm=evm_a),
                ],
            },
            {
                "admin_idx": 1,
                "m_within": 1,
                "leaves": [
                    _make_leaf_dict(leaf_hash="0x" + "02" * 32, evm=evm_b),
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
                    _make_leaf_dict(leaf_hash="0x" + "01" * 32, evm=records_evm),
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
                "leaves": [_make_leaf_dict(leaf_hash="0x" + "aa" * 32)],
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
                "leaves": [_make_leaf_dict(leaf_hash="0x" + "aa" * 32)],
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
                "leaves": [_make_leaf_dict(leaf_hash="0x" + "aa" * 32)],
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
