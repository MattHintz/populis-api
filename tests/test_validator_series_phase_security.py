from __future__ import annotations

from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api import validator_service
from solslot_api.validator_quorum import VoucherSeriesPhaseClaim
from solslot_api.validator_service import (
    ValidatorEvidenceError,
    _verify_governed_deed_launchers,
)
from solslot_puzzles import load_puzzle
from solslot_puzzles.mint_publish_driver import deed_launcher_puzzle_hash
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.voucher_presale_v2 import (
    DeedAllocationCommitmentV2,
    allocation_root,
)


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _hex(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _fixture(*, launcher_puzzle_hash: bytes32, child_puzzle_hash: bytes32):
    launcher = Coin(_b32(1), launcher_puzzle_hash, uint64(1))
    row = DeedAllocationCommitmentV2(
        deed_id=canonicalise_property_id("parcel-1"),
        share_ppm=1_000_000,
        par_value_mojos=1,
        deed_launcher_id=bytes32(launcher.name()),
    )
    terms = SimpleNamespace(inventory_cap=1, allocation_root=allocation_root((row,)))
    claim = VoucherSeriesPhaseClaim(
        network="testnet11",
        genesis_artifact_hash=_hex(_b32(3)),
        series_terms={
            "deeds": [
                {
                    "ordinal": 0,
                    "deedId": "parcel-1",
                    "deedIdCanon": _hex(row.deed_id),
                    "sharePpm": row.share_ppm,
                    "parValueMojos": row.par_value_mojos,
                    "deedLauncherId": _hex(row.deed_launcher_id),
                }
            ]
        },
        series_coin_id=_hex(_b32(4)),
        series_sold_count=0,
        series_redeemed_count=0,
        series_refunded_count=0,
        series_phase=1,
        series_launched_at=0,
        transition=2,
        launch_anchor=1_800_000_000,
        deed_launcher_ids=[_hex(row.deed_launcher_id)],
        governed_deed_puzzle_hashes=[_hex(child_puzzle_hash)],
        validator_message=_hex(_b32(5)),
    )
    return launcher, terms, claim


def _install_chain_evidence(
    monkeypatch: pytest.MonkeyPatch,
    *,
    launcher: Coin,
    puzzle: Program,
    child_puzzle_hash: bytes32,
) -> None:
    monkeypatch.setattr(
        validator_service,
        "_fetch_coin",
        lambda *_args, **_kwargs: {
            "coin": {
                "parent_coin_info": _hex(launcher.parent_coin_info),
                "puzzle_hash": _hex(launcher.puzzle_hash),
                "amount": 1,
            },
            "confirmed_block_index": 100,
            "spent_block_index": 101,
            "spent": True,
        },
    )
    spend = make_spend(
        launcher,
        puzzle,
        Program.to([_b32(6), child_puzzle_hash, 1, []]),
    )
    monkeypatch.setattr(
        validator_service,
        "_fetch_coin_spend",
        lambda *_args, **_kwargs: spend,
    )


def test_series_phase_rejects_generic_singleton_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_hash = _b32(7)
    launcher, terms, claim = _fixture(
        launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
        child_puzzle_hash=child_hash,
    )
    _install_chain_evidence(
        monkeypatch,
        launcher=launcher,
        puzzle=Program.to(1),
        child_puzzle_hash=child_hash,
    )

    with pytest.raises(ValidatorEvidenceError, match="DID-bound"):
        _verify_governed_deed_launchers(
            SimpleNamespace(),
            claim,
            terms,
            {"launcherIds": {"did": _hex(_b32(8))}},
        )


def test_series_phase_rejects_child_outside_executed_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    did_launcher = _b32(8)
    did_struct = singleton_struct(did_launcher)
    launcher_hash = deed_launcher_puzzle_hash(
        protocol_did_singleton_struct=did_struct
    )
    expected_child_hash = _b32(9)
    launcher, terms, claim = _fixture(
        launcher_puzzle_hash=launcher_hash,
        child_puzzle_hash=expected_child_hash,
    )
    _install_chain_evidence(
        monkeypatch,
        launcher=launcher,
        puzzle=load_puzzle("singleton_launcher_with_did.clsp").curry(did_struct),
        child_puzzle_hash=_b32(10),
    )

    with pytest.raises(ValidatorEvidenceError, match="executed proposal"):
        _verify_governed_deed_launchers(
            SimpleNamespace(),
            claim,
            terms,
            {"launcherIds": {"did": _hex(did_launcher)}},
        )


def test_series_phase_accepts_exact_did_bound_governed_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    did_launcher = _b32(8)
    did_struct = singleton_struct(did_launcher)
    launcher_hash = deed_launcher_puzzle_hash(
        protocol_did_singleton_struct=did_struct
    )
    child_hash = _b32(9)
    launcher, terms, claim = _fixture(
        launcher_puzzle_hash=launcher_hash,
        child_puzzle_hash=child_hash,
    )
    _install_chain_evidence(
        monkeypatch,
        launcher=launcher,
        puzzle=load_puzzle("singleton_launcher_with_did.clsp").curry(did_struct),
        child_puzzle_hash=child_hash,
    )

    _verify_governed_deed_launchers(
        SimpleNamespace(),
        claim,
        terms,
        {"launcherIds": {"did": _hex(did_launcher)}},
    )
