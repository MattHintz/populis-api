from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.kos_exact_execution import ExactExecutionAction
from solslot_api.protocol_submission import (
    PreparedProtocolBundle,
    ProtocolSubmissionError,
)
from solslot_api.stripe_voucher_execution import (
    parse_stripe_terminal_execution,
    prepare_and_dispatch_stripe_terminal,
    resume_stripe_terminal,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


def exact_bundle() -> tuple[PreparedProtocolBundle, dict[str, Coin], Coin, Coin]:
    protocol_coin = Coin(b32(1), b32(2), uint64(4))
    role_puzzle_hashes = {
        "coordination": b32(11),
        "deed": b32(12),
        "series": b32(13),
        "terminalVoucher": b32(14),
    }
    protocol_puzzle = Program.to(
        (1, [[51, puzzle_hash, 1] for puzzle_hash in role_puzzle_hashes.values()])
    )
    roles = {
        role: Coin(protocol_coin.name(), puzzle_hash, uint64(1))
        for role, puzzle_hash in role_puzzle_hashes.items()
    }
    fee_coin = Coin(b32(20), b32(21), uint64(10))
    fee_puzzle = Program.to((1, [[51, fee_coin.puzzle_hash, 7], [52, 3]]))
    bundle = SpendBundle(
        [
            make_spend(protocol_coin, protocol_puzzle, Program.to(0)),
            make_spend(fee_coin, fee_puzzle, Program.to(0)),
        ],
        G2Element(),
    )
    return (
        PreparedProtocolBundle(
            bundle=bundle,
            fee_mojos=3,
            fee_coin_id=hex32(fee_coin.name()),
        ),
        roles,
        protocol_coin,
        fee_coin,
    )


class RecordingStore:
    def __init__(self) -> None:
        self.execution: dict[str, Any] | None = None
        self.events: list[str] = []

    def bind_stripe_terminal_execution(
        self,
        terms_hash: str,
        serial: int,
        execution: dict[str, Any],
    ) -> None:
        assert terms_hash == hex32(b32(30))
        assert serial == 4
        self.events.append("persisted")
        if self.execution is not None and self.execution != execution:
            raise ValueError("terminal execution changed")
        self.execution = deepcopy(execution)

    def voucher(self, terms_hash: str, serial: int) -> dict[str, Any]:
        assert terms_hash == hex32(b32(30))
        assert serial == 4
        return {"terminalExactExecution": deepcopy(self.execution)}


class FixedSubmitter:
    def __init__(self, prepared: PreparedProtocolBundle) -> None:
        self.prepared = prepared

    async def prepare_and_dispatch(self, bundle: dict[str, Any], dispatcher):
        assert SpendBundle.from_json_dict(bundle).coin_spends
        result = await dispatcher(self.prepared)
        return {
            "spendBundleId": hex32(bytes32(self.prepared.bundle.name())),
            "dispatchResult": dict(result or {}),
        }


class RecordingExecutor:
    def __init__(self, store: RecordingStore, *, fail: bool = False) -> None:
        self.store = store
        self.fail = fail
        self.calls: list[tuple[Any, PreparedProtocolBundle]] = []

    async def dispatch(self, request, prepared):
        assert self.store.events == ["persisted"]
        self.store.events.append("dispatched")
        self.calls.append((request, prepared))
        if self.fail:
            raise ProtocolSubmissionError(
                "simulated lost executor response",
                submission_attempted=True,
            )
        return {"accepted": True}


@pytest.mark.asyncio
async def test_terminal_execution_is_persisted_before_dispatch_and_resumes_exactly(
) -> None:
    prepared, roles, series_input, deed_input = exact_bundle()
    store = RecordingStore()
    submitter = FixedSubmitter(prepared)
    first_executor = RecordingExecutor(store, fail=True)
    purchase_id = b32(31)
    artifact_hash = b32(32)

    with pytest.raises(ProtocolSubmissionError, match="lost executor response"):
        await prepare_and_dispatch_stripe_terminal(
            store=store,
            submitter=submitter,  # type: ignore[arg-type]
            exact_executor=first_executor,  # type: ignore[arg-type]
            terms_hash=hex32(b32(30)),
            serial=4,
            mode="REDEEM",
            voucher_action=3,
            purchase_id=purchase_id,
            artifact_hash=artifact_hash,
            claim_hash=b32(33),
            protocol_bundle=prepared.bundle,
            expected_outputs=roles,
            bindings={
                "seriesInputCoinId": hex32(series_input.name()),
                "deedInputCoinId": hex32(deed_input.name()),
                "externalSettlementEvidenceHash": hex32(b32(34)),
            },
        )

    assert store.execution is not None
    assert store.events == ["persisted", "dispatched"]
    assert store.execution["request"]["action"] == int(
        ExactExecutionAction.VOUCHER_TERMINAL
    )
    assert store.execution["prepared"]["feeMojos"] == "3"
    first_bundle_id = store.execution["prepared"]["spendBundleId"]

    store.events = ["persisted"]
    resumed_executor = RecordingExecutor(store)
    execution, _observed_at = await resume_stripe_terminal(
        exact_executor=resumed_executor,  # type: ignore[arg-type]
        execution=store.execution,
        expected_purchase_id=purchase_id,
        expected_artifact_hash=artifact_hash,
    )

    assert execution["prepared"]["spendBundleId"] == first_bundle_id
    assert len(resumed_executor.calls) == 1
    assert (
        hex32(bytes32(resumed_executor.calls[0][1].bundle.name()))
        == first_bundle_id
    )


@pytest.mark.asyncio
async def test_terminal_resume_rejects_relabeling_and_unbound_inputs() -> None:
    prepared, roles, series_input, deed_input = exact_bundle()
    store = RecordingStore()
    executor = RecordingExecutor(store)
    await prepare_and_dispatch_stripe_terminal(
        store=store,
        submitter=FixedSubmitter(prepared),  # type: ignore[arg-type]
        exact_executor=executor,  # type: ignore[arg-type]
        terms_hash=hex32(b32(30)),
        serial=4,
        mode="REDEEM",
        voucher_action=3,
        purchase_id=b32(31),
        artifact_hash=b32(32),
        claim_hash=b32(33),
        protocol_bundle=prepared.bundle,
        expected_outputs=roles,
        bindings={
            "seriesInputCoinId": hex32(series_input.name()),
            "deedInputCoinId": hex32(deed_input.name()),
            "externalSettlementEvidenceHash": hex32(b32(34)),
        },
    )
    assert store.execution is not None

    missing_role = deepcopy(store.execution)
    del missing_role["outputRoles"]["deed"]
    with pytest.raises(ProtocolSubmissionError, match="output roles"):
        parse_stripe_terminal_execution(missing_role)

    changed_input = deepcopy(store.execution)
    changed_input["bindings"]["deedInputCoinId"] = hex32(b32(99))
    with pytest.raises(ProtocolSubmissionError, match="inputs are absent"):
        parse_stripe_terminal_execution(changed_input)

    changed_purchase = deepcopy(store.execution)
    with pytest.raises(ProtocolSubmissionError, match="purchase ID changed"):
        parse_stripe_terminal_execution(
            changed_purchase,
            expected_purchase_id=b32(98),
        )
