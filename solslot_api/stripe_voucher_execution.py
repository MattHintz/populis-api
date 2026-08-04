"""Crash-safe exact KoS handoff for Stripe voucher terminal spends."""
from __future__ import annotations

import time
from typing import Any, Mapping

from chia.types.blockchain_format.coin import Coin
from chia_rs import SpendBundle
from chia_rs.sized_bytes import bytes32

from .kos_exact_execution import (
    ExactExecutionAction,
    ExactExecutionOutput,
    ExactExecutionRequest,
    KeyOfSolomonExactExecutor,
)
from .protocol_submission import (
    PreparedProtocolBundle,
    ProtocolBundleSubmitter,
    ProtocolSubmissionError,
)


SCHEMA = "solslot.stripe-voucher-terminal-execution.v1"
_MODE_ACTIONS = {
    "REDEEM": {3},
    "REFUND_EXPIRED": {2},
    "REFUND_OWNER": {1, 4},
}
_MODE_SHAPES = {
    "REDEEM": (
        {"coordination", "deed", "series", "terminalVoucher"},
        {
            "seriesInputCoinId",
            "deedInputCoinId",
            "externalSettlementEvidenceHash",
        },
    ),
    "REFUND_EXPIRED": (
        {"series", "terminalVoucher"},
        {"seriesInputCoinId", "externalSettlementEvidenceHash"},
    ),
    "REFUND_OWNER": (
        {"series", "terminalVoucher", "vault"},
        {
            "seriesInputCoinId",
            "vaultInputCoinId",
            "externalSettlementEvidenceHash",
        },
    ),
}


async def prepare_and_dispatch_stripe_terminal(
    *,
    store: Any,
    submitter: ProtocolBundleSubmitter,
    exact_executor: KeyOfSolomonExactExecutor,
    terms_hash: str,
    serial: int,
    mode: str,
    voucher_action: int,
    purchase_id: bytes32,
    artifact_hash: bytes32,
    claim_hash: bytes32,
    protocol_bundle: SpendBundle,
    expected_outputs: Mapping[str, Coin],
    bindings: Mapping[str, Any],
) -> tuple[dict[str, Any], int]:
    _validate_mode(mode, voucher_action)
    role_outputs = _role_outputs(expected_outputs)
    request = ExactExecutionRequest(
        action=ExactExecutionAction.VOUCHER_TERMINAL,
        purchase_id=purchase_id,
        artifact_hash=artifact_hash,
        claim_hash=claim_hash,
        expected_outputs=tuple(
            sorted(
                (_execution_output(coin) for coin in role_outputs.values()),
                key=lambda output: bytes(output.coin_id),
            )
        ),
    )

    async def dispatch(prepared: PreparedProtocolBundle):
        document = _document(
            mode=mode,
            voucher_action=voucher_action,
            request=request,
            prepared=prepared,
            role_outputs=role_outputs,
            bindings=bindings,
        )
        store.bind_stripe_terminal_execution(terms_hash, serial, document)
        return await exact_executor.dispatch(request, prepared)

    result = await submitter.prepare_and_dispatch(
        protocol_bundle.to_json_dict(),
        dispatch,
    )
    bound = store.voucher(terms_hash, serial).get("terminalExactExecution")
    if not isinstance(bound, dict):
        raise ProtocolSubmissionError(
            "exact Stripe voucher execution was not persisted",
            submission_attempted=True,
        )
    if str(result.get("spendBundleId", "")).lower() != str(
        bound.get("prepared", {}).get("spendBundleId", "")
    ).lower():
        raise ProtocolSubmissionError(
            "KoS returned a different Stripe voucher bundle ID",
            submission_attempted=True,
        )
    return bound, int(time.time())


async def resume_stripe_terminal(
    *,
    exact_executor: KeyOfSolomonExactExecutor,
    execution: Mapping[str, Any],
    expected_purchase_id: bytes32,
    expected_artifact_hash: bytes32,
) -> tuple[dict[str, Any], int]:
    document = parse_stripe_terminal_execution(
        execution,
        expected_purchase_id=expected_purchase_id,
        expected_artifact_hash=expected_artifact_hash,
    )
    request = _request_from_json(document["request"])
    prepared = _prepared_from_json(document["prepared"])
    await exact_executor.dispatch(request, prepared)
    return document, int(time.time())


def parse_stripe_terminal_execution(
    execution: Mapping[str, Any],
    *,
    expected_purchase_id: bytes32 | None = None,
    expected_artifact_hash: bytes32 | None = None,
) -> dict[str, Any]:
    document = dict(execution)
    if document.get("schema") != SCHEMA:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher execution schema is invalid"
        )
    mode = str(document.get("mode", ""))
    try:
        voucher_action = int(document["voucherAction"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher action is invalid"
        ) from exc
    _validate_mode(mode, voucher_action)
    request = _request_from_json(document.get("request"))
    prepared = _prepared_from_json(document.get("prepared"))
    if (
        expected_purchase_id is not None
        and request.purchase_id != expected_purchase_id
    ):
        raise ProtocolSubmissionError("persisted Stripe voucher purchase ID changed")
    if (
        expected_artifact_hash is not None
        and request.artifact_hash != expected_artifact_hash
    ):
        raise ProtocolSubmissionError("persisted Stripe voucher artifact hash changed")
    if request.action != ExactExecutionAction.VOUCHER_TERMINAL:
        raise ProtocolSubmissionError("persisted Stripe voucher action is not terminal")
    additions = {_hex32(coin.name()): coin for coin in prepared.bundle.additions()}
    removals = {_hex32(coin.name()) for coin in prepared.bundle.removals()}
    expected_ids = {_hex32(output.coin_id) for output in request.expected_outputs}
    if not expected_ids.issubset(additions):
        raise ProtocolSubmissionError("persisted Stripe voucher outputs are absent")
    roles = document.get("outputRoles")
    expected_roles, expected_bindings = _MODE_SHAPES[mode]
    if not isinstance(roles, Mapping) or set(roles) != expected_roles:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher output roles are missing"
        )
    try:
        role_ids = {_hex32(_b32(value)) for value in roles.values()}
    except ValueError as exc:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher output roles are malformed"
        ) from exc
    if role_ids != expected_ids:
        raise ProtocolSubmissionError("persisted Stripe voucher output roles changed")
    bindings = document.get("bindings")
    if not isinstance(bindings, Mapping) or set(bindings) != expected_bindings:
        raise ProtocolSubmissionError("persisted Stripe voucher bindings are missing")
    try:
        series_input = _hex32(_b32(bindings["seriesInputCoinId"]))
        evidence_hash = _b32(bindings["externalSettlementEvidenceHash"])
        bound_inputs = {series_input}
        if "deedInputCoinId" in bindings:
            bound_inputs.add(_hex32(_b32(bindings["deedInputCoinId"])))
        if "vaultInputCoinId" in bindings:
            bound_inputs.add(_hex32(_b32(bindings["vaultInputCoinId"])))
    except (KeyError, ValueError) as exc:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher bindings are malformed"
        ) from exc
    if evidence_hash == bytes32.zeros:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher evidence hash is empty"
        )
    if not bound_inputs.issubset(removals):
        raise ProtocolSubmissionError(
            "persisted Stripe voucher inputs are absent from its exact bundle"
        )
    return document


def _document(
    *,
    mode: str,
    voucher_action: int,
    request: ExactExecutionRequest,
    prepared: PreparedProtocolBundle,
    role_outputs: Mapping[str, Coin],
    bindings: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "mode": mode,
        "voucherAction": voucher_action,
        "request": {
            "action": int(request.action),
            "purchaseId": _hex32(request.purchase_id),
            "artifactHash": _hex32(request.artifact_hash),
            "claimHash": _hex32(request.claim_hash),
            "expectedOutputs": [
                {
                    "coinId": _hex32(output.coin_id),
                    "puzzleHash": _hex32(output.puzzle_hash),
                    "amount": str(output.amount),
                }
                for output in request.expected_outputs
            ],
        },
        "prepared": prepared.to_json(),
        "outputRoles": {
            role: _hex32(coin.name()) for role, coin in sorted(role_outputs.items())
        },
        "bindings": dict(bindings),
    }


def _request_from_json(value: Any) -> ExactExecutionRequest:
    if not isinstance(value, Mapping):
        raise ProtocolSubmissionError("persisted Stripe voucher request is malformed")
    try:
        outputs = tuple(
            ExactExecutionOutput(
                coin_id=_b32(item["coinId"]),
                puzzle_hash=_b32(item["puzzleHash"]),
                amount=int(item["amount"]),
            )
            for item in value["expectedOutputs"]
        )
        request = ExactExecutionRequest(
            action=ExactExecutionAction(int(value["action"])),
            purchase_id=_b32(value["purchaseId"]),
            artifact_hash=_b32(value["artifactHash"]),
            claim_hash=_b32(value["claimHash"]),
            expected_outputs=outputs,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher request is malformed"
        ) from exc
    if tuple(sorted(outputs, key=lambda output: bytes(output.coin_id))) != outputs:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher outputs are not canonical"
        )
    return request


def _prepared_from_json(value: Any) -> PreparedProtocolBundle:
    if not isinstance(value, Mapping):
        raise ProtocolSubmissionError("persisted Stripe voucher bundle is malformed")
    try:
        bundle = SpendBundle.from_json_dict(dict(value["spendBundle"]))
        bundle_id = _b32(value["spendBundleId"])
        fee_mojos = int(value["feeMojos"])
        fee_coin_id = _b32(value["feeCoinId"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolSubmissionError(
            "persisted Stripe voucher bundle is malformed"
        ) from exc
    if bytes32(bundle.name()) != bundle_id:
        raise ProtocolSubmissionError("persisted Stripe voucher bundle ID changed")
    if fee_mojos < 0:
        raise ProtocolSubmissionError("persisted Stripe voucher fee is invalid")
    if fee_coin_id not in {bytes32(coin.name()) for coin in bundle.removals()}:
        raise ProtocolSubmissionError("persisted Stripe voucher fee coin is absent")
    return PreparedProtocolBundle(
        bundle=bundle,
        fee_mojos=fee_mojos,
        fee_coin_id=_hex32(fee_coin_id),
    )


def _role_outputs(value: Mapping[str, Coin]) -> dict[str, Coin]:
    if not value or any(
        not role or not isinstance(coin, Coin)
        for role, coin in value.items()
    ):
        raise ValueError("Stripe voucher terminal outputs are invalid")
    result = dict(value)
    if len({_hex32(coin.name()) for coin in result.values()}) != len(result):
        raise ValueError("Stripe voucher terminal outputs must be unique")
    return result


def _execution_output(coin: Coin) -> ExactExecutionOutput:
    return ExactExecutionOutput(
        coin_id=bytes32(coin.name()),
        puzzle_hash=bytes32(coin.puzzle_hash),
        amount=int(coin.amount),
    )


def _validate_mode(mode: str, voucher_action: int) -> None:
    if mode not in _MODE_ACTIONS or voucher_action not in _MODE_ACTIONS[mode]:
        raise ValueError("Stripe voucher terminal mode does not match its action")


def _b32(value: Any) -> bytes32:
    try:
        return bytes32.fromhex(str(value).removeprefix("0x"))
    except (TypeError, ValueError) as exc:
        raise ValueError("expected a 32-byte hex value") from exc


def _hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


__all__ = [
    "SCHEMA",
    "parse_stripe_terminal_execution",
    "prepare_and_dispatch_stripe_terminal",
    "resume_stripe_terminal",
]
