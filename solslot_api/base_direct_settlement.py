"""Chain-confirmed Base settlement authorization for direct asset delivery."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from chia_rs import SpendBundle

from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseArtifactV3,
    PurchaseBatchV1,
    PurchaseDeliveryKind,
)

from .external_settlement import base_evidence_hash
from .stripe_delivery_store import (
    EXTERNAL_SETTLEMENT_PENDING,
    PAYMENT_RAIL_BASE_USDC,
    StripeDeliveryOperation,
)


SCHEMA = "solslot.base-direct-settlement-authorization.v1"


def build_direct_settlement_authorization(
    *,
    operation: StripeDeliveryOperation,
    purchase: PurchaseArtifactV3 | PurchaseBatchV1,
) -> tuple[str, dict[str, Any]]:
    batch = purchase if isinstance(purchase, PurchaseBatchV1) else None
    canonical = batch.artifacts[0] if batch is not None else purchase
    if (
        operation.payment_rail != PAYMENT_RAIL_BASE_USDC
        or operation.state != EXTERNAL_SETTLEMENT_PENDING
        or canonical.rail != PaymentRail.EVM_TEST_USD
    ):
        raise PaymentArtifactError("Base direct delivery is not ready to settle")
    delivery_output_ids = _operation_output_ids(
        operation,
        plural_name="expected_delivery_output_coin_ids",
        singular_name="expected_delivery_output_coin_id",
    )
    result_output_ids = _operation_output_ids(
        operation,
        plural_name="expected_treasury_output_coin_ids",
        singular_name="expected_treasury_output_coin_id",
    )
    if not all(
        (
            operation.delivery_bundle,
            operation.delivery_bundle_id,
            operation.receipt_coin_id,
            delivery_output_ids,
            result_output_ids,
            operation.confirmation_height,
        )
    ):
        raise PaymentArtifactError("Base direct chain evidence is incomplete")
    bundle = SpendBundle.from_json_dict(operation.delivery_bundle)
    receipt_id = str(operation.receipt_coin_id).lower()
    removals = {"0x" + coin.name().hex(): coin for coin in bundle.removals()}
    additions = {"0x" + coin.name().hex(): coin for coin in bundle.additions()}
    delivery_outputs = tuple(additions.get(value) for value in delivery_output_ids)
    result_outputs = tuple(additions.get(value) for value in result_output_ids)
    if any(value is None for value in (*delivery_outputs, *result_outputs)):
        raise PaymentArtifactError("Base direct committed outputs are missing")
    delivery_input_ids = tuple(
        "0x" + value.parent_coin_info.hex()
        for value in delivery_outputs
        if value is not None
    )
    if receipt_id not in removals or any(
        value not in removals for value in delivery_input_ids
    ):
        raise PaymentArtifactError("Base direct committed inputs are missing")
    source = operation.evidence.get("source")
    if not isinstance(source, dict):
        raise PaymentArtifactError("Base direct source evidence is missing")
    spoke = _address(str(source.get("spoke") or ""), "escrow spoke")
    global_payment_id = _hex32(
        operation.evidence.get("globalPaymentId"),
        "global payment ID",
    )
    authorization = {
        "schema": SCHEMA,
        "outcome": "DELIVERED",
        "globalPaymentId": global_payment_id,
        "purchaseId": "0x" + purchase.purchase_id.hex(),
        "purchaseArtifactHash": "0x" + (
            purchase.batch_hash if batch is not None else purchase.artifact_hash
        ).hex(),
        "deliveryKind": (
            "SMARTDEED"
            if canonical.delivery_kind == PurchaseDeliveryKind.SMARTDEED
            else "SGT"
        ),
        "deliveryAssetId": "0x" + canonical.delivery_asset_id.hex(),
        "deliveryAssetIds": [
            "0x" + value.delivery_asset_id.hex()
            for value in (batch.artifacts if batch is not None else (canonical,))
        ],
        "deliveryAmount": batch.quantity if batch is not None else int(canonical.delivery_amount),
        "deliveryContextHash": "0x" + canonical.delivery_context_hash.hex(),
        "vaultLauncherId": "0x" + canonical.vault_launcher_id.hex(),
        "vaultP2PuzzleHash": "0x" + canonical.vault_p2_puzzle_hash.hex(),
        "originalPayer": "0x" + (bytes(12) + _address(
            str(operation.evidence.get("depositor") or ""),
            "original payer",
        )).hex(),
        "payment": {
            "rail": "BASE_SEPOLIA_USDC",
            "chainId": int(canonical.rail_chain_id),
            "assetId": "0x" + canonical.rail_asset_id.hex(),
            "assetDecimals": int(canonical.rail_asset_decimals),
            "escrowContract": "0x" + (bytes(12) + spoke).hex(),
            "principal": int(
                batch.total_rail_amount if batch is not None else canonical.rail_amount
            ),
            "evidenceHash": "0x" + base_evidence_hash(operation.evidence).hex(),
        },
        "chia": {
            "spendBundleId": str(operation.delivery_bundle_id).lower(),
            "confirmedHeight": int(operation.confirmation_height),
            "externalReceiptInputCoinId": receipt_id,
            "deliveryInputCoinId": delivery_input_ids[0],
            "deliveryInputCoinIds": list(delivery_input_ids),
            "deliveryOutputCoinId": delivery_output_ids[0],
            "deliveryOutputCoinIds": list(delivery_output_ids),
            "resultAuthorizationCoinId": result_output_ids[0],
            "resultAuthorizationCoinIds": list(result_output_ids),
        },
    }
    encoded = json.dumps(
        authorization,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + sha256(encoded).hexdigest(), authorization


def _operation_output_ids(
    operation: StripeDeliveryOperation,
    *,
    plural_name: str,
    singular_name: str,
) -> tuple[str, ...]:
    plural = getattr(operation, plural_name, ()) or ()
    if plural:
        return tuple(str(value).lower() for value in plural)
    singular = getattr(operation, singular_name, None)
    return (str(singular).lower(),) if singular else ()


def _address(value: str, label: str) -> bytes:
    if not value.startswith("0x") or len(value) != 42:
        raise PaymentArtifactError(f"{label} is invalid")
    try:
        result = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise PaymentArtifactError(f"{label} is invalid") from exc
    if result == bytes(20):
        raise PaymentArtifactError(f"{label} cannot be zero")
    return result


def _hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        raise PaymentArtifactError(f"{label} is invalid")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise PaymentArtifactError(f"{label} is invalid") from exc
    if raw == bytes(32):
        raise PaymentArtifactError(f"{label} cannot be zero")
    return "0x" + raw.hex()


__all__ = ["SCHEMA", "build_direct_settlement_authorization"]
