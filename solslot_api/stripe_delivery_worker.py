"""Crash-safe Stripe receipt and exact protocol-asset delivery coordinator."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any, Mapping

from fastapi import HTTPException
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseDeliveryKind,
    build_stripe_settlement_receipt_v1,
    purchase_artifact_v3_from_json,
    stripe_settlement_evidence_from_json,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    build_stripe_primary_offer_v5,
    prepare_stripe_receipt_offer,
    StripeSettlementTermsV1,
    curry_stripe_settlement_receipt,
    stripe_settlement_receipt_solution,
)
from solslot_puzzles.sgt_driver import sgt_free_inner_puzzle, sgt_locked_inner_mod
from solslot_puzzles.sgt_reserve_driver import (
    SGTAllocationRail,
    build_sgt_external_sale_spend,
)
from solslot_puzzles.vault_driver import (
    puzzle_for_p2_vault,
    puzzle_hash_for_p2_vault,
)
from .config import Settings
from .base_direct_settlement import build_direct_settlement_authorization
from .credential_auth import require_minting_writes
from .external_settlement import (
    base_result_authorization_puzzle_hash,
    build_base_settlement_receipt,
)
from .faucet import Faucet
from .launch_gates import require_operation_gate
from .native_purchases import _load_context
from .omnichain_evidence import load_omnichain_evidence
from .governance_queue import GovernanceQueueStore
from .governance_sale_offer import (
    reconstruct_governed_sale_coin,
    reconstruct_governed_sale_lineage,
)
from .payment_purchase_store import get_payment_purchase_store
from .protocol_submission import ProtocolBundleSubmitter
from .public_artifact import load_signed_public_artifact
from .state import get_registry
from .stripe_delivery_store import (
    DELIVERY_PREPARED,
    DELIVERY_SUBMITTED,
    EXTERNAL_SETTLEMENT_PENDING,
    FINALIZED,
    PAYMENT_VERIFIED,
    RECEIPT_CONFIRMED,
    RECEIPT_FUNDING_PREPARED,
    RECEIPT_FUNDING_SUBMITTED,
    PAYMENT_RAIL_BASE_USDC,
    PAYMENT_RAIL_STRIPE,
    StripeDeliveryOperation,
    StripeDeliveryStore,
)
from .vault_eligibility import require_current_approved_vault
from .validator_quorum import (
    StripeSettlementClaim,
    collect_stripe_settlement_quorum,
    configured_validator_pubkeys,
)


logger = logging.getLogger(__name__)
_CREATE_COIN = 51


class StripeDeliveryError(RuntimeError):
    """The exact paid delivery cannot safely advance."""


class StripeDeliveryManualReview(StripeDeliveryError):
    """Chain state conflicts with the operation's immutable commitments."""


@dataclass(frozen=True)
class StripeDeliveryWorkerConfig:
    enabled: bool = False
    interval_seconds: float = 15.0
    lease_seconds: int = 60


class StripeDeliveryWorker:
    def __init__(
        self,
        *,
        settings: Settings,
        faucet: Faucet,
        provider: Any,
        submitter: ProtocolBundleSubmitter,
        store: StripeDeliveryStore,
        config: StripeDeliveryWorkerConfig,
    ) -> None:
        self.settings = settings
        self.faucet = faucet
        self.provider = provider
        self.submitter = submitter
        self.store = store
        self.config = config
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._advance_lock = asyncio.Lock()
        self._owner = f"stripe-delivery-{id(self):x}"

    async def start(self) -> None:
        if not self.config.enabled or (self._task and not self._task.done()):
            return
        self._stop.clear()
        self._task = asyncio.create_task(
            self._run_forever(), name="solslot-stripe-delivery"
        )
        logger.info(
            "Stripe protocol-asset delivery worker started; interval=%ss",
            self.config.interval_seconds,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def _run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                await self.reconcile_once()
            except Exception:  # noqa: BLE001
                logger.exception("Stripe protocol-asset delivery reconciliation failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self.config.interval_seconds
                )
            except asyncio.TimeoutError:
                pass

    async def reconcile_once(
        self,
        purchase_id: str | None = None,
    ) -> StripeDeliveryOperation | None:
        if not self._writes_are_open():
            return None
        async with self._advance_lock:
            operation = (
                self.store.claim(
                    purchase_id,
                    owner=self._owner,
                    lease_seconds=self.config.lease_seconds,
                )
                if purchase_id is not None
                else self.store.claim_next(
                    owner=self._owner,
                    lease_seconds=self.config.lease_seconds,
                )
            )
            if operation is None or operation.state == FINALIZED:
                return operation
            if not self._rail_is_enabled(operation):
                return self.store.release_lease(operation.purchase_id)
            try:
                return await self._advance(operation)
            except StripeDeliveryManualReview as exc:
                logger.error(
                    "Stripe purchase %s requires manual review: %s",
                    operation.purchase_id,
                    exc,
                )
                return self.store.record_manual_review(
                    operation.purchase_id,
                    error=str(exc),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Stripe purchase %s remains retryable: %s",
                    operation.purchase_id,
                    exc,
                )
                return self.store.record_error(operation.purchase_id, str(exc))

    def _writes_are_open(self) -> bool:
        if not (
            self.config.enabled
            and self.settings.protocol_fee_funding_enabled
            and (
                self.settings.stripe_settlement_enabled
                or self.settings.payment_omnichain_enabled
            )
        ):
            return False
        try:
            require_minting_writes(self.settings)
            require_operation_gate(self.settings, "purchases")
        except HTTPException:
            return False
        return True

    def _rail_is_enabled(self, operation: StripeDeliveryOperation) -> bool:
        if operation.payment_rail == PAYMENT_RAIL_STRIPE:
            return self.settings.stripe_settlement_enabled
        if operation.payment_rail == PAYMENT_RAIL_BASE_USDC:
            return self.settings.payment_omnichain_enabled
        return False

    async def _advance(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        if operation.state == PAYMENT_VERIFIED:
            return await self._prepare_receipt_funding(operation)
        if operation.state == RECEIPT_FUNDING_PREPARED:
            return await self._submit_or_recover_receipt_funding(operation)
        if operation.state == RECEIPT_FUNDING_SUBMITTED:
            return await self._confirm_receipt(operation)
        if operation.state == RECEIPT_CONFIRMED:
            return await self._prepare_delivery(operation)
        if operation.state == DELIVERY_PREPARED:
            return await self._submit_or_recover_delivery(operation)
        if operation.state == DELIVERY_SUBMITTED:
            return await self._confirm_delivery(operation)
        if operation.state == EXTERNAL_SETTLEMENT_PENDING:
            if operation.settlement_authorization is None:
                purchase = purchase_artifact_v3_from_json(
                    self._stored_purchase(operation.purchase_id)
                )
                authorization_id, authorization = (
                    build_direct_settlement_authorization(
                        operation=operation,
                        purchase=purchase,
                    )
                )
                return self.store.record_external_settlement_authorization(
                    operation.purchase_id,
                    authorization_id=authorization_id,
                    authorization=authorization,
                )
            return self.store.release_lease(operation.purchase_id)
        return operation

    def _receipt_terms(self, operation: StripeDeliveryOperation):
        purchase = purchase_artifact_v3_from_json(
            self._stored_purchase(operation.purchase_id)
        )
        result_puzzle_hash = bytes32.zeros
        if operation.payment_rail == PAYMENT_RAIL_STRIPE:
            evidence = stripe_settlement_evidence_from_json(operation.evidence)
            receipt = build_stripe_settlement_receipt_v1(
                artifact=purchase,
                evidence=evidence,
                validator_pubkeys=configured_validator_pubkeys(
                    self.settings
                ),
            )
        elif operation.payment_rail == PAYMENT_RAIL_BASE_USDC:
            token = self.settings.payment_evm_usdc_tokens.get(
                str(purchase.rail_chain_id)
            )
            if not token:
                raise StripeDeliveryManualReview(
                    "Base settlement token is disabled"
                )
            deployment = load_omnichain_evidence(
                self.settings,
                chain_id=purchase.rail_chain_id,
                token_address=token,
                gateway_profile=str(
                    operation.evidence.get("gatewayProfile") or ""
                ),
            )
            try:
                result_puzzle_hash = base_result_authorization_puzzle_hash(
                    artifact=purchase,
                    evidence=operation.evidence,
                    return_puzzle_hash=bytes32.from_hexstr(
                        deployment.return_puzzle_hash
                    ),
                )
                receipt = build_base_settlement_receipt(
                    artifact=purchase,
                    evidence=operation.evidence,
                    result_authorization_puzzle_hash=result_puzzle_hash,
                )
            except (ValueError, PaymentArtifactError) as exc:
                raise StripeDeliveryManualReview(
                    "Base result authorization cannot be reconstructed"
                ) from exc
        else:
            raise StripeDeliveryManualReview("unsupported external payment rail")
        if _hex32(receipt.receipt_hash) != operation.receipt_hash.lower():
            raise StripeDeliveryManualReview(
                "stored Stripe receipt hash differs from canonical evidence"
            )
        terms = StripeSettlementTermsV1(
            receipt=receipt,
            validator_pubkeys=configured_validator_pubkeys(self.settings),
        )
        if receipt.result_authorization_puzzle_hash != result_puzzle_hash:
            raise StripeDeliveryManualReview(
                "external receipt result authorization differs from deployment evidence"
            )
        return purchase, receipt, terms

    def _stored_purchase(self, purchase_id: str) -> dict[str, Any]:
        return self._stored_record(purchase_id).purchase_artifact

    def _stored_record(self, purchase_id: str):
        return get_payment_purchase_store(
            self.settings.payment_purchase_db_path
        ).get(purchase_id)

    async def _prepare_receipt_funding(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        _purchase, _receipt, terms = self._receipt_terms(operation)
        receipt_puzzle = curry_stripe_settlement_receipt(terms)
        parent = await self._select_faucet_coin(1)
        conditions = [
            Program.to(
                [
                    _CREATE_COIN,
                    bytes32(receipt_puzzle.get_tree_hash()),
                    1,
                    [terms.receipt.receipt_hash],
                ]
            )
        ]
        change = int(parent.amount) - 1
        if change:
            conditions.append(
                Program.to(
                    [_CREATE_COIN, self.faucet.address_puzzle_hash, change]
                )
            )
        condition_program = Program.to(conditions)
        delegated = Program.to((1, condition_program))
        parent_spend = make_spend(
            parent,
            self.faucet.key.puzzle,
            Program.to([0, delegated, Program.to(0)]),
        )
        signature = G2Element.from_bytes(
            self.faucet.sign_delegated_spend(parent, condition_program)
        )
        protocol_bundle = SpendBundle([parent_spend], signature)
        receipt_coin = Coin(
            bytes32(parent.name()),
            bytes32(receipt_puzzle.get_tree_hash()),
            uint64(1),
        )
        return self.store.record_receipt_prepared(
            operation.purchase_id,
            input_coin_id=_hex32(parent.name()),
            protocol_bundle=protocol_bundle.to_json_dict(),
            receipt_coin_id=_hex32(receipt_coin.name()),
            receipt_puzzle_hash=_hex32(receipt_coin.puzzle_hash),
        )

    async def _submit_or_recover_receipt_funding(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        if not operation.receipt_coin_id or not operation.receipt_funding_input_coin_id:
            raise StripeDeliveryManualReview("prepared receipt funding is incomplete")
        if await self._is_exact_confirmed_output(
            operation.receipt_coin_id,
            operation.receipt_puzzle_hash,
            1,
            require_unspent=True,
        ):
            return self.store.record_receipt_confirmed(operation.purchase_id)
        input_record = await self.provider.get_coin_record_by_name(
            operation.receipt_funding_input_coin_id
        )
        pending_id = await self._mempool_bundle_id(
            operation.receipt_funding_input_coin_id
        )
        if pending_id:
            return self.store.record_receipt_funding(
                operation.purchase_id,
                bundle_id=pending_id,
                receipt_coin_id=operation.receipt_coin_id,
                receipt_puzzle_hash=str(operation.receipt_puzzle_hash),
                fee_mojos=None,
                mempool_observed_at=_utc_now(),
            )
        if _is_spent(input_record):
            raise StripeDeliveryManualReview(
                "receipt funding input was spent without its committed receipt output"
            )
        if operation.receipt_funding_bundle is None:
            raise StripeDeliveryManualReview("prepared receipt bundle is missing")
        result = await self.submitter.submit(operation.receipt_funding_bundle)
        return self.store.record_receipt_funding(
            operation.purchase_id,
            bundle_id=str(result["spendBundleId"]).lower(),
            receipt_coin_id=operation.receipt_coin_id,
            receipt_puzzle_hash=str(operation.receipt_puzzle_hash),
            fee_mojos=int(result["feeMojos"]),
            mempool_observed_at=str(result["mempoolObservedAt"]),
        )

    async def _confirm_receipt(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        if not operation.receipt_coin_id:
            raise StripeDeliveryManualReview("receipt coin binding is missing")
        if await self._is_exact_confirmed_output(
            operation.receipt_coin_id,
            operation.receipt_puzzle_hash,
            1,
            require_unspent=True,
        ):
            return self.store.record_receipt_confirmed(operation.purchase_id)
        return self.store.release_lease(operation.purchase_id)

    async def _prepare_delivery(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        purchase, receipt, receipt_terms = self._receipt_terms(operation)
        expected_rail = (
            PaymentRail.STRIPE
            if operation.payment_rail == PAYMENT_RAIL_STRIPE
            else PaymentRail.EVM_TEST_USD
        )
        if purchase.rail != expected_rail or not operation.receipt_coin_id:
            raise StripeDeliveryManualReview("delivery payment rail changed")
        receipt_record = await self.provider.get_coin_record_by_name(
            operation.receipt_coin_id
        )
        receipt_coin = _confirmed_unspent_coin(receipt_record)
        if receipt_coin is None:
            return self.store.release_lease(operation.purchase_id)
        if purchase.delivery_kind == PurchaseDeliveryKind.SGT:
            return await self._prepare_sgt_delivery(
                operation=operation,
                purchase=purchase,
                receipt=receipt,
                receipt_terms=receipt_terms,
                receipt_coin=receipt_coin,
            )
        if purchase.delivery_kind != PurchaseDeliveryKind.SMARTDEED:
            raise StripeDeliveryManualReview(
                "external purchase has an unsupported delivery kind"
            )
        context = await _load_context(
            self.settings,
            self.provider,
            operation.purchase_id,
            require_live=False,
            allowed_rails=(expected_rail,),
        )
        if context.reservation is None:
            raise StripeDeliveryManualReview(
                "SmartDeed reservation terms are unavailable"
            )
        claim = StripeSettlementClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(context.genesis_artifact["artifactHash"]).lower(),
            purchase_artifact=context.stored.purchase_artifact,
            stripe_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_STRIPE
                else None
            ),
            base_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            base_result_authorization_puzzle_hash=(
                _hex32(
                    receipt.result_authorization_puzzle_hash
                )
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            receipt_coin_id=_hex32(receipt_coin.name()),
            receipt_puzzle_hash=_hex32(receipt_coin.puzzle_hash),
            deed_coin_id=_hex32(context.deed_coin.name()),
            deed_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
            smart_deed_inner_hash=_hex32(context.terms.smart_deed_inner_hash),
            reservation_expires_at=context.reservation.expires_at,
            protocol_puzzle_hash=_hex32(context.terms.protocol_puzhash),
            credential_vault_coin_id=str(
                context.credential_receipt["chiaVaultCoinId"]
            ),
            credential_identity_root=str(
                context.credential_receipt["identityAttestRoot"]
            ),
            credential_policy_version=int(
                context.credential_receipt["policyVersion"]
            ),
            credential_bridge_policy_hash=str(
                context.credential_receipt["bridgePolicyHash"]
            ),
            credential_owner_auth_type=context.credential_owner_auth_type,
            credential_owner_key="0x" + context.credential_owner_key.hex(),
        )
        quorum = await collect_stripe_settlement_quorum(self.settings, claim)
        receipt_puzzle = curry_stripe_settlement_receipt(receipt_terms)
        receipt_spend = make_spend(
            receipt_coin,
            receipt_puzzle,
            stripe_settlement_receipt_solution(
                receipt_coin=receipt_coin,
                signer_indices=quorum.signer_indices,
            ),
        )
        buyer_offer = prepare_stripe_receipt_offer(
            receipt_spend=receipt_spend,
            receipt=receipt,
            terms=context.terms,
        )
        primary = build_stripe_primary_offer_v5(
            receipt_offer=buyer_offer,
            receipt=receipt,
            receipt_coin=receipt_coin,
            deed_coin=context.deed_coin,
            deed_singleton_struct=context.deed_struct,
            lineage_proof=context.deed_lineage,
            artifact=purchase,
            signer_indices=quorum.signer_indices,
            terms=context.terms,
            reservation=context.reservation,
        )
        valid = primary.aggregate_offer.to_valid_spend()
        signed = WalletSpendBundle(
            valid.coin_spends,
            AugSchemeMPL.aggregate(
                [valid.aggregated_signature, quorum.aggregated_signature]
            ),
        )
        additions = signed.additions()
        vault_full = SINGLETON_MOD.curry(
            context.deed_struct,
            puzzle_for_p2_vault(purchase.vault_launcher_id),
        )
        deed_output = _one_output(
            additions,
            puzzle_hash=bytes32(vault_full.get_tree_hash()),
            amount=1,
            label="vault SmartDeed",
        )
        treasury_output = _one_output(
            additions,
            puzzle_hash=(
                receipt.result_authorization_puzzle_hash
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else context.terms.protocol_puzhash
            ),
            amount=1,
            label=(
                "Base result authorization"
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else "receipt treasury"
            ),
        )
        if deed_output.parent_coin_info != context.deed_coin.name():
            raise StripeDeliveryManualReview(
                "SmartDeed successor is not descended from the governed deed"
            )
        return self.store.record_delivery_prepared(
            operation.purchase_id,
            protocol_bundle=signed.to_json_dict(),
            delivery_output_coin_id=_hex32(deed_output.name()),
            treasury_output_coin_id=_hex32(treasury_output.name()),
            signer_indices=quorum.signer_indices,
        )

    async def _prepare_sgt_delivery(
        self,
        *,
        operation: StripeDeliveryOperation,
        purchase: Any,
        receipt: Any,
        receipt_terms: StripeSettlementTermsV1,
        receipt_coin: Coin,
    ) -> StripeDeliveryOperation:
        stored = self._stored_record(operation.purchase_id)
        protocol = stored.offer_artifact.get("protocol")
        if not isinstance(protocol, Mapping):
            raise StripeDeliveryManualReview(
                "SGT purchase protocol context is missing"
            )
        proposal_id = protocol.get("governanceProposalId")
        if not isinstance(proposal_id, str):
            raise StripeDeliveryManualReview(
                "SGT purchase has no governed proposal"
            )
        queue = GovernanceQueueStore(self.settings.admin_db_path)
        try:
            record = queue.get(proposal_id)
        finally:
            queue.close()
        if record.kind != "SGT_SALE" or record.state != "EXECUTED":
            raise StripeDeliveryManualReview(
                "SGT sale is not an executed governance proposal"
            )
        chain = await reconstruct_governed_sale_coin(
            record=record,
            provider=self.provider,
            settings=self.settings,
        )
        terms = chain.terms
        if (
            chain.spent_height is not None
            or terms.payment_rail
            != (
                SGTAllocationRail.STRIPE
                if operation.payment_rail == PAYMENT_RAIL_STRIPE
                else SGTAllocationRail.BASE_USDC
            )
            or terms.purchase_artifact_hash != purchase.artifact_hash
            or terms.payment_amount != purchase.rail_amount
            or terms.sgt_amount != purchase.delivery_amount
            or terms.sale_id != purchase.delivery_context_hash
            or terms.recipient_vault_launcher_id
            != purchase.vault_launcher_id
            or purchase.delivery_asset_id != chain.sgt_tail_hash
            or protocol.get("saleCoinId")
            != _hex32(chain.sale_coin.name())
        ):
            raise StripeDeliveryManualReview(
                "SGT delivery differs from its governed sale allocation"
            )
        lineage = await reconstruct_governed_sale_lineage(
            context=chain,
            provider=self.provider,
        )
        approved = require_current_approved_vault(
            self.settings,
            _hex32(purchase.vault_launcher_id),
            expected_identity_attest_root=_hex32(purchase.zkpassport_root),
        )
        vault_record = get_registry().get(purchase.vault_launcher_id)
        credential_receipt = approved.enrollment.receipt
        if vault_record is None or credential_receipt is None:
            raise StripeDeliveryManualReview(
                "SGT recipient vault ownership evidence is unavailable"
            )
        genesis = load_signed_public_artifact(self.settings)
        claim = StripeSettlementClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            purchase_artifact=stored.purchase_artifact,
            stripe_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_STRIPE
                else None
            ),
            base_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            base_result_authorization_puzzle_hash=(
                _hex32(
                    receipt.result_authorization_puzzle_hash
                )
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            receipt_coin_id=_hex32(receipt_coin.name()),
            receipt_puzzle_hash=_hex32(receipt_coin.puzzle_hash),
            sgt_sale_coin_id=_hex32(chain.sale_coin.name()),
            sgt_sale_puzzle_hash=_hex32(chain.sale_coin.puzzle_hash),
            governance_proposal_id=record.id,
            governance_bill_clvm_hex=record.bill_clvm_hex,
            protocol_puzzle_hash=_hex32(
                purchase.protocol_treasury_puzzle_hash
            ),
            credential_vault_coin_id=str(
                credential_receipt.chiaVaultCoinId
            ),
            credential_identity_root=str(
                credential_receipt.identityAttestRoot
            ),
            credential_policy_version=int(
                credential_receipt.policyVersion
            ),
            credential_bridge_policy_hash=str(
                credential_receipt.bridgePolicyHash
            ),
            credential_owner_auth_type=vault_record.auth_type,
            credential_owner_key="0x" + bytes(vault_record.owner_pubkey).hex(),
        )
        quorum = await collect_stripe_settlement_quorum(self.settings, claim)
        receipt_puzzle = curry_stripe_settlement_receipt(receipt_terms)
        receipt_spend = make_spend(
            receipt_coin,
            receipt_puzzle,
            stripe_settlement_receipt_solution(
                receipt_coin=receipt_coin,
                signer_indices=quorum.signer_indices,
            ),
        )
        sale_spend = build_sgt_external_sale_spend(
            sale_coin=chain.sale_coin,
            sale_lineage_proof=lineage,
            proposal_tracker_struct=chain.tracker_struct,
            reserve_owner_inner_hash=chain.reserve_owner_inner_hash,
            sgt_tail_hash=chain.sgt_tail_hash,
            terms=terms,
            external_receipt_coin_id=receipt_coin.name(),
            external_receipt_hash=receipt.receipt_hash,
        )
        signed = WalletSpendBundle(
            [receipt_spend, sale_spend],
            quorum.aggregated_signature,
        )
        recipient_inner = sgt_free_inner_puzzle(
            bytes32(sgt_locked_inner_mod().get_tree_hash()),
            chain.tracker_struct,
            puzzle_hash_for_p2_vault(purchase.vault_launcher_id),
        )
        recipient_full = construct_cat_puzzle(
            CAT_MOD,
            chain.sgt_tail_hash,
            recipient_inner,
        )
        additions = signed.additions()
        sgt_output = _one_output(
            additions,
            puzzle_hash=bytes32(recipient_full.get_tree_hash()),
            amount=terms.sgt_amount,
            label="vault SGT",
        )
        treasury_output = _one_output(
            additions,
            puzzle_hash=(
                receipt.result_authorization_puzzle_hash
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else purchase.protocol_treasury_puzzle_hash
            ),
            amount=1,
            label=(
                "Base result authorization"
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else "receipt treasury"
            ),
        )
        if sgt_output.parent_coin_info != chain.sale_coin.name():
            raise StripeDeliveryManualReview(
                "SGT successor is not descended from the governed sale coin"
            )
        if treasury_output.parent_coin_info != receipt_coin.name():
            raise StripeDeliveryManualReview(
                "receipt treasury output is not descended from the receipt"
            )
        return self.store.record_delivery_prepared(
            operation.purchase_id,
            protocol_bundle=signed.to_json_dict(),
            delivery_output_coin_id=_hex32(sgt_output.name()),
            treasury_output_coin_id=_hex32(treasury_output.name()),
            signer_indices=quorum.signer_indices,
        )

    async def _submit_or_recover_delivery(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        confirmation = await self._delivery_confirmation(operation)
        if confirmation is not None:
            return self._record_delivery_confirmation(operation, confirmation)
        if operation.delivery_bundle is None:
            raise StripeDeliveryManualReview("prepared delivery bundle is missing")
        bundle = SpendBundle.from_json_dict(operation.delivery_bundle)
        input_ids = [_hex32(coin.name()) for coin in bundle.removals()]
        for coin_id in input_ids:
            pending_id = await self._mempool_bundle_id(coin_id)
            if pending_id:
                return self.store.record_delivery_submission(
                    operation.purchase_id,
                    bundle_id=pending_id,
                    delivery_output_coin_id=str(
                        operation.expected_delivery_output_coin_id
                    ),
                    treasury_output_coin_id=str(
                        operation.expected_treasury_output_coin_id
                    ),
                    signer_indices=operation.signer_indices,
                    fee_mojos=None,
                    mempool_observed_at=_utc_now(),
                )
        input_records = [
            await self.provider.get_coin_record_by_name(coin_id)
            for coin_id in input_ids
        ]
        if any(_is_spent(record) for record in input_records):
            raise StripeDeliveryManualReview(
                "delivery input was spent without both committed outputs"
            )
        result = await self.submitter.submit(operation.delivery_bundle)
        return self.store.record_delivery_submission(
            operation.purchase_id,
            bundle_id=str(result["spendBundleId"]).lower(),
            delivery_output_coin_id=str(
                operation.expected_delivery_output_coin_id
            ),
            treasury_output_coin_id=str(
                operation.expected_treasury_output_coin_id
            ),
            signer_indices=operation.signer_indices,
            fee_mojos=int(result["feeMojos"]),
            mempool_observed_at=str(result["mempoolObservedAt"]),
        )

    async def _confirm_delivery(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        confirmation = await self._delivery_confirmation(operation)
        if confirmation is None:
            return self.store.release_lease(operation.purchase_id)
        return self._record_delivery_confirmation(operation, confirmation)

    def _record_delivery_confirmation(
        self,
        operation: StripeDeliveryOperation,
        confirmation_height: int,
    ) -> StripeDeliveryOperation:
        confirmed = self.store.record_delivery_confirmed(
            operation.purchase_id,
            confirmation_height=confirmation_height,
        )
        if confirmed.payment_rail != PAYMENT_RAIL_BASE_USDC:
            return confirmed
        purchase = purchase_artifact_v3_from_json(
            self._stored_purchase(operation.purchase_id)
        )
        authorization_id, authorization = build_direct_settlement_authorization(
            operation=confirmed,
            purchase=purchase,
        )
        return self.store.record_external_settlement_authorization(
            operation.purchase_id,
            authorization_id=authorization_id,
            authorization=authorization,
        )

    async def _delivery_confirmation(
        self,
        operation: StripeDeliveryOperation,
    ) -> int | None:
        if not (
            operation.expected_delivery_output_coin_id
            and operation.expected_treasury_output_coin_id
            and operation.delivery_bundle
        ):
            return None
        delivery_record = await self.provider.get_coin_record_by_name(
            operation.expected_delivery_output_coin_id
        )
        treasury_record = await self.provider.get_coin_record_by_name(
            operation.expected_treasury_output_coin_id
        )
        if not (
            _is_confirmed(delivery_record)
            and _is_confirmed(treasury_record)
        ):
            return None
        heights = {
            int(delivery_record.get("confirmed_block_index") or 0),
            int(treasury_record.get("confirmed_block_index") or 0),
        }
        if len(heights) != 1:
            raise StripeDeliveryManualReview(
                "delivery asset and treasury outputs did not confirm atomically"
            )
        bundle = SpendBundle.from_json_dict(operation.delivery_bundle)
        input_records = [
            await self.provider.get_coin_record_by_name(_hex32(coin.name()))
            for coin in bundle.removals()
        ]
        if any(not _is_spent(record) for record in input_records):
            return None
        spent_heights = {
            int(record.get("spent_block_index") or 0)
            for record in input_records
            if isinstance(record, Mapping)
        }
        if spent_heights != heights:
            raise StripeDeliveryManualReview(
                "delivery inputs and outputs did not settle in one block"
            )
        return heights.pop()

    async def _select_faucet_coin(self, amount: int) -> Coin:
        records = await self.provider.get_coin_records_by_puzzle_hash(
            self.faucet.address_hex,
            include_spent=False,
        )
        eligible: list[dict[str, Any]] = []
        for record in records:
            coin = self.faucet.select_coin(
                [record],
                min_amount=amount,
                max_amount=self.settings.faucet_max_spend_mojos,
            )
            if coin is None:
                continue
            if await self.provider.get_mempool_items_by_coin_name(
                _hex32(coin.name())
            ):
                continue
            eligible.append(record)
        selected = self.faucet.select_coin(
            eligible,
            min_amount=amount,
            max_amount=self.settings.faucet_max_spend_mojos,
        )
        if selected is None:
            raise StripeDeliveryError(
                "fee till has no confirmed unreserved receipt-funding coin"
            )
        return selected

    async def _mempool_bundle_id(self, coin_id: str) -> str | None:
        items = await self.provider.get_mempool_items_by_coin_name(coin_id)
        if not isinstance(items, list):
            return None
        for item in items:
            if not isinstance(item, Mapping):
                continue
            value = item.get("spend_bundle_name") or item.get("name")
            if isinstance(value, str):
                try:
                    return _normalize_hex32(value)
                except ValueError:
                    continue
        return None

    async def _is_exact_confirmed_output(
        self,
        coin_id: str,
        puzzle_hash: str | None,
        amount: int,
        *,
        require_unspent: bool,
    ) -> bool:
        if puzzle_hash is None:
            return False
        record = await self.provider.get_coin_record_by_name(coin_id)
        coin = _coin_from_record(record)
        return bool(
            coin is not None
            and _is_confirmed(record)
            and (not require_unspent or not _is_spent(record))
            and _hex32(coin.name()) == coin_id.lower()
            and _hex32(coin.puzzle_hash) == puzzle_hash.lower()
            and int(coin.amount) == amount
        )


def _one_output(
    additions: list[Coin],
    *,
    puzzle_hash: bytes32,
    amount: int,
    label: str,
) -> Coin:
    matches = [
        coin
        for coin in additions
        if coin.puzzle_hash == puzzle_hash and int(coin.amount) == amount
    ]
    if len(matches) != 1:
        raise StripeDeliveryManualReview(
            f"delivery must create exactly one {label}; found {len(matches)}"
        )
    return matches[0]


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping) or not isinstance(record.get("coin"), Mapping):
        return None
    coin = record["coin"]
    try:
        return Coin(
            bytes32.fromhex(str(coin["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(coin["puzzle_hash"]).removeprefix("0x")),
            uint64(int(coin["amount"])),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _confirmed_unspent_coin(record: Any) -> Coin | None:
    coin = _coin_from_record(record)
    if coin is None or not _is_confirmed(record) or _is_spent(record):
        return None
    return coin


def _is_confirmed(record: Any) -> bool:
    return (
        isinstance(record, Mapping)
        and int(record.get("confirmed_block_index") or 0) > 0
    )


def _is_spent(record: Any) -> bool:
    return bool(
        _is_confirmed(record)
        and (
            bool(record.get("spent"))
            or int(record.get("spent_block_index") or 0) > 0
        )
    )


def _hex32(value: Any) -> str:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError("value must be bytes32")
    return "0x" + raw.hex()


def _normalize_hex32(value: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    if len(normalized) != 66:
        raise ValueError("value is not bytes32")
    bytes.fromhex(normalized[2:])
    return normalized


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "StripeDeliveryError",
    "StripeDeliveryManualReview",
    "StripeDeliveryWorker",
    "StripeDeliveryWorkerConfig",
]
