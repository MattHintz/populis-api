from __future__ import annotations

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
import pytest
from types import SimpleNamespace

from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    build_sgt_purchase_artifact_v3,
    build_stripe_settlement_receipt_v1,
    purchase_artifact_v3_to_json,
    stripe_settlement_evidence_to_json,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.primary_purchase_v2_driver import (
    BASE_SEPOLIA_USDC_ASSET_ID,
)
from solslot_puzzles.sgt_driver import (
    bill_sgt_sale,
    sgt_free_inner_puzzle,
    sgt_locked_inner_mod,
)
from solslot_puzzles.sgt_reserve_driver import (
    SGTAllocationRail,
    sgt_cat_puzzle,
    sgt_sale_inner_puzzle,
    sgt_sale_terms_from_bill,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    StripeSettlementTermsV1,
    curry_stripe_settlement_receipt,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault

from solslot_api.config import Settings
from solslot_api.external_settlement import build_base_settlement_receipt
from solslot_api.faucet import Faucet
from solslot_api.stripe_delivery_store import (
    DELIVERY_PREPARED,
    DELIVERY_SGT,
    FINALIZED,
    PAYMENT_RAIL_BASE_USDC,
    PAYMENT_RAIL_STRIPE,
    RECEIPT_CONFIRMED,
    RECEIPT_FUNDING_PREPARED,
    RECEIPT_FUNDING_SUBMITTED,
    StripeDeliveryStore,
)
from solslot_api.stripe_delivery_worker import (
    StripeDeliveryWorker,
    StripeDeliveryWorkerConfig,
    _bound_outputs,
)


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _hex(value) -> str:
    return "0x" + bytes(value).hex()


def _record(coin: Coin, *, confirmed: int = 0, spent: int = 0):
    return {
        "coin": {
            "parent_coin_info": _hex(coin.parent_coin_info),
            "puzzle_hash": _hex(coin.puzzle_hash),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": confirmed,
        "spent_block_index": spent,
        "spent": spent > 0,
    }


class FakeProvider:
    def __init__(self):
        self.records = {}
        self.mempool = {}

    async def get_coin_record_by_name(self, coin_id):
        return self.records.get(coin_id.lower())

    async def get_mempool_items_by_coin_name(self, coin_id):
        return self.mempool.get(coin_id.lower(), [])


class FakeSubmitter:
    def __init__(self):
        self.calls = 0

    async def submit(self, _bundle):
        self.calls += 1
        return {
            "spendBundleId": _hex(_b32(90)),
            "feeMojos": "7",
            "mempoolObservedAt": "2026-08-01T12:00:00Z",
        }


class FakeExactExecutor:
    def __init__(self):
        self.calls = []

    async def dispatch(self, request, prepared):
        self.calls.append((request, prepared))
        return {"accepted": True}


def _worker(tmp_path, provider, submitter, store):
    return StripeDeliveryWorker(
        settings=Settings(),
        faucet=Faucet.from_seed_hex("01" * 32, "testnet11"),
        provider=provider,
        submitter=submitter,
        exact_executor=FakeExactExecutor(),
        store=store,
        config=StripeDeliveryWorkerConfig(enabled=True),
    )


def _queued(store):
    return store.queue(
        purchase_id=_hex(_b32(1)),
        evidence={"paymentIntentId": "pi_test"},
        receipt_hash=_hex(_b32(2)),
    )


def test_exact_output_manifest_preserves_sgt_quantity_and_multiple_outputs():
    parent = Coin(_b32(60), _b32(61), uint64(30_001))
    conditions = Program.to(
        [
            [51, _b32(62), 30_000],
            [51, _b32(63), 1],
        ]
    )
    spend = make_spend(parent, Program.to((1, conditions)), Program.to(0))
    bundle = SpendBundle([spend], G2Element())
    additions = bundle.additions()
    outputs = _bound_outputs(
        bundle.to_json_dict(),
        tuple(_hex(coin.name()) for coin in additions),
    )

    assert sorted(output.amount for output in outputs) == [1, 30_000]
    assert {output.coin_id for output in outputs} == {
        bytes32(coin.name()) for coin in additions
    }


@pytest.mark.asyncio
async def test_receipt_prepared_recovers_mempool_without_second_push(tmp_path):
    store = StripeDeliveryStore(str(tmp_path / "delivery.db"))
    provider = FakeProvider()
    submitter = FakeSubmitter()
    operation = _queued(store)
    input_coin = Coin(_b32(3), _b32(4), uint64(5))
    receipt_coin = Coin(input_coin.name(), _b32(5), uint64(1))
    provider.records[_hex(input_coin.name())] = _record(input_coin, confirmed=10)
    provider.mempool[_hex(input_coin.name())] = [
        {"spend_bundle_name": "pending"}
    ]
    receipt_conditions = Program.to([[51, receipt_coin.puzzle_hash, 1]])
    receipt_spend = make_spend(
        input_coin,
        Program.to((1, receipt_conditions)),
        Program.to(0),
    )
    receipt_bundle = SpendBundle([receipt_spend], G2Element())
    prepared = store.record_receipt_prepared(
        operation.purchase_id,
        input_coin_id=_hex(input_coin.name()),
        protocol_bundle=receipt_bundle.to_json_dict(),
        receipt_coin_id=_hex(receipt_coin.name()),
        receipt_puzzle_hash=_hex(receipt_coin.puzzle_hash),
    )
    prepared = store.bind_receipt_exact_bundle(
        operation.purchase_id,
        exact_bundle={
            "spendBundleId": _hex(receipt_bundle.name()),
            "feeMojos": "4",
            "feeCoinId": _hex(input_coin.name()),
            "spendBundle": receipt_bundle.to_json_dict(),
        },
    )
    provider.mempool[_hex(input_coin.name())] = [
        {"spend_bundle_name": _hex(receipt_bundle.name())}
    ]
    assert prepared.state == RECEIPT_FUNDING_PREPARED

    recovered = await _worker(
        tmp_path, provider, submitter, store
    )._submit_or_recover_receipt_funding(prepared)

    assert recovered.state == RECEIPT_FUNDING_SUBMITTED
    assert recovered.receipt_funding_bundle_id == _hex(receipt_bundle.name())
    assert recovered.receipt_funding_fee_mojos == 4
    assert submitter.calls == 0


@pytest.mark.asyncio
async def test_prepared_delivery_finalizes_only_one_atomic_block(tmp_path):
    store = StripeDeliveryStore(str(tmp_path / "delivery.db"))
    provider = FakeProvider()
    submitter = FakeSubmitter()
    operation = _queued(store)
    receipt_parent = Coin(_b32(7), _b32(8), uint64(5))
    receipt_coin = Coin(receipt_parent.name(), _b32(9), uint64(1))
    operation = store.record_receipt_prepared(
        operation.purchase_id,
        input_coin_id=_hex(receipt_parent.name()),
        protocol_bundle={"coin_spends": [], "aggregated_signature": "c0"},
        receipt_coin_id=_hex(receipt_coin.name()),
        receipt_puzzle_hash=_hex(receipt_coin.puzzle_hash),
    )
    operation = store.record_receipt_confirmed(operation.purchase_id)
    assert operation.state == RECEIPT_CONFIRMED

    deed_input = Coin(_b32(10), _b32(11), uint64(1))
    receipt_spend = make_spend(
        receipt_coin,
        Program.to((1, [[51, _b32(13), 1]])),
        Program.to(0),
    )
    deed_spend = make_spend(
        deed_input,
        Program.to((1, [[51, _b32(12), 1]])),
        Program.to(0),
    )
    bundle = SpendBundle([receipt_spend, deed_spend], G2Element())
    deed_output = next(
        coin for coin in bundle.additions() if coin.parent_coin_info == deed_input.name()
    )
    treasury_output = next(
        coin for coin in bundle.additions() if coin.parent_coin_info == receipt_coin.name()
    )
    operation = store.record_delivery_prepared(
        operation.purchase_id,
        protocol_bundle=bundle.to_json_dict(),
        deed_output_coin_id=_hex(deed_output.name()),
        treasury_output_coin_id=_hex(treasury_output.name()),
        signer_indices=(0, 1),
    )
    assert operation.state == DELIVERY_PREPARED

    provider.records[_hex(receipt_coin.name())] = _record(
        receipt_coin, confirmed=20, spent=30
    )
    provider.records[_hex(deed_input.name())] = _record(
        deed_input, confirmed=20, spent=30
    )
    provider.records[_hex(deed_output.name())] = _record(
        deed_output, confirmed=30
    )
    provider.records[_hex(treasury_output.name())] = _record(
        treasury_output, confirmed=30
    )

    finalized = await _worker(
        tmp_path, provider, submitter, store
    )._confirm_delivery(operation)

    assert finalized.state == FINALIZED
    assert finalized.confirmation_height == 30
    assert submitter.calls == 0


@pytest.mark.asyncio
async def test_two_deed_delivery_confirms_every_output_in_one_block(tmp_path):
    store = StripeDeliveryStore(str(tmp_path / "delivery.db"))
    provider = FakeProvider()
    operation = _queued(store)
    receipt_coin = Coin(_b32(70), _b32(71), uint64(2))
    deed_inputs = (
        Coin(_b32(72), _b32(73), uint64(1)),
        Coin(_b32(74), _b32(75), uint64(1)),
    )
    receipt_spend = make_spend(
        receipt_coin,
        Program.to((1, [])),
        Program.to(0),
    )
    deed_spends = tuple(
        make_spend(
            coin,
            Program.to(
                (
                    1,
                    [
                        [51, _b32(76 + index), 1],
                        [51, _b32(78), 1],
                    ],
                )
            ),
            Program.to(0),
        )
        for index, coin in enumerate(deed_inputs)
    )
    bundle = SpendBundle([receipt_spend, *deed_spends], G2Element())
    additions = bundle.additions()
    delivery_outputs = tuple(
        next(
            output
            for output in additions
            if output.parent_coin_info == coin.name()
            and output.puzzle_hash == _b32(76 + index)
        )
        for index, coin in enumerate(deed_inputs)
    )
    treasury_outputs = tuple(
        next(
            output
            for output in additions
            if output.parent_coin_info == coin.name()
            and output.puzzle_hash == _b32(78)
        )
        for coin in deed_inputs
    )
    operation = store.record_receipt_prepared(
        operation.purchase_id,
        input_coin_id=_hex(_b32(79)),
        protocol_bundle={"coin_spends": [], "aggregated_signature": "c0"},
        receipt_coin_id=_hex(receipt_coin.name()),
        receipt_puzzle_hash=_hex(receipt_coin.puzzle_hash),
    )
    operation = store.record_receipt_confirmed(operation.purchase_id)
    operation = store.record_delivery_prepared(
        operation.purchase_id,
        protocol_bundle=bundle.to_json_dict(),
        delivery_output_coin_id=_hex(delivery_outputs[0].name()),
        delivery_output_coin_ids=tuple(
            _hex(output.name()) for output in delivery_outputs
        ),
        treasury_output_coin_id=_hex(treasury_outputs[0].name()),
        treasury_output_coin_ids=tuple(
            _hex(output.name()) for output in treasury_outputs
        ),
        signer_indices=(0, 1),
    )
    for coin in (receipt_coin, *deed_inputs):
        provider.records[_hex(coin.name())] = _record(
            coin,
            confirmed=40,
            spent=50,
        )
    for coin in (*delivery_outputs, *treasury_outputs):
        provider.records[_hex(coin.name())] = _record(coin, confirmed=50)

    finalized = await _worker(
        tmp_path,
        provider,
        FakeSubmitter(),
        store,
    )._confirm_delivery(operation)

    assert finalized.state == FINALIZED
    assert finalized.confirmation_height == 50
    assert finalized.expected_delivery_output_coin_ids == tuple(
        _hex(output.name()) for output in delivery_outputs
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "delivery_payment_rail",
    (PAYMENT_RAIL_STRIPE, PAYMENT_RAIL_BASE_USDC),
)
async def test_sgt_delivery_uses_governed_sale_coin_and_vault_destination(
    tmp_path,
    monkeypatch,
    delivery_payment_rail,
):
    store = StripeDeliveryStore(str(tmp_path / "delivery.db"))
    provider = FakeProvider()
    worker = _worker(tmp_path, provider, FakeSubmitter(), store)
    vault_launcher = _b32(21)
    sgt_tail = _b32(22)
    sale_id = _b32(23)
    treasury = _b32(24)
    is_base = delivery_payment_rail == PAYMENT_RAIL_BASE_USDC
    purchase = build_sgt_purchase_artifact_v3(
        network="testnet11",
        sgt_asset_id=sgt_tail,
        sale_id=sale_id,
        sgt_amount=30_000,
        base_usd_amount_minor=10_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=treasury,
        zkpassport_root=_b32(25),
        rail=(PaymentRail.EVM_TEST_USD if is_base else PaymentRail.STRIPE),
        rail_chain_id=(84532 if is_base else 0),
        rail_asset_id=(
            BASE_SEPOLIA_USDC_ASSET_ID if is_base else bytes32.zeros
        ),
        rail_asset_decimals=(6 if is_base else 2),
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        authorization_nonce=_b32(26),
        authorization_expires_at=1_900_000_600,
        quote_expires_at=1_900_000_300,
    )
    reserve_owner = _b32(27)
    bill = bill_sgt_sale(
        sale_id=sale_id,
        sgt_amount=30_000,
        recipient_vault_launcher_id=vault_launcher,
        payment_rail=int(
            SGTAllocationRail.BASE_USDC
            if is_base
            else SGTAllocationRail.STRIPE
        ),
        payment_asset_id=(
            BASE_SEPOLIA_USDC_ASSET_ID if is_base else bytes32.zeros
        ),
        payment_amount=purchase.rail_amount,
        company_treasury_puzzle_hash=_b32(28),
        expires_at=1_900_000_300,
        reserve_owner_inner_puzzle_hash=reserve_owner,
        purchase_artifact_hash=purchase.artifact_hash,
    )
    terms = sgt_sale_terms_from_bill(
        bill,
        reserve_owner_inner_hash=reserve_owner,
    )
    tracker = singleton_struct(_b32(29))
    reserve_free = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        tracker,
        reserve_owner,
    )
    reserve_full = construct_cat_puzzle(CAT_MOD, sgt_tail, reserve_free)
    reserve_coin = Coin(_b32(30), reserve_full.get_tree_hash(), uint64(40_000))
    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=reserve_owner,
        sgt_tail_hash=sgt_tail,
        terms=terms,
    )
    sale_full = sgt_cat_puzzle(
        proposal_tracker_struct=tracker,
        sgt_tail_hash=sgt_tail,
        owner_inner_puzzle=sale_inner,
    )
    sale_coin = Coin(
        reserve_coin.name(),
        sale_full.get_tree_hash(),
        uint64(terms.sgt_amount),
    )
    lineage = LineageProof(
        reserve_coin.parent_coin_info,
        bytes32(reserve_free.get_tree_hash()),
        reserve_coin.amount,
    )
    pubkeys = tuple(
        bytes(AugSchemeMPL.key_gen(bytes([seed]) * 32).get_g1())
        for seed in (31, 32, 33)
    )
    if is_base:
        evidence = {
            "globalPaymentId": _hex(_b32(40)),
            "depositor": "0x" + "42" * 20,
            "settlementToken": (
                "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
            ),
            "transactionHash": _hex(_b32(43)),
            "blockNumber": 1_234_567,
            "blockHash": _hex(_b32(44)),
            "logIndex": 2,
            "status": "CONFIRMED",
            "source": {
                "chainId": 84532,
                "spoke": "0x" + "41" * 20,
                "blockTimestamp": 1_800_000_100,
            },
        }
        receipt = build_base_settlement_receipt(
            artifact=purchase,
            evidence=evidence,
            result_authorization_puzzle_hash=_b32(47),
        )
    else:
        evidence = StripeSettlementEvidenceV1(
            stripe_account_id="acct_test123",
            livemode=False,
            payment_intent_id="pi_test123",
            event_id="evt_test123",
            amount_minor=purchase.rail_amount,
            currency="usd",
            method_family=StripeMethodFamily.CARD,
            funding_type=StripeFundingType.CREDIT,
            processing_charge_minor=0,
            status=StripePaymentStatus.SUCCEEDED,
            refunded_minor=0,
            refund_state=StripeRefundState.NONE,
            dispute_state=StripeDisputeState.NONE,
            observed_at=1_800_000_100,
        )
        receipt = build_stripe_settlement_receipt_v1(
            artifact=purchase,
            evidence=evidence,
            validator_pubkeys=pubkeys,
        )
    receipt_terms = StripeSettlementTermsV1(
        receipt=receipt,
        validator_pubkeys=pubkeys,  # type: ignore[arg-type]
    )
    receipt_puzzle = curry_stripe_settlement_receipt(receipt_terms)
    receipt_coin = Coin(
        _b32(34),
        receipt_puzzle.get_tree_hash(),
        uint64(1),
    )
    purchase_json = purchase_artifact_v3_to_json(purchase)
    purchase_id = _hex(purchase.purchase_id)
    operation = store.queue(
        purchase_id=purchase_id,
        evidence=(
            evidence
            if is_base
            else stripe_settlement_evidence_to_json(evidence)
        ),
        receipt_hash=_hex(receipt.receipt_hash),
        payment_rail=delivery_payment_rail,
        delivery_kind=DELIVERY_SGT,
    )
    operation = store.record_receipt_prepared(
        purchase_id,
        input_coin_id=_hex(_b32(35)),
        protocol_bundle={"coin_spends": [], "aggregated_signature": "c0"},
        receipt_coin_id=_hex(receipt_coin.name()),
        receipt_puzzle_hash=_hex(receipt_coin.puzzle_hash),
    )
    operation = store.record_receipt_confirmed(purchase_id)
    record = SimpleNamespace(
        id="sgt-sale-test",
        kind="SGT_SALE",
        state="EXECUTED",
        bill_clvm_hex="0x" + bytes(bill).hex(),
    )
    chain = SimpleNamespace(
        sale_coin=sale_coin,
        terms=terms,
        tracker_struct=tracker,
        sgt_tail_hash=sgt_tail,
        reserve_owner_inner_hash=reserve_owner,
        spent_height=None,
    )

    class FakeQueue:
        def __init__(self, _path):
            pass

        def get(self, proposal_id):
            assert proposal_id == record.id
            return record

        def close(self):
            pass

    async def fake_chain(**_kwargs):
        return chain

    async def fake_lineage(**_kwargs):
        return lineage

    async def fake_quorum(_settings, claim):
        assert claim.sgt_sale_coin_id == _hex(sale_coin.name())
        assert claim.deed_coin_id is None
        assert (claim.base_evidence is not None) is is_base
        assert (claim.stripe_evidence is not None) is (not is_base)
        assert (
            claim.base_result_authorization_puzzle_hash is not None
        ) is is_base
        assert len(claim.signature_messages(pubkeys)) == 1
        return SimpleNamespace(
            signer_indices=(0, 1),
            aggregated_signature=G2Element(),
        )

    credential = SimpleNamespace(
        chiaVaultCoinId=_hex(_b32(36)),
        identityAttestRoot=_hex(purchase.zkpassport_root),
        policyVersion=2,
        bridgePolicyHash=_hex(_b32(37)),
    )
    approved = SimpleNamespace(
        enrollment=SimpleNamespace(receipt=credential),
    )
    monkeypatch.setattr(
        worker,
        "_stored_record",
        lambda _purchase_id: SimpleNamespace(
            purchase_artifact=purchase_json,
            offer_artifact={
                "protocol": {
                    "governanceProposalId": record.id,
                    "saleCoinId": _hex(sale_coin.name()),
                }
            },
        ),
    )
    monkeypatch.setattr(
        "solslot_api.stripe_delivery_worker.GovernanceQueueStore",
        FakeQueue,
    )
    monkeypatch.setattr(
        "solslot_api.stripe_delivery_worker.reconstruct_governed_sale_coin",
        fake_chain,
    )
    monkeypatch.setattr(
        "solslot_api.stripe_delivery_worker.reconstruct_governed_sale_lineage",
        fake_lineage,
    )
    monkeypatch.setattr(
        "solslot_api.stripe_delivery_worker.require_current_approved_vault",
        lambda *_args, **_kwargs: approved,
    )
    monkeypatch.setattr(
        "solslot_api.stripe_delivery_worker.get_registry",
        lambda: SimpleNamespace(
            get=lambda _launcher: SimpleNamespace(
                auth_type=1,
                owner_pubkey=pubkeys[0],
            )
        ),
    )
    monkeypatch.setattr(
        "solslot_api.stripe_delivery_worker.load_signed_public_artifact",
        lambda _settings: {"artifactHash": _hex(_b32(38))},
    )
    monkeypatch.setattr(
        "solslot_api.stripe_delivery_worker.collect_stripe_settlement_quorum",
        fake_quorum,
    )

    prepared = await worker._prepare_sgt_delivery(
        operation=operation,
        purchase=purchase,
        receipt=receipt,
        receipt_terms=receipt_terms,
        receipt_coin=receipt_coin,
    )

    assert prepared.state == DELIVERY_PREPARED
    assert prepared.delivery_kind == DELIVERY_SGT
    assert prepared.expected_sgt_output_coin_id is not None
    assert prepared.expected_deed_output_coin_id is None
    bundle = SpendBundle.from_json_dict(prepared.delivery_bundle)
    sgt_outputs = [
        coin
        for coin in bundle.additions()
        if int(coin.amount) == terms.sgt_amount
    ]
    assert len(sgt_outputs) == 1
    assert sgt_outputs[0].parent_coin_info == sale_coin.name()
    coordination_outputs = [
        coin
        for coin in bundle.additions()
        if int(coin.amount) == 1
        and coin.parent_coin_info == receipt_coin.name()
    ]
    assert len(coordination_outputs) == 1
    assert coordination_outputs[0].puzzle_hash == (
        receipt.result_authorization_puzzle_hash
        if is_base
        else purchase.protocol_treasury_puzzle_hash
    )
