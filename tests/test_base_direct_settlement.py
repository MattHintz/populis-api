from types import SimpleNamespace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.payment_artifacts_v3 import (
    build_purchase_batch_v1,
    build_evm_test_usd_purchase_artifact_v3,
)

from solslot_api.base_direct_settlement import (
    SCHEMA,
    build_direct_settlement_authorization,
)
from solslot_api.stripe_delivery_store import (
    EXTERNAL_SETTLEMENT_PENDING,
    PAYMENT_RAIL_BASE_USDC,
)


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _hex(value: bytes32) -> str:
    return "0x" + value.hex()


def test_authorization_derives_input_from_exact_delivery_output() -> None:
    purchase = build_evm_test_usd_purchase_artifact_v3(
        chain_id=84532,
        token_asset_id=bytes32(bytes(12) + bytes.fromhex(
            "036cbd53842c5426634e7929541ec2318f3dcf7e"
        )),
        network="testnet11",
        collection_id=_b32(1),
        deed_launcher_id=_b32(2),
        metadata_root=_b32(3),
        metadata_anchor_id=_b32(4),
        share_ppm=100_000,
        base_usd_amount_minor=10_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=_b32(5),
        zkpassport_root=_b32(6),
        vault_launcher_id=_b32(7),
        vault_p2_puzzle_hash=_b32(8),
        authorization_nonce=_b32(9),
        authorization_expires_at=1_900_000_600,
        quote_expires_at=1_900_000_300,
    )
    receipt_coin = Coin(_b32(10), _b32(11), uint64(1))
    delivery_coin = Coin(_b32(12), _b32(13), uint64(1))
    ephemeral_coin = Coin(receipt_coin.name(), _b32(14), uint64(1))
    result_hash = _b32(15)
    delivery_hash = _b32(16)
    receipt_spend = make_spend(
        receipt_coin,
        Program.to(1),
        Program.to([[51, result_hash, 1], [51, ephemeral_coin.puzzle_hash, 1]]),
    )
    ephemeral_spend = make_spend(
        ephemeral_coin,
        Program.to(1),
        Program.to([]),
    )
    delivery_spend = make_spend(
        delivery_coin,
        Program.to(1),
        Program.to([[51, delivery_hash, 1]]),
    )
    bundle = SpendBundle(
        [receipt_spend, ephemeral_spend, delivery_spend],
        G2Element(),
    )
    additions = bundle.additions()
    delivery_output = next(
        coin for coin in additions
        if coin.parent_coin_info == delivery_coin.name()
    )
    result_output = next(
        coin for coin in additions
        if coin.puzzle_hash == result_hash
    )
    operation = SimpleNamespace(
        payment_rail=PAYMENT_RAIL_BASE_USDC,
        state=EXTERNAL_SETTLEMENT_PENDING,
        delivery_bundle=bundle.to_json_dict(),
        delivery_bundle_id=_hex(bundle.name()),
        receipt_coin_id=_hex(receipt_coin.name()),
        expected_delivery_output_coin_id=_hex(delivery_output.name()),
        expected_treasury_output_coin_id=_hex(result_output.name()),
        confirmation_height=123,
        evidence={
            "globalPaymentId": _hex(_b32(17)),
            "depositor": "0x" + "18" * 20,
            "source": {"spoke": "0x" + "19" * 20},
        },
    )

    _authorization_id, authorization = build_direct_settlement_authorization(
        operation=operation,
        purchase=purchase,
    )

    assert authorization["schema"] == SCHEMA
    assert authorization["chia"]["deliveryInputCoinId"] == _hex(
        delivery_coin.name()
    )
    assert authorization["chia"]["resultAuthorizationCoinId"] == _hex(
        result_output.name()
    )


def test_batch_authorization_preserves_every_exact_deed_output() -> None:
    common = {
        "chain_id": 84532,
        "token_asset_id": bytes32(
            bytes(12)
            + bytes.fromhex("036cbd53842c5426634e7929541ec2318f3dcf7e")
        ),
        "network": "testnet11",
        "collection_id": _b32(31),
        "metadata_root": _b32(32),
        "metadata_anchor_id": _b32(33),
        "share_ppm": 50_000,
        "base_usd_amount_minor": 10_000,
        "technology_fee_bps": 100,
        "protocol_treasury_puzzle_hash": _b32(34),
        "zkpassport_root": _b32(35),
        "vault_launcher_id": _b32(36),
        "vault_p2_puzzle_hash": _b32(37),
        "authorization_nonce": _b32(38),
        "authorization_expires_at": 1_900_000_600,
        "quote_expires_at": 1_900_000_300,
    }
    batch = build_purchase_batch_v1(
        batch_nonce=_b32(39),
        artifacts=(
            build_evm_test_usd_purchase_artifact_v3(
                **common,
                deed_launcher_id=_b32(40),
            ),
            build_evm_test_usd_purchase_artifact_v3(
                **common,
                deed_launcher_id=_b32(41),
            ),
        ),
    )
    receipt_coin = Coin(_b32(42), _b32(43), uint64(2))
    delivery_inputs = (
        Coin(_b32(44), _b32(45), uint64(1)),
        Coin(_b32(46), _b32(47), uint64(1)),
    )
    delivery_hashes = (_b32(48), _b32(49))
    result_hash = _b32(50)
    spends = [
        make_spend(receipt_coin, Program.to(1), Program.to([]))
    ]
    spends.extend(
        make_spend(
            coin,
            Program.to(1),
            Program.to(
                [
                    [51, delivery_hash, 1],
                    [51, result_hash, 1],
                ]
            ),
        )
        for coin, delivery_hash in zip(
            delivery_inputs,
            delivery_hashes,
            strict=True,
        )
    )
    bundle = SpendBundle(spends, G2Element())
    additions = bundle.additions()
    delivery_outputs = tuple(
        next(
            coin
            for coin in additions
            if coin.parent_coin_info == parent.name()
            and coin.puzzle_hash == delivery_hash
        )
        for parent, delivery_hash in zip(
            delivery_inputs,
            delivery_hashes,
            strict=True,
        )
    )
    result_outputs = tuple(
        next(
            coin
            for coin in additions
            if coin.parent_coin_info == parent.name()
            and coin.puzzle_hash == result_hash
        )
        for parent in delivery_inputs
    )
    operation = SimpleNamespace(
        payment_rail=PAYMENT_RAIL_BASE_USDC,
        state=EXTERNAL_SETTLEMENT_PENDING,
        delivery_bundle=bundle.to_json_dict(),
        delivery_bundle_id=_hex(bundle.name()),
        receipt_coin_id=_hex(receipt_coin.name()),
        expected_delivery_output_coin_id=_hex(delivery_outputs[0].name()),
        expected_delivery_output_coin_ids=tuple(
            _hex(coin.name()) for coin in delivery_outputs
        ),
        expected_treasury_output_coin_id=_hex(result_outputs[0].name()),
        expected_treasury_output_coin_ids=tuple(
            _hex(coin.name()) for coin in result_outputs
        ),
        confirmation_height=321,
        evidence={
            "globalPaymentId": _hex(_b32(51)),
            "depositor": "0x" + "52" * 20,
            "source": {"spoke": "0x" + "53" * 20},
        },
    )

    _authorization_id, authorization = build_direct_settlement_authorization(
        operation=operation,
        purchase=batch,
    )

    assert authorization["deliveryAmount"] == 2
    assert authorization["purchaseArtifactHash"] == _hex(batch.batch_hash)
    assert authorization["chia"]["deliveryInputCoinIds"] == [
        _hex(coin.name()) for coin in delivery_inputs
    ]
    assert authorization["chia"]["deliveryOutputCoinIds"] == [
        _hex(coin.name()) for coin in delivery_outputs
    ]
    assert authorization["chia"]["resultAuthorizationCoinIds"] == [
        _hex(coin.name()) for coin in result_outputs
    ]
