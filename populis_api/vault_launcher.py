"""Vault launcher composition.

Given:
  - a recovered 33-byte compressed secp256k1 pubkey (for EVM) or 48-byte BLS
    G1 (for Chia wallet)
  - the configured faucet (funds 1 mojo + fee)
  - the configured pool_launcher_id

Builds a *signed* SpendBundle that:
  1. Spends one faucet coin → creates (a) the singleton launcher coin
     with the vault's curried puzzle hash and (b) a change output back to
     the faucet.
  2. Spends the launcher coin → creates the vault singleton.

The launcher spend itself carries no AGG_SIG requirement (the launcher
puzzle is `(mod (singleton_full_puzzle_hash amount key_value_list) ...)`
— signatureless).  Only the faucet parent spend needs a BLS signature.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from populis_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    one_leaf_merkle_root,
    puzzle_for_vault_full,
    vault_discovery_hint,
)

from .faucet import Faucet

logger = logging.getLogger(__name__)

SINGLETON_AMOUNT = uint64(1)


@dataclass
class LaunchedVault:
    """Result of building + signing a vault launch spend bundle."""

    vault_launcher_id: bytes32
    vault_full_puzhash: bytes32
    p2_vault_puzhash: bytes32  # Derived separately by the driver
    spend_bundle: SpendBundle
    owner_pubkey: bytes
    auth_type: int

    @property
    def spend_bundle_id(self) -> str:
        return "0x" + self.spend_bundle.name().hex()


def build_and_sign_launch(
    *,
    faucet: Faucet,
    faucet_coin_json: dict,
    owner_pubkey: bytes,
    auth_type: int,
    pool_launcher_id: bytes32,
    fee: int = 0,
) -> LaunchedVault:
    """Build and sign the vault launch SpendBundle.

    `faucet_coin_json` is a coin record dict from coinset.org (must match
    `faucet.address_puzzle_hash` and have amount ≥ 1 + fee).
    """
    coin_payload = faucet_coin_json.get("coin") or faucet_coin_json
    parent_coin = Coin(
        parent_coin_info=_bytes32(coin_payload["parent_coin_info"]),
        puzzle_hash=_bytes32(coin_payload["puzzle_hash"]),
        amount=uint64(int(coin_payload["amount"])),
    )
    if parent_coin.puzzle_hash != faucet.address_puzzle_hash:
        raise ValueError(
            "Selected faucet coin has wrong puzzle hash; faucet key and coin record disagree"
        )
    if parent_coin.amount < SINGLETON_AMOUNT + fee:
        raise ValueError(
            f"Faucet coin {parent_coin.amount} mojos cannot cover 1 + {fee} fee"
        )

    launcher_coin = _launcher_coin_for_parent(parent_coin)
    vault_launcher_id = bytes32(launcher_coin.name())

    members_root = one_leaf_merkle_root(owner_pubkey)
    vault_full_puzzle = puzzle_for_vault_full(
        vault_launcher_id,
        owner_pubkey,
        auth_type,
        members_root,
        pool_launcher_id,
    )
    vault_full_puzhash = bytes32(vault_full_puzzle.get_tree_hash())

    # --- Launcher solution -----------------------------------------------
    launcher_solution = Program.to([vault_full_puzhash, SINGLETON_AMOUNT, []])

    # --- Parent (faucet) conditions: launcher coin + change + fee --------
    #
    # `puzzle_for_pk` (p2_delegated_puzzle_or_hidden_puzzle) auto-emits its
    # own AGG_SIG_ME condition over `sha256tree(delegated_puzzle)` — we do
    # NOT add a manual (50 ...) condition here.
    #
    # The launcher CREATE_COIN includes a CHIP-22 hint derived deterministically
    # from the owner's pubkey.  This is what makes the vault discoverable from
    # chain alone — any client knowing the owner pubkey can call
    # `get_coin_records_by_hint(vault_discovery_hint(auth_type, pubkey))` to
    # find this launcher without consulting the backend.
    discovery_hint = vault_discovery_hint(auth_type, owner_pubkey)

    change = parent_coin.amount - SINGLETON_AMOUNT - fee
    assert change >= 0, "faucet coin too small"
    conditions_list = [
        # CREATE_COIN launcher  (memos = [hint] makes this coin discoverable by hint)
        Program.to([51, SINGLETON_LAUNCHER_HASH, SINGLETON_AMOUNT, [discovery_hint]]),
    ]
    if change > 0:
        conditions_list.append(Program.to([51, parent_coin.puzzle_hash, change]))
    if fee > 0:
        conditions_list.append(Program.to([52, fee]))  # RESERVE_FEE

    conditions = Program.to(conditions_list)

    # --- Parent spend (standard p2 puzzle + delegated conditions) --------
    # p2_delegated_puzzle_or_hidden_puzzle solution format:
    #   (original_public_key_or_zero  delegated_puzzle  delegated_solution)
    # Passing 0 for original_public_key selects the synthetic-sig path,
    # which auto-emits AGG_SIG_ME(synth_pk, sha256tree(delegated_puzzle)).
    delegated_puzzle = Program.to((1, conditions))  # (q . conditions)
    delegated_solution = Program.to(0)
    parent_solution = Program.to([0, delegated_puzzle, delegated_solution])

    parent_spend = make_spend(parent_coin, faucet.key.puzzle, parent_solution)

    # --- Launcher spend (no signature required) --------------------------
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER

    # chia-rs 0.41's `make_spend` accepts either Program or SerializedProgram
    # and converts internally.  There is no `SerializedProgram.from_program`
    # classmethod in this version — pass Program directly.
    launcher_spend = make_spend(launcher_coin, SINGLETON_LAUNCHER, launcher_solution)

    # --- Sign the parent spend with AGG_SIG_ME --------------------------
    # Message committed by the puzzle: sha256tree(delegated_puzzle).
    # Full AGG_SIG_ME payload: message || coin.name() || AGG_SIG_ME_ADDITIONAL_DATA.
    sig_message = (
        bytes(delegated_puzzle.get_tree_hash())
        + bytes(parent_coin.name())
        + faucet.agg_sig_me_data
    )
    aggregated_sig = AugSchemeMPL.sign(faucet.key.synthetic_sk, sig_message)

    return LaunchedVault(
        vault_launcher_id=vault_launcher_id,
        vault_full_puzhash=vault_full_puzhash,
        p2_vault_puzhash=bytes32(b"\x00" * 32),  # filled in by caller (driver helper)
        spend_bundle=SpendBundle([parent_spend, launcher_spend], aggregated_sig),
        owner_pubkey=owner_pubkey,
        auth_type=auth_type,
    )


def _launcher_coin_for_parent(parent_coin: Coin) -> Coin:
    """Exact mirror of populis_puzzles.vault_driver.launcher_coin_for_parent."""
    return Coin(
        parent_coin_info=bytes32(parent_coin.name()),
        puzzle_hash=SINGLETON_LAUNCHER_HASH,
        amount=SINGLETON_AMOUNT,
    )


def _agg_sig_message(launcher_coin: Coin) -> bytes:
    """Payload the faucet attests to — the launcher coin id being created."""
    return bytes(launcher_coin.name())


def _bytes32(h: str) -> bytes32:
    clean = h[2:] if h.startswith("0x") else h
    return bytes32.fromhex(clean)


__all__ = [
    "AUTH_TYPE_BLS",
    "AUTH_TYPE_SECP256K1",
    "LaunchedVault",
    "build_and_sign_launch",
]
