"""Chain-authoritative SOLS secondary SmartDeed market.

SOLS is the pool CAT used by Pool V3 spend case 6. It is not a primary
checkout rail. This module deliberately refuses to turn database rows into
market inventory until the live pool, deed custody, and governed collection
NAV have all been reconstructed from Testnet11 puzzle solutions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Annotated, Any, Mapping, Optional

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import APIRouter, Depends, HTTPException, Request, status

from solslot_puzzles import load_puzzle
from solslot_puzzles.collection_nav_registry_driver import (
    collection_nav_registry_inner_mod_hash,
    collection_nav_root,
    normalise_nav_entries,
)
from solslot_puzzles.mint_publish_driver import canonical_p2_pool_mod_hash
from solslot_puzzles.pool_economics_v2 import (
    PoolEconomicState,
    deed_metadata_commitment,
    quote_specific_deed_swap,
)
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, puzzle_for_p2_vault

from .chia_provider import ChiaProvider, ChiaProviderError
from .collection_store import CollectionStore, get_collection_store
from .config import Settings, get_settings
from .credential_auth import require_vault_record, verify_vault_session
from .public_artifact import (
    PublicArtifactError,
    PublicArtifactMissing,
    load_signed_public_artifact,
)
from .vault_eligibility import require_current_approved_vault


router = APIRouter(prefix="/sols", tags=["sols-secondary-market"])

POOL_ACTIVE = 1
POOL_SPEND_DEPOSIT = 1
POOL_SPEND_SETTLEMENT = 3
POOL_SPEND_GOVERNANCE = 4
POOL_SPEND_V2_SPECIFIC_DEED_SWAP = 6
POOL_SPEND_V2_TRUE_REDEMPTION = 7
POOL_SPEND_V2_RESERVE_ACQUISITION = 8
DEED_SPEND_POOL_DEPOSIT = 0x64
MAX_SINGLETON_DEPTH = 10_000


@dataclass(frozen=True)
class LiveCoin:
    coin_id: str
    parent_coin_id: str
    puzzle_hash: str
    amount: int
    confirmed_height: int
    spent_height: Optional[int]
    is_launcher: bool = False


@dataclass(frozen=True)
class SingletonTip:
    launcher_id: str
    live: LiveCoin
    latest_spent: Optional[LiveCoin]
    depth: int


@dataclass(frozen=True)
class PoolState:
    pool_status: int
    total_nav_locked_mojos: int
    deed_count: int
    total_pool_token_supply: int
    treasury_reserve_tokens: int
    live_coin_id: str
    live_puzzle_hash: str
    confirmed_height: int
    lineage_depth: int

    def economics(self) -> PoolEconomicState:
        return PoolEconomicState(
            total_nav_locked_mojos=self.total_nav_locked_mojos,
            deed_count=self.deed_count,
            total_pool_token_supply=self.total_pool_token_supply,
            treasury_reserve_tokens=self.treasury_reserve_tokens,
        )


@dataclass(frozen=True)
class NavRegistryState:
    live_coin_id: str
    live_puzzle_hash: str
    collection_nav_root: str
    registry_version: int
    entries: dict[str, int]
    confirmed_height: int


@dataclass(frozen=True)
class PoolDeed:
    deed_coin_id: str
    deed_launcher_id: str
    par_value_mojos: int
    asset_class: int
    property_id_canon: str
    collection_id_canon: str
    share_ppm: int
    confirmed_height: int


def _hex(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _hex32(value: str, label: str) -> str:
    normalized = value.removeprefix("0x").lower()
    if len(normalized) != 64:
        raise ValueError(f"{label} must be exactly 32 bytes")
    bytes.fromhex(normalized)
    return "0x" + normalized


def _program(value: str) -> Program:
    return Program.from_bytes(bytes.fromhex(value.removeprefix("0x")))


def _coin(record: Mapping[str, Any], *, launcher: bool = False) -> LiveCoin:
    payload = record.get("coin")
    if not isinstance(payload, Mapping):
        raise ValueError("coin record has no coin")
    parent = _hex32(str(payload.get("parent_coin_info") or ""), "parent coin id")
    puzzle = _hex32(str(payload.get("puzzle_hash") or ""), "puzzle hash")
    amount = int(payload.get("amount"))
    coin_id = _hex(
        Coin(
            bytes32.fromhex(parent.removeprefix("0x")),
            bytes32.fromhex(puzzle.removeprefix("0x")),
            uint64(amount),
        ).name()
    )
    spent = int(record.get("spent_block_index") or 0)
    return LiveCoin(
        coin_id=coin_id,
        parent_coin_id=parent,
        puzzle_hash=puzzle,
        amount=amount,
        confirmed_height=int(record.get("confirmed_block_index") or 0),
        spent_height=spent or None,
        is_launcher=launcher,
    )


def _singleton_child(
    records: list[dict[str, Any]],
    *,
    expected_amount: int,
) -> LiveCoin:
    candidates = [
        _coin(record)
        for record in records
        if isinstance(record.get("coin"), Mapping)
        and int(record["coin"].get("amount") or -1) == expected_amount
    ]
    if len(candidates) != 1:
        raise ValueError(
            "singleton continuation is missing or ambiguous"
        )
    return candidates[0]


async def _singleton_tip(provider: ChiaProvider, launcher_id: str) -> Optional[SingletonTip]:
    launcher_id = _hex32(launcher_id, "launcher id")
    launcher_record = await provider.get_coin_record_by_name(launcher_id)
    if launcher_record is None:
        return None
    launcher = _coin(launcher_record, launcher=True)
    nodes = [launcher]
    if launcher.spent_height is None:
        return SingletonTip(launcher_id, launcher, None, 0)

    parent = launcher.coin_id
    for _ in range(MAX_SINGLETON_DEPTH):
        children = await provider.get_coin_records_by_parent_ids(
            [parent], include_spent=True
        )
        if not children:
            raise ValueError(
                "spent singleton coin has no confirmed continuation"
            )
        child = _singleton_child(
            children,
            expected_amount=launcher.amount,
        )
        nodes.append(child)
        if child.spent_height is None:
            return SingletonTip(
                launcher_id,
                child,
                next((item for item in reversed(nodes[:-1]) if item.spent_height), None),
                len(nodes) - 1,
            )
        parent = child.coin_id
    raise ValueError("singleton lineage exceeds the safety limit")


async def _latest_solution(
    provider: ChiaProvider, tip: SingletonTip
) -> Optional[dict[str, Any]]:
    spent = tip.latest_spent
    if spent is None or spent.is_launcher or spent.spent_height is None:
        return None
    return await provider.get_puzzle_and_solution(spent.coin_id, spent.spent_height)


def _solution_parts(solution_hex: str, label: str) -> tuple[list[Program], list[Program]]:
    outer = list(_program(solution_hex).as_iter())
    if len(outer) != 3:
        raise ValueError(f"{label} singleton solution must have three items")
    inner = list(outer[2].as_iter())
    return outer, inner


def _apply_pool_transition(
    previous: PoolEconomicState,
    *,
    pool_status: int,
    fp_scale: int,
    spend_case: int,
    params: list[Program],
) -> tuple[int, PoolEconomicState]:
    if spend_case == POOL_SPEND_DEPOSIT:
        if len(params) != 9:
            raise ValueError("pool deposit has the wrong parameter count")
        par = int(params[2].as_int())
        minted = (par * fp_scale) // 1000
        return pool_status, PoolEconomicState(
            previous.total_nav_locked_mojos + par,
            previous.deed_count + 1,
            previous.total_pool_token_supply + minted,
            previous.treasury_reserve_tokens,
        )
    if spend_case == POOL_SPEND_SETTLEMENT:
        return 1, PoolEconomicState(
            0,
            0,
            previous.total_pool_token_supply,
            previous.treasury_reserve_tokens,
        )
    if spend_case == POOL_SPEND_GOVERNANCE:
        if len(params) != 2:
            raise ValueError("pool governance has the wrong parameter count")
        return int(params[0].as_int()), previous
    if spend_case in (POOL_SPEND_V2_SPECIFIC_DEED_SWAP, POOL_SPEND_V2_TRUE_REDEMPTION):
        expected = 24 if spend_case == POOL_SPEND_V2_SPECIFIC_DEED_SWAP else 15
        if len(params) != expected:
            raise ValueError("pool deed exit has the wrong parameter count")
        nav = int(params[7].as_int())
        share = int(params[6].as_int())
        deed_nav = (nav * share + 999_999) // 1_000_000
        circulating = (
            previous.total_pool_token_supply - previous.treasury_reserve_tokens
        )
        principal = (
            deed_nav * circulating + previous.total_nav_locked_mojos - 1
        ) // previous.total_nav_locked_mojos
        return pool_status, PoolEconomicState(
            previous.total_nav_locked_mojos - deed_nav,
            previous.deed_count - 1,
            previous.total_pool_token_supply
            - (principal if spend_case == POOL_SPEND_V2_TRUE_REDEMPTION else 0),
            previous.treasury_reserve_tokens
            + (principal if spend_case == POOL_SPEND_V2_SPECIFIC_DEED_SWAP else 0),
        )
    if spend_case == POOL_SPEND_V2_RESERVE_ACQUISITION:
        if len(params) != 15:
            raise ValueError("pool acquisition has the wrong parameter count")
        nav = int(params[7].as_int())
        share = int(params[6].as_int())
        deed_nav = (nav * share + 999_999) // 1_000_000
        price = int(params[13].as_int())
        reserve_paid = min(previous.treasury_reserve_tokens, price)
        fresh = price - reserve_paid
        return pool_status, PoolEconomicState(
            previous.total_nav_locked_mojos + deed_nav,
            previous.deed_count + 1,
            previous.total_pool_token_supply + fresh,
            previous.treasury_reserve_tokens - reserve_paid,
        )
    raise ValueError(f"unsupported Pool V3 spend case {spend_case}")


def _decode_pool_state(
    puzzle_solution: Mapping[str, Any], tip: SingletonTip
) -> PoolState:
    full = _program(str(puzzle_solution["puzzle_reveal"]))
    full_uncurried = full.uncurry()
    if full_uncurried is None:
        raise ValueError("pool puzzle is not a curried singleton")
    full_mod, full_args_program = full_uncurried
    full_args = list(full_args_program.as_iter())
    if len(full_args) != 2 or full_mod.get_tree_hash() != SINGLETON_MOD_HASH:
        raise ValueError("pool puzzle is not the canonical singleton")
    old_inner = full_args[1]
    old_uncurried = old_inner.uncurry()
    if old_uncurried is None:
        raise ValueError("pool inner puzzle is not curried")
    inner_mod, inner_args_program = old_uncurried
    inner_args = list(inner_args_program.as_iter())
    if len(inner_args) != 24:
        raise ValueError("Pool V3 inner puzzle must have 24 arguments")
    if inner_mod.get_tree_hash() != load_puzzle("pool_singleton_inner_v3.clsp").get_tree_hash():
        raise ValueError("pool inner module hash is not Pool V3")

    _, inner_solution = _solution_parts(
        str(puzzle_solution["solution"]), "pool"
    )
    if len(inner_solution) != 5:
        raise ValueError("Pool V3 inner solution must have five items")
    spend_case = int(inner_solution[3].as_int())
    params = list(inner_solution[4].as_iter())
    previous_status = int(inner_args[19].as_int())
    previous = PoolEconomicState(
        int(inner_args[20].as_int()),
        int(inner_args[21].as_int()),
        int(inner_args[22].as_int()),
        int(inner_args[23].as_int()),
    )
    current_status, current = _apply_pool_transition(
        previous,
        pool_status=previous_status,
        fp_scale=int(inner_args[18].as_int()),
        spend_case=spend_case,
        params=params,
    )
    current_inner = inner_mod.curry(
        *inner_args[:19],
        current_status,
        current.total_nav_locked_mojos,
        current.deed_count,
        current.total_pool_token_supply,
        current.treasury_reserve_tokens,
    )
    current_full = full_mod.curry(full_args[0], current_inner)
    if _hex(current_full.get_tree_hash()) != tip.live.puzzle_hash:
        raise ValueError("reconstructed pool state does not match the live coin")
    return PoolState(
        pool_status=current_status,
        total_nav_locked_mojos=current.total_nav_locked_mojos,
        deed_count=current.deed_count,
        total_pool_token_supply=current.total_pool_token_supply,
        treasury_reserve_tokens=current.treasury_reserve_tokens,
        live_coin_id=tip.live.coin_id,
        live_puzzle_hash=tip.live.puzzle_hash,
        confirmed_height=tip.live.confirmed_height,
        lineage_depth=tip.depth,
    )


def _nav_entries(node: Program) -> list[tuple[bytes32, int]]:
    entries: list[tuple[bytes32, int]] = []
    for item in node.as_iter():
        values = list(item.as_iter())
        if len(values) != 2:
            raise ValueError("NAV entry must contain collection id and value")
        entries.append((bytes32(values[0].as_atom()), int(values[1].as_int())))
    return normalise_nav_entries(entries)


def _decode_nav_state(
    puzzle_solution: Mapping[str, Any], tip: SingletonTip
) -> NavRegistryState:
    full = _program(str(puzzle_solution["puzzle_reveal"]))
    full_uncurried = full.uncurry()
    if full_uncurried is None:
        raise ValueError("NAV registry puzzle is not a curried singleton")
    full_mod, full_args_program = full_uncurried
    full_args = list(full_args_program.as_iter())
    if len(full_args) != 2 or full_mod.get_tree_hash() != SINGLETON_MOD_HASH:
        raise ValueError("NAV registry is not a canonical singleton")
    old_inner = full_args[1]
    inner_uncurried = old_inner.uncurry()
    if inner_uncurried is None:
        raise ValueError("NAV registry inner puzzle is not curried")
    inner_mod, inner_args_program = inner_uncurried
    inner_args = list(inner_args_program.as_iter())
    if (
        len(inner_args) != 4
        or inner_mod.get_tree_hash() != collection_nav_registry_inner_mod_hash()
    ):
        raise ValueError("NAV registry inner puzzle is not canonical")
    _, inner_solution = _solution_parts(
        str(puzzle_solution["solution"]), "NAV registry"
    )
    if len(inner_solution) != 5:
        raise ValueError("NAV registry inner solution must have five items")
    previous_entries = _nav_entries(inner_solution[3])
    old_root = bytes32(inner_args[2].as_atom())
    if collection_nav_root(previous_entries) != old_root:
        raise ValueError("NAV registry witness does not reproduce its previous root")
    old_version = int(inner_args[3].as_int())
    new_version = int(inner_solution[4].as_int())
    collection_id = bytes32(inner_solution[1].as_atom())
    nav_value = int(inner_solution[2].as_int())
    if new_version == old_version:
        entries = previous_entries
        if (collection_id, nav_value) not in entries:
            raise ValueError("NAV read witness does not match current entries")
    elif new_version == old_version + 1:
        entries = [
            (collection_id, nav_value),
            *(item for item in previous_entries if item[0] != collection_id),
        ]
    else:
        raise ValueError("NAV registry version transition is invalid")
    root = collection_nav_root(entries)
    current_inner = inner_mod.curry(
        inner_args[0], inner_args[1], root, new_version
    )
    current_full = full_mod.curry(full_args[0], current_inner)
    if _hex(current_full.get_tree_hash()) != tip.live.puzzle_hash:
        raise ValueError("reconstructed NAV registry does not match the live coin")
    return NavRegistryState(
        live_coin_id=tip.live.coin_id,
        live_puzzle_hash=tip.live.puzzle_hash,
        collection_nav_root=_hex(root),
        registry_version=new_version,
        entries={_hex(key): value for key, value in entries},
        confirmed_height=tip.live.confirmed_height,
    )


def _decode_pool_deed(
    puzzle_solution: Mapping[str, Any],
    tip: SingletonTip,
    *,
    expected_pool_launcher_id: str,
) -> PoolDeed:
    full = _program(str(puzzle_solution["puzzle_reveal"]))
    full_uncurried = full.uncurry()
    if full_uncurried is None:
        raise ValueError("SmartDeed puzzle is not a curried singleton")
    full_mod, full_args_program = full_uncurried
    full_args = list(full_args_program.as_iter())
    if len(full_args) != 2 or full_mod.get_tree_hash() != SINGLETON_MOD_HASH:
        raise ValueError("SmartDeed is not a canonical singleton")
    old_inner = full_args[1]
    inner_uncurried = old_inner.uncurry()
    if inner_uncurried is None:
        raise ValueError("SmartDeed inner puzzle is not curried")
    inner_mod, inner_args_program = inner_uncurried
    inner_args = list(inner_args_program.as_iter())
    if (
        len(inner_args) != 15
        or inner_mod.get_tree_hash()
        != load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
    ):
        raise ValueError("SmartDeed V2 inner puzzle must have 15 arguments")
    _, inner_solution = _solution_parts(
        str(puzzle_solution["solution"]), "SmartDeed"
    )
    if len(inner_solution) != 5:
        raise ValueError("SmartDeed inner solution must have five items")
    if int(inner_solution[3].as_int()) != DEED_SPEND_POOL_DEPOSIT:
        raise ValueError("live SmartDeed is not in pool custody")

    deed_struct = inner_args[0]
    struct_values = list(deed_struct.as_iter())
    if len(struct_values) != 2:
        raise ValueError("SmartDeed singleton struct is malformed")
    launcher_pair = list(struct_values[1].as_iter())
    if len(launcher_pair) != 2:
        raise ValueError("SmartDeed launcher pair is malformed")
    deed_launcher_id = bytes32(launcher_pair[0].as_atom())
    pool_launcher_id = bytes32(inner_args[11].as_atom())
    if _hex(pool_launcher_id) != _hex32(
        expected_pool_launcher_id, "expected pool launcher id"
    ):
        raise ValueError("SmartDeed is committed to a different pool")
    p2_pool_mod_hash = bytes32(inner_args[13].as_atom())
    if p2_pool_mod_hash != canonical_p2_pool_mod_hash():
        raise ValueError("SmartDeed uses a retired pool custody module")

    par_value = int(inner_args[2].as_int())
    asset_class = int(inner_args[3].as_int())
    property_id = bytes32(inner_args[4].as_atom())
    collection_id = bytes32(inner_args[5].as_atom())
    share_ppm = int(inner_args[6].as_int())
    commitment = deed_metadata_commitment(
        deed_launcher_id,
        par_value,
        asset_class,
        property_id,
        collection_id,
        share_ppm,
    )
    p2_pool = load_puzzle("p2_pool_v2.clsp").curry(
        p2_pool_mod_hash,
        bytes32(inner_args[10].as_atom()),
        pool_launcher_id,
        bytes32(inner_args[12].as_atom()),
        commitment,
    )
    current_full = full_mod.curry(full_args[0], p2_pool)
    if _hex(current_full.get_tree_hash()) != tip.live.puzzle_hash:
        raise ValueError("pool-custodied SmartDeed does not match the live coin")
    return PoolDeed(
        deed_coin_id=tip.live.coin_id,
        deed_launcher_id=_hex(deed_launcher_id),
        par_value_mojos=par_value,
        asset_class=asset_class,
        property_id_canon=_hex(property_id),
        collection_id_canon=_hex(collection_id),
        share_ppm=share_ppm,
        confirmed_height=tip.live.confirmed_height,
    )


class SolsMarketReader:
    def __init__(
        self,
        provider: ChiaProvider,
        store: CollectionStore,
        settings: Settings,
    ) -> None:
        self.provider = provider
        self.store = store
        self.settings = settings

    async def snapshot(self) -> dict[str, Any]:
        artifact = load_signed_public_artifact(self.settings)
        launchers = artifact["launcherIds"]
        puzzle_hashes = artifact["puzzleHashes"]
        pool_tip = await _singleton_tip(self.provider, str(launchers["pool"]))
        nav_tip = await _singleton_tip(self.provider, str(launchers["navRegistry"]))
        pool_solution = (
            await _latest_solution(self.provider, pool_tip) if pool_tip else None
        )
        nav_solution = (
            await _latest_solution(self.provider, nav_tip) if nav_tip else None
        )
        pool = (
            _decode_pool_state(pool_solution, pool_tip)
            if pool_tip and pool_solution
            else None
        )
        nav = (
            _decode_nav_state(nav_solution, nav_tip)
            if nav_tip and nav_solution
            else None
        )

        opportunities: list[dict[str, Any]] = []
        rejected = 0
        for candidate in self.store.sols_market_candidates():
            try:
                collection = self.store.public_collection(candidate["collectionId"])
                if not collection["verification"]["chainReconstructed"]:
                    raise ValueError("collection metadata is not reconstructed")
                tip = await _singleton_tip(
                    self.provider, str(candidate["deedLauncherId"])
                )
                solution = (
                    await _latest_solution(self.provider, tip) if tip else None
                )
                if not tip or not solution:
                    raise ValueError("SmartDeed has no current pool-custody spend")
                deed = _decode_pool_deed(
                    solution,
                    tip,
                    expected_pool_launcher_id=str(launchers["pool"]),
                )
                if deed.deed_launcher_id.lower() != str(
                    candidate["deedLauncherId"]
                ).lower():
                    raise ValueError("SmartDeed launcher does not match collection")
                if deed.share_ppm != int(candidate["sharePpm"]):
                    raise ValueError("SmartDeed share does not match collection")
                if deed.par_value_mojos != int(candidate["parValueMojos"]):
                    raise ValueError("SmartDeed par value does not match collection")
                if pool is None or nav is None:
                    raise ValueError("pool or NAV registry has no confirmed state")
                nav_value = nav.entries.get(deed.collection_id_canon)
                if nav_value is None:
                    raise ValueError("collection has no current governed NAV")
                quote = quote_specific_deed_swap(
                    pool.economics(),
                    collection_nav_mojos=nav_value,
                    share_ppm=deed.share_ppm,
                )
                opportunities.append(
                    {
                        "deedId": candidate["deedId"],
                        "deedLauncherId": deed.deed_launcher_id,
                        "deedCoinId": deed.deed_coin_id,
                        "collectionId": candidate["collectionId"],
                        "collectionSlug": candidate["collectionSlug"],
                        "collectionTitle": candidate["collectionTitle"],
                        "collectionSummary": candidate["collectionSummary"],
                        "metadataRoot": candidate["metadataRoot"],
                        "propertyIdCanon": deed.property_id_canon,
                        "collectionIdCanon": deed.collection_id_canon,
                        "sharePpm": deed.share_ppm,
                        "parValueMojos": str(deed.par_value_mojos),
                        "assetClass": deed.asset_class,
                        "navValueMojos": str(nav_value),
                        "deedNavMojos": str(quote.deed_nav_mojos),
                        "principalSolsMojos": str(quote.principal_tokens),
                        "protocolFeeSolsMojos": str(
                            quote.fee_split.protocol_fee_tokens
                        ),
                        "governanceFeeSolsMojos": str(
                            quote.fee_split.governance_fee_tokens
                        ),
                        "totalSolsMojos": str(quote.buyer_total_tokens),
                        "chainVerified": True,
                        "confirmedHeight": deed.confirmed_height,
                    }
                )
            except (KeyError, TypeError, ValueError):
                rejected += 1

        if pool is None or nav is None:
            outcome = "WAITING"
            title = "SOLS liquidity is waiting for its first confirmed pool state"
            body = "No customer swap is exposed until the pool and NAV registry reconstruct from Testnet11."
        elif pool.pool_status != POOL_ACTIVE:
            outcome = "PAUSED"
            title = "SOLS secondary swaps are paused"
            body = "The governed pool is frozen. Existing vault balances remain visible."
        elif not opportunities:
            outcome = "WAITING"
            title = "No SmartDeeds are available for SOLS yet"
            body = "A deed appears only after mint, primary delivery, pool deposit, and governed NAV confirmation."
        else:
            outcome = "READY"
            title = f"{len(opportunities)} SmartDeed swap{'s' if len(opportunities) != 1 else ''} available"
            body = "Prices are derived from the current governed NAV and Pool V3 state."
        visible_opportunities = (
            opportunities
            if pool is not None
            and nav is not None
            and pool.pool_status == POOL_ACTIVE
            else []
        )
        return {
            "schemaVersion": 1,
            "network": self.settings.network,
            "asset": {
                "symbol": "SOLS",
                "name": "Solslot Pool Token",
                "tailHash": puzzle_hashes["poolTokenTailHash"],
                "purpose": "secondary-smartdeed-swaps-only",
            },
            "outcome": outcome,
            "title": title,
            "body": body,
            "pool": asdict(pool) if pool else None,
            "navRegistry": asdict(nav) if nav else None,
            "opportunities": visible_opportunities,
            "verifiedOpportunityCount": len(visible_opportunities),
            "rejectedCandidateCount": rejected,
            "provider": self.provider.status(),
        }

    async def vault_balance(
        self, vault_launcher_id: str, pool_token_tail_hash: str
    ) -> int:
        inner = puzzle_for_p2_vault(
            bytes32.fromhex(_hex32(vault_launcher_id, "vault launcher").removeprefix("0x"))
        )
        cat = construct_cat_puzzle(
            CAT_MOD,
            bytes32.fromhex(
                _hex32(pool_token_tail_hash, "pool token tail").removeprefix("0x")
            ),
            inner,
        )
        records = await self.provider.get_coin_records_by_puzzle_hash(
            _hex(cat.get_tree_hash()), include_spent=False
        )
        return sum(int(item["coin"]["amount"]) for item in records)


def _reader(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> SolsMarketReader:
    provider = getattr(request.app.state, "coinset", None)
    if not isinstance(provider, ChiaProvider):
        raise HTTPException(status_code=503, detail="Chia provider is unavailable")
    return SolsMarketReader(provider, store, settings)


@router.get("/market")
async def sols_market(
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    try:
        return await reader.snapshot()
    except PublicArtifactMissing:
        return {
            "schemaVersion": 1,
            "network": "testnet11",
            "outcome": "LOCKED",
            "title": "SOLS secondary swaps begin after protocol launch",
            "body": "The signed genesis artifact is not installed. No swap inventory is exposed.",
            "pool": None,
            "navRegistry": None,
            "opportunities": [],
            "verifiedOpportunityCount": 0,
            "rejectedCandidateCount": 0,
        }
    except (ChiaProviderError, PublicArtifactError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SOLS market verification failed closed: {exc}",
        ) from exc


@router.get("/vaults/{vault_launcher_id}/opportunities")
async def vault_sols_opportunities(
    vault_launcher_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    session = verify_vault_session(settings, request, vault_launcher_id)
    approved = require_current_approved_vault(
        settings,
        session.vault_launcher_id,
    )
    record = require_vault_record(session.vault_launcher_id)
    try:
        snapshot = await reader.snapshot()
        tail_hash = str(snapshot["asset"]["tailHash"])
        balance = await reader.vault_balance(approved.launcher_id, tail_hash)
    except (
        ChiaProviderError,
        PublicArtifactError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SOLS vault verification failed closed: {exc}",
        ) from exc
    if record.auth_type != AUTH_TYPE_BLS:
        return {
            **snapshot,
            "vault": {
                "launcherId": approved.launcher_id,
                "eligible": False,
                "reason": "SOLS swaps currently require a Chia or Google BLS vault.",
                "balanceSolsMojos": str(balance),
                "identityConfirmed": True,
            },
            "opportunities": [],
            "verifiedOpportunityCount": 0,
        }
    return {
        **snapshot,
        "vault": {
            "launcherId": approved.launcher_id,
            "eligible": True,
            "reason": None,
            "balanceSolsMojos": str(balance),
            "identityConfirmed": True,
        },
        "opportunities": [
            {
                **item,
                "affordable": balance >= int(item["totalSolsMojos"]),
            }
            for item in snapshot["opportunities"]
        ],
    }


__all__ = [
    "PoolDeed",
    "PoolState",
    "SolsMarketReader",
    "router",
]
