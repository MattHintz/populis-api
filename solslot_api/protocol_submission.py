"""Mempool-aware Chia submission funded by the existing server fee till."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import G2Element, SpendBundle

from .chia_provider import ChiaProvider, ChiaProviderError
from .faucet import Faucet

CREATE_COIN = 51
RESERVE_FEE = 52


class ProtocolSubmissionError(RuntimeError):
    """A server-funded protocol bundle cannot be safely submitted."""

    def __init__(
        self,
        message: str,
        *,
        submission_attempted: bool = False,
    ) -> None:
        super().__init__(message)
        self.submission_attempted = submission_attempted


@dataclass(frozen=True)
class ProtocolFeePolicy:
    enabled: bool = False
    target_seconds: int = 300
    minimum_mojos: int = 1
    maximum_mojos: int = 10_000_000
    maximum_funding_coin_mojos: int = 10_000_000
    mempool_timeout_seconds: float = 20.0
    mempool_poll_seconds: float = 0.5


class ProtocolBundleSubmitter:
    """Add one bounded fee-till spend and prove local mempool propagation."""

    def __init__(
        self,
        *,
        provider: ChiaProvider,
        faucet: Faucet,
        policy: ProtocolFeePolicy,
    ) -> None:
        self.provider = provider
        self.faucet = faucet
        self.policy = policy
        self._lock = asyncio.Lock()

    async def submit(self, protocol_bundle_json: dict[str, Any]) -> dict[str, Any]:
        if not self.policy.enabled:
            raise ProtocolSubmissionError("protocol fee funding is disabled")
        try:
            protocol_bundle = SpendBundle.from_json_dict(protocol_bundle_json)
        except Exception as exc:
            raise ProtocolSubmissionError("protocol spend bundle is malformed") from exc
        if not protocol_bundle.coin_spends:
            raise ProtocolSubmissionError("protocol spend bundle has no coin spends")
        try:
            existing_fee = sum(
                int(coin.amount) for coin in protocol_bundle.removals()
            ) - sum(int(coin.amount) for coin in protocol_bundle.additions())
        except Exception as exc:
            raise ProtocolSubmissionError(
                "protocol spend bundle conditions cannot be evaluated"
            ) from exc
        if existing_fee != 0:
            raise ProtocolSubmissionError(
                "protocol spend bundle must not carry a separate user-funded fee"
            )

        # Production keeps one worker for faucet-backed writes. Holding this
        # lock until mempool observation prevents reuse of an unconfirmed coin.
        async with self._lock:
            preliminary_fee = await self._estimate_fee(protocol_bundle)
            protocol_input_ids = {
                bytes(coin.name()) for coin in protocol_bundle.removals()
            }
            fee_coin = await self._select_fee_coin(
                preliminary_fee,
                excluded_coin_ids=protocol_input_ids,
            )
            final_bundle, fee = await self._converge_fee(
                protocol_bundle,
                fee_coin,
                preliminary_fee,
            )
            try:
                mempool = await self.provider.push_tx_confirmed_in_primary_mempool(
                    final_bundle.to_json_dict(),
                    required_coin_id="0x" + fee_coin.name().hex(),
                    timeout_seconds=self.policy.mempool_timeout_seconds,
                    poll_seconds=self.policy.mempool_poll_seconds,
                )
            except ChiaProviderError as exc:
                raise ProtocolSubmissionError(
                    str(exc),
                    submission_attempted=True,
                ) from exc

        return {
            "schemaVersion": 1,
            "status": "MEMPOOL",
            "network": self.faucet.network,
            "spendBundleId": "0x" + final_bundle.name().hex(),
            "feeMojos": str(fee),
            "feeTargetSeconds": self.policy.target_seconds,
            "feeCoinId": "0x" + fee_coin.name().hex(),
            "feeTillPuzzleHash": self.faucet.address_hex,
            "submissionProvider": mempool["provider"],
            "mempoolObservedAt": mempool["observed_at"],
            "ambiguousPushRecovered": bool(mempool["ambiguous_push"]),
            "spendBundle": final_bundle.to_json_dict(),
        }

    async def _estimate_fee(self, bundle: SpendBundle) -> int:
        try:
            response = await self.provider.get_fee_estimate(
                target_times=[self.policy.target_seconds],
                spend_bundle=bundle.to_json_dict(),
                require_primary=True,
            )
        except ChiaProviderError as exc:
            raise ProtocolSubmissionError(str(exc)) from exc
        estimates = response.get("estimates")
        target_times = response.get("target_times")
        if (
            not isinstance(estimates, list)
            or len(estimates) != 1
            or not isinstance(target_times, list)
            or target_times != [self.policy.target_seconds]
        ):
            raise ProtocolSubmissionError("local node returned a malformed fee estimate")
        raw_estimate = estimates[0]
        if isinstance(raw_estimate, bool) or not isinstance(raw_estimate, int):
            raise ProtocolSubmissionError(
                "local node returned a non-integer fee estimate"
            )
        estimate = raw_estimate
        if estimate < 0:
            raise ProtocolSubmissionError("local node returned a negative fee estimate")
        fee = max(estimate, self.policy.minimum_mojos)
        if fee > self.policy.maximum_mojos:
            raise ProtocolSubmissionError(
                f"medium fee {fee} exceeds configured cap "
                f"{self.policy.maximum_mojos}"
            )
        return fee

    async def _select_fee_coin(
        self,
        fee: int,
        *,
        excluded_coin_ids: set[bytes],
    ):
        try:
            records = await self.provider.get_coin_records_by_puzzle_hash(
                self.faucet.address_hex,
                include_spent=False,
            )
        except ChiaProviderError as exc:
            raise ProtocolSubmissionError(str(exc)) from exc

        available: list[dict[str, Any]] = []
        for record in records:
            try:
                coin = self.faucet.select_coin(
                    [record],
                    min_amount=fee,
                    max_amount=self.policy.maximum_funding_coin_mojos,
                )
            except (KeyError, TypeError, ValueError):
                continue
            if coin is None:
                continue
            if bytes(coin.name()) in excluded_coin_ids:
                continue
            try:
                pending = await self.provider.get_mempool_items_by_coin_name(
                    "0x" + coin.name().hex()
                )
            except ChiaProviderError as exc:
                raise ProtocolSubmissionError(str(exc)) from exc
            if not pending:
                available.append(record)

        selected = self.faucet.select_coin(
            available,
            min_amount=fee,
            max_amount=self.policy.maximum_funding_coin_mojos,
        )
        if selected is None:
            raise ProtocolSubmissionError(
                "protocol fee till has no eligible confirmed, unreserved coin"
            )
        return selected

    async def _converge_fee(
        self,
        protocol_bundle: SpendBundle,
        fee_coin,
        preliminary_fee: int,
    ) -> tuple[SpendBundle, int]:
        fee = preliminary_fee
        for _ in range(3):
            if fee > int(fee_coin.amount):
                raise ProtocolSubmissionError(
                    "selected protocol fee coin is smaller than the medium fee"
                )
            aggregate = SpendBundle.aggregate(
                [protocol_bundle, self._fee_bundle(fee_coin, fee)]
            )
            estimated = await self._estimate_fee(aggregate)
            next_fee = max(fee, estimated)
            if next_fee == fee:
                return aggregate, fee
            fee = next_fee
        raise ProtocolSubmissionError("medium fee estimate did not converge")

    def _fee_bundle(self, coin, fee: int) -> SpendBundle:
        conditions = [Program.to([RESERVE_FEE, fee])]
        change = int(coin.amount) - fee
        if change:
            conditions.insert(
                0,
                Program.to(
                    [CREATE_COIN, self.faucet.address_puzzle_hash, change]
                ),
            )
        condition_program = Program.to(conditions)
        delegated = Program.to((1, condition_program))
        solution = Program.to([0, delegated, Program.to(0)])
        spend = make_spend(coin, self.faucet.key.puzzle, solution)
        signature = G2Element.from_bytes(
            self.faucet.sign_delegated_spend(coin, condition_program)
        )
        return SpendBundle([spend], signature)


__all__ = [
    "ProtocolBundleSubmitter",
    "ProtocolFeePolicy",
    "ProtocolSubmissionError",
]
