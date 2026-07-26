from __future__ import annotations

import pytest

from solslot_api.collection_display_units import (
    DisplayUnitError,
    allocate_par_mojos,
    dollars_to_minor,
    ownership_to_ppm,
    percentage_to_bps,
    usd_minor_to_asset_units,
)


def test_display_units_convert_exactly_without_float_rounding() -> None:
    assert dollars_to_minor("825000.09", label="market value") == "82500009"
    assert percentage_to_bps("2.50", label="technology fee", maximum_bps=1000) == "250"
    assert ownership_to_ppm("33.3333", label="ownership") == 333_333
    assert usd_minor_to_asset_units(
        50_000_000,
        price_usd_minor_per_asset=200_000,
        asset_decimals=12,
    ) == 250_000_000_000_000


@pytest.mark.parametrize("value", ["1e3", "1,000", "-1", "01", ".5", "1.001"])
def test_money_rejects_ambiguous_or_overprecise_values(value: str) -> None:
    with pytest.raises(DisplayUnitError):
        dollars_to_minor(value, label="amount")


def test_fee_and_share_bounds_are_enforced() -> None:
    with pytest.raises(DisplayUnitError):
        percentage_to_bps("10.01", label="technology fee", maximum_bps=1000)
    with pytest.raises(DisplayUnitError):
        ownership_to_ppm("100.0001", label="ownership")


def test_deed_par_uses_deterministic_largest_remainders() -> None:
    allocation = allocate_par_mojos(
        10,
        {"deed.0": 333_333, "deed.1": 333_333, "deed.2": 333_334},
    )
    assert allocation == {"deed.0": 3, "deed.1": 3, "deed.2": 4}
    assert sum(allocation.values()) == 10


def test_deed_par_requires_exact_100_percent() -> None:
    with pytest.raises(DisplayUnitError, match="exactly 100%"):
        allocate_par_mojos(10, {"deed.0": 500_000})
