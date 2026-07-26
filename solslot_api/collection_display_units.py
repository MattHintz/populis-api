"""Strict owner-facing unit conversion for collection drafts.

The canonical dossier deliberately stores integers.  Administrators work in
dollars, percentages, and ownership shares; this module is the sole boundary
that converts those display values into protocol storage units.
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Mapping


_DISPLAY_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
MAX_UINT64 = (1 << 64) - 1
TARGET_ALLOCATION_PPM = 1_000_000


class DisplayUnitError(ValueError):
    """Raised when a human-readable amount cannot be represented exactly."""


def scaled_integer(
    value: str,
    *,
    label: str,
    decimal_places: int,
    maximum: int = MAX_UINT64,
) -> int:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 40
        or not value.isascii()
        or not _DISPLAY_DECIMAL.fullmatch(value)
    ):
        raise DisplayUnitError(
            f"{label} must be a plain non-negative decimal without commas or exponent notation"
        )
    whole, dot, fraction = value.partition(".")
    if dot and len(fraction) > decimal_places:
        raise DisplayUnitError(
            f"{label} supports at most {decimal_places} decimal places"
        )
    scaled = int(whole) * (10**decimal_places)
    if fraction:
        scaled += int(fraction.ljust(decimal_places, "0"))
    if scaled > maximum:
        raise DisplayUnitError(f"{label} is too large")
    return scaled


def dollars_to_minor(value: str, *, label: str) -> str:
    return str(scaled_integer(value, label=label, decimal_places=2))


def percentage_to_bps(
    value: str,
    *,
    label: str,
    maximum_bps: int = 10_000,
) -> str:
    return str(
        scaled_integer(
            value,
            label=label,
            decimal_places=2,
            maximum=maximum_bps,
        )
    )


def ownership_to_ppm(value: str, *, label: str) -> int:
    return scaled_integer(
        value,
        label=label,
        decimal_places=4,
        maximum=TARGET_ALLOCATION_PPM,
    )


def usd_minor_to_asset_units(
    usd_minor: int,
    *,
    price_usd_minor_per_asset: int,
    asset_decimals: int,
) -> int:
    if usd_minor < 0:
        raise DisplayUnitError("USD amount cannot be negative")
    if price_usd_minor_per_asset <= 0:
        raise DisplayUnitError("oracle price must be positive")
    if asset_decimals < 0 or asset_decimals > 18:
        raise DisplayUnitError("oracle asset decimals are unsupported")
    numerator = usd_minor * (10**asset_decimals)
    amount = (numerator + price_usd_minor_per_asset - 1) // price_usd_minor_per_asset
    if amount > MAX_UINT64:
        raise DisplayUnitError("oracle-derived protocol amount exceeds uint64")
    return amount


def allocate_par_mojos(
    collection_par_mojos: int,
    ownership_ppm: Mapping[str, int],
) -> dict[str, int]:
    """Allocate collection par exactly with deterministic largest remainders."""

    if collection_par_mojos <= 0:
        raise DisplayUnitError("collection par must be positive")
    if not ownership_ppm:
        return {}
    if sum(ownership_ppm.values()) != TARGET_ALLOCATION_PPM:
        raise DisplayUnitError("ownership shares must total exactly 100%")

    allocated: dict[str, int] = {}
    remainders: list[tuple[int, str]] = []
    used = 0
    for key in sorted(ownership_ppm):
        share = ownership_ppm[key]
        if share <= 0 or share > TARGET_ALLOCATION_PPM:
            raise DisplayUnitError(f"ownership share {key} is outside 0-100%")
        numerator = collection_par_mojos * share
        amount, remainder = divmod(numerator, TARGET_ALLOCATION_PPM)
        allocated[key] = amount
        used += amount
        remainders.append((remainder, key))

    for _remainder, key in sorted(remainders, key=lambda item: (-item[0], item[1]))[
        : collection_par_mojos - used
    ]:
        allocated[key] += 1
    if any(value <= 0 for value in allocated.values()):
        raise DisplayUnitError("each deed must receive a positive protocol par value")
    if sum(allocated.values()) != collection_par_mojos:
        raise DisplayUnitError("deed par allocation does not equal collection par")
    return allocated


__all__ = [
    "DisplayUnitError",
    "allocate_par_mojos",
    "dollars_to_minor",
    "ownership_to_ppm",
    "percentage_to_bps",
    "scaled_integer",
    "usd_minor_to_asset_units",
]
