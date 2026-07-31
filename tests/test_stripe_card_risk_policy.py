from __future__ import annotations

from types import SimpleNamespace

import pytest

from solslot_api.validator_service import (
    ValidatorEvidenceError,
    _validate_stripe_card_risk,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseKind,
    StripeMethodFamily,
)


def _settings(**overrides):
    values = {
        "stripe_reject_highest_risk": True,
        "stripe_require_direct_card_3ds": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _artifact(kind: PurchaseKind):
    return SimpleNamespace(purchase_kind=kind)


def _charge(*, risk_level: str = "normal", result: str = "authenticated"):
    return {
        "outcome": {"risk_level": risk_level},
        "payment_method_details": {
            "card": {"three_d_secure": {"result": result}}
        },
    }


def test_highest_risk_card_is_rejected_for_presale_and_direct() -> None:
    for kind in (PurchaseKind.PRESALE, PurchaseKind.DIRECT):
        with pytest.raises(ValidatorEvidenceError, match="highest risk"):
            _validate_stripe_card_risk(
                _settings(),
                artifact=_artifact(kind),
                method_family=StripeMethodFamily.CARD,
                charge=_charge(risk_level="highest"),
            )


def test_direct_card_requires_authenticated_3ds() -> None:
    for result in ("", "failed", "attempt_acknowledged", "not_supported"):
        with pytest.raises(ValidatorEvidenceError, match="authenticated 3DS"):
            _validate_stripe_card_risk(
                _settings(),
                artifact=_artifact(PurchaseKind.DIRECT),
                method_family=StripeMethodFamily.CARD,
                charge=_charge(result=result),
            )


def test_authenticated_direct_card_and_normal_presale_card_pass() -> None:
    _validate_stripe_card_risk(
        _settings(),
        artifact=_artifact(PurchaseKind.DIRECT),
        method_family=StripeMethodFamily.CARD,
        charge=_charge(),
    )
    _validate_stripe_card_risk(
        _settings(),
        artifact=_artifact(PurchaseKind.PRESALE),
        method_family=StripeMethodFamily.CARD,
        charge=_charge(result="not_supported"),
    )


def test_ach_does_not_enter_card_risk_policy() -> None:
    _validate_stripe_card_risk(
        _settings(),
        artifact=_artifact(PurchaseKind.PRESALE),
        method_family=StripeMethodFamily.US_BANK_ACCOUNT,
        charge=None,
    )
