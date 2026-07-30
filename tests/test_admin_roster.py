from __future__ import annotations

from eth_account import Account

from solslot_api.admin_roster import (
    artifact_admins,
    current_artifact_admins,
)
from solslot_api.public_artifact import PublicArtifactError


ACCOUNTS = [
    Account.from_key("0x" + f"{index:064x}")
    for index in (101, 102, 103, 104)
]


def _compressed(account) -> str:
    return "0x" + account._key_obj.public_key.to_compressed_bytes().hex()


def _artifact() -> dict:
    return {
        "ceremony": {"ceremonyId": "0x" + "11" * 32},
        "adminAuthority": {
            "version": 3,
            "identityVaults": [
                {
                    "slot": slot,
                    "dailyCompressedPubkey": _compressed(account),
                }
                for slot, account in enumerate(ACCOUNTS[:3])
            ],
        },
    }


class FakeStore:
    def __init__(self, cases: list[dict]) -> None:
        self._cases = cases

    def recovery_cases(self, ceremony_id: str) -> list[dict]:
        assert ceremony_id == "0x" + "11" * 32
        return self._cases


def test_original_authority_v3_roster_is_derived_from_identity_vaults() -> None:
    roster = artifact_admins(_artifact())

    assert [address for address, _ in roster] == [
        account.address.lower() for account in ACCOUNTS[:3]
    ]


def test_only_completed_cross_chain_rotation_replaces_login_identity() -> None:
    replacement = ACCOUNTS[3]
    pending = {
        "state": "CHIA_CONFIRMED",
        "kind": "ROUTINE",
        "intent": {
            "slot": 1,
            "newDailyEvmKey": replacement.address,
            "newDailyChiaKey": _compressed(replacement),
        },
    }
    completed = {**pending, "state": "COMPLETED"}

    before = current_artifact_admins(_artifact(), FakeStore([pending]))
    after = current_artifact_admins(_artifact(), FakeStore([completed]))

    assert before[1][0] == ACCOUNTS[1].address.lower()
    assert after[1] == (
        replacement.address.lower(),
        _compressed(replacement).lower(),
    )
    assert ACCOUNTS[1].address.lower() not in {value for row in after for value in row}


def test_completed_rotation_must_bind_address_to_compressed_key() -> None:
    with __import__("pytest").raises(
        PublicArtifactError,
        match="does not bind one daily identity",
    ):
        current_artifact_admins(
            _artifact(),
            FakeStore(
                [
                    {
                        "state": "COMPLETED",
                        "kind": "LOST",
                        "intent": {
                            "slot": 0,
                            "newDailyEvmKey": ACCOUNTS[3].address,
                            "newDailyChiaKey": _compressed(ACCOUNTS[2]),
                        },
                    }
                ]
            ),
        )
