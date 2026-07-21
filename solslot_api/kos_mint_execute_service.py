"""Independent evidence checks and signing for the KoS MINT capability.

This module deliberately has no spend-bundle endpoint and no generic BLS
operation. It recognizes one evidence shape: the MINT-only AGG_SIG_ME
condition committed by the signed governance artifact.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

import httpx
from chia_rs import AugSchemeMPL, Coin, PrivateKey
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from pydantic import BaseModel, ConfigDict, Field, field_validator

from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import (
    KOS_MINT_EXECUTE_TAG,
    PROTOCOL_PREFIX,
    kos_mint_execute_message,
    kos_mint_execute_signing_message,
)

from .faucet import AGG_SIG_ME_DATA
from .kos_mint_execute_ledger import KosMintExecuteLedger, KosMintExecuteLedgerConflict
from .kos_mint_execute_signer import request_hash
from .kos_mint_execute_settings import KosMintExecuteSignerSettings
from .public_artifact import PublicArtifactError, verify_signed_public_artifact_file
from .release_metadata import ReleaseMetadata, load_release_metadata


class KosMintExecuteEvidenceError(RuntimeError):
    """A request is not the one constrained governance MINT action."""


_VISIBLE_MESSAGE_SIZE = len(PROTOCOL_PREFIX) + len(KOS_MINT_EXECUTE_TAG) + 32
_SIGNING_MESSAGE_SIZE = _VISIBLE_MESSAGE_SIZE + 32 + 32


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


def _hex_value(value: str, size: int, field: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    if len(raw) != size:
        raise ValueError(f"{field} must be {size} bytes")
    return normalized


class KosMintExecuteClaim(BaseModel):
    """The full, fixed vocabulary accepted by the isolated signer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: Literal["governance-mint-execute-v1"]
    network: Literal["testnet11"]
    artifactHash: str
    proposalId: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9._-]+$")
    proposalHash: str
    governanceCoinId: str
    mintExecuteCosignerPubkey: str
    visibleMessage: str
    signingMessage: str

    @field_validator("artifactHash", "proposalHash", "governanceCoinId")
    @classmethod
    def _hex32(cls, value: str, info) -> str:
        return _hex_value(value, 32, info.field_name)

    @field_validator("mintExecuteCosignerPubkey")
    @classmethod
    def _pubkey(cls, value: str) -> str:
        return _hex_value(value, 48, "mintExecuteCosignerPubkey")

    @field_validator("visibleMessage")
    @classmethod
    def _visible_message(cls, value: str) -> str:
        # ``PROTOCOL_PREFIX || b\"KOSM\" || sha256tree(...)``.
        return _hex_value(value, _VISIBLE_MESSAGE_SIZE, "visibleMessage")

    @field_validator("signingMessage")
    @classmethod
    def _signing_message(cls, value: str) -> str:
        # Visible condition payload plus the live coin id and AGG_SIG_ME
        # additional data.
        return _hex_value(value, _SIGNING_MESSAGE_SIZE, "signingMessage")

    def canonical_payload(self) -> dict[str, str]:
        return {
            "capability": self.capability,
            "network": self.network,
            "artifactHash": self.artifactHash,
            "proposalId": self.proposalId,
            "proposalHash": self.proposalHash,
            "governanceCoinId": self.governanceCoinId,
            "mintExecuteCosignerPubkey": self.mintExecuteCosignerPubkey,
            "visibleMessage": self.visibleMessage,
            "signingMessage": self.signingMessage,
        }

    def canonical_request(self) -> str:
        return json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )

    def request_hash(self) -> str:
        return request_hash(self.canonical_payload())


@dataclass(frozen=True)
class KosMintExecuteEvidence:
    claim: KosMintExecuteClaim
    private_key: PrivateKey
    artifact: dict[str, Any]
    release: ReleaseMetadata


def _is_protected_systemd_credential(path: Path, mode: int) -> bool:
    credentials_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not credentials_directory:
        return False
    try:
        directory = Path(credentials_directory)
        directory_stat = directory.stat()
        path_stat = path.stat()
        if path.parent.resolve(strict=True) != directory.resolve(strict=True):
            return False
    except OSError:
        return False
    forbidden_file_bits = (
        stat.S_IWUSR | stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO
    )
    forbidden_directory_bits = stat.S_IWGRP | stat.S_IRWXO
    return (
        bool(mode & stat.S_IRUSR)
        and not mode & forbidden_file_bits
        and not stat.S_IMODE(directory_stat.st_mode) & forbidden_directory_bits
        and path_stat.st_uid == directory_stat.st_uid
        and path_stat.st_gid == directory_stat.st_gid
    )


def load_kos_mint_execute_private_key(settings: KosMintExecuteSignerSettings) -> PrivateKey:
    """Load one exact serialized BLS key from a protected credential file."""
    path = Path(settings.private_key_file)
    if path.is_symlink() or not path.is_file():
        raise KosMintExecuteEvidenceError("KoS private-key credential is missing or is a symlink")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO) and not _is_protected_systemd_credential(path, mode):
        raise KosMintExecuteEvidenceError(
            "KoS private-key credential must not be accessible by group/other"
        )
    try:
        raw = bytes.fromhex(path.read_text(encoding="ascii").strip().removeprefix("0x"))
        private_key = PrivateKey.from_bytes(raw)
    except (OSError, UnicodeError, ValueError) as exc:
        raise KosMintExecuteEvidenceError(
            "KoS private-key credential is unreadable or invalid"
        ) from exc
    if len(raw) != 32:
        raise KosMintExecuteEvidenceError(
            "KoS private-key credential must contain exactly 32 bytes of hex"
        )
    return private_key


def load_kos_mint_execute_artifact(
    settings: KosMintExecuteSignerSettings,
) -> tuple[dict[str, Any], ReleaseMetadata]:
    try:
        artifact = verify_signed_public_artifact_file(settings.public_artifact_path)
    except PublicArtifactError as exc:
        raise KosMintExecuteEvidenceError(str(exc)) from exc
    try:
        release = load_release_metadata(settings.release_metadata_path)
    except (OSError, ValueError) as exc:
        raise KosMintExecuteEvidenceError("KoS signer release metadata is invalid") from exc
    if release is None:
        raise KosMintExecuteEvidenceError("KoS signer release metadata is missing")
    source_shas = artifact.get("sourceShas")
    if not isinstance(source_shas, Mapping):
        raise KosMintExecuteEvidenceError("signed artifact source commits are missing")
    if source_shas.get("api") != release.apiCommit:
        raise KosMintExecuteEvidenceError("signed artifact API commit does not match KoS signer")
    if source_shas.get("protocol") != release.protocolCommit:
        raise KosMintExecuteEvidenceError(
            "signed artifact protocol commit does not match KoS signer"
        )
    if artifact.get("network") != settings.network:
        raise KosMintExecuteEvidenceError("signed artifact network does not match KoS signer")
    return artifact, release


def _coin_from_record(record: Mapping[str, Any]) -> Coin:
    coin = record.get("coin")
    if not isinstance(coin, Mapping):
        raise KosMintExecuteEvidenceError("governance coin record is malformed")
    try:
        return Coin(
            bytes32.fromhex(str(coin["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(coin["puzzle_hash"]).removeprefix("0x")),
            uint64(int(coin["amount"])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise KosMintExecuteEvidenceError("governance coin record is malformed") from exc


def _fetch_unspent_governance_coin(
    settings: KosMintExecuteSignerSettings, governance_coin_id: str
) -> Coin:
    try:
        with httpx.Client(
            base_url=settings.coinset_base_url,
            timeout=settings.coinset_timeout_seconds,
            headers={"content-type": "application/json"},
            trust_env=False,
        ) as client:
            response = client.post(
                "/get_coin_record_by_name", json={"name": governance_coin_id}
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise KosMintExecuteEvidenceError("Coinset could not verify governance coin") from exc
    record = payload.get("coin_record") if isinstance(payload, Mapping) else None
    if not isinstance(record, Mapping):
        raise KosMintExecuteEvidenceError("governance coin is not confirmed on Chia")
    if int(record.get("confirmed_block_index") or 0) <= 0:
        raise KosMintExecuteEvidenceError("governance coin is not confirmed on Chia")
    if bool(record.get("spent")) or int(record.get("spent_block_index") or 0) != 0:
        raise KosMintExecuteEvidenceError("governance coin is already spent")
    coin = _coin_from_record(record)
    if _hex(bytes(coin.name())) != governance_coin_id:
        raise KosMintExecuteEvidenceError("governance coin id does not match Coinset fields")
    return coin


def verify_kos_mint_execute_claim(
    settings: KosMintExecuteSignerSettings,
    claim: KosMintExecuteClaim,
) -> KosMintExecuteEvidence:
    """Independently bind a claim to static artifact and live chain state."""
    artifact, release = load_kos_mint_execute_artifact(settings)
    if claim.artifactHash != str(artifact.get("artifactHash", "")).lower():
        raise KosMintExecuteEvidenceError("claim artifact hash is not the active signed artifact")
    governance = artifact.get("governanceStruct")
    launchers = artifact.get("launcherIds")
    puzzle_hashes = artifact.get("puzzleHashes")
    if not all(isinstance(value, Mapping) for value in (governance, launchers, puzzle_hashes)):
        raise KosMintExecuteEvidenceError("signed artifact governance bindings are incomplete")
    try:
        cosigner_pubkey = bytes.fromhex(
            str(governance["mintExecuteCosignerPubkey"]).removeprefix("0x")
        )
        governance_launcher_id = bytes32.fromhex(
            str(launchers["governance"]).removeprefix("0x")
        )
        governance_full_puzzle_hash = bytes32.fromhex(
            str(puzzle_hashes["governanceFullPuzzleHash"]).removeprefix("0x")
        )
        proposal_hash = bytes32.fromhex(claim.proposalHash.removeprefix("0x"))
        governance_coin_id = bytes32.fromhex(claim.governanceCoinId.removeprefix("0x"))
    except (KeyError, TypeError, ValueError) as exc:
        raise KosMintExecuteEvidenceError("signed artifact governance bindings are malformed") from exc
    if len(cosigner_pubkey) != 48 or claim.mintExecuteCosignerPubkey != _hex(cosigner_pubkey):
        raise KosMintExecuteEvidenceError("claim co-signer public key does not match artifact")

    private_key = load_kos_mint_execute_private_key(settings)
    if bytes(private_key.get_g1()) != cosigner_pubkey:
        raise KosMintExecuteEvidenceError(
            "KoS private-key credential does not match signed artifact"
        )
    coin = _fetch_unspent_governance_coin(settings, claim.governanceCoinId)
    if bytes32(coin.name()) != governance_coin_id:
        raise KosMintExecuteEvidenceError("governance coin name is inconsistent")
    if coin.puzzle_hash != governance_full_puzzle_hash or int(coin.amount) != 1:
        raise KosMintExecuteEvidenceError(
            "live coin is not the signed governance singleton successor"
        )

    singleton = singleton_struct(governance_launcher_id)
    visible_message = kos_mint_execute_message(
        governance_singleton_struct=singleton,
        governance_coin_id=governance_coin_id,
        proposal_hash=proposal_hash,
    )
    additional_data = AGG_SIG_ME_DATA[settings.network]
    signing_message = kos_mint_execute_signing_message(
        governance_singleton_struct=singleton,
        governance_coin_id=governance_coin_id,
        proposal_hash=proposal_hash,
        agg_sig_me_additional_data=bytes32(additional_data),
    )
    if claim.visibleMessage != _hex(visible_message):
        raise KosMintExecuteEvidenceError("claim visible message is not the MINT governance message")
    if claim.signingMessage != _hex(signing_message):
        raise KosMintExecuteEvidenceError("claim AGG_SIG_ME message is not canonical")
    return KosMintExecuteEvidence(
        claim=claim,
        private_key=private_key,
        artifact=artifact,
        release=release,
    )


def sign_kos_mint_execute_claim(
    settings: KosMintExecuteSignerSettings,
    ledger: KosMintExecuteLedger,
    claim: KosMintExecuteClaim,
) -> str:
    """Return a replay-safe signature for exactly one live MINT execution."""
    evidence = verify_kos_mint_execute_claim(settings, claim)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            evidence.private_key,
            bytes.fromhex(claim.signingMessage.removeprefix("0x")),
        )
    ).hex()
    try:
        return ledger.record_or_recover(
            request_hash=claim.request_hash(),
            canonical_request=claim.canonical_request(),
            governance_coin_id=claim.governanceCoinId,
            proposal_hash=claim.proposalHash,
            artifact_hash=claim.artifactHash,
            signature=signature,
        )
    except KosMintExecuteLedgerConflict as exc:
        raise KosMintExecuteEvidenceError(str(exc)) from exc


__all__ = [
    "KosMintExecuteClaim",
    "KosMintExecuteEvidence",
    "KosMintExecuteEvidenceError",
    "load_kos_mint_execute_artifact",
    "load_kos_mint_execute_private_key",
    "sign_kos_mint_execute_claim",
    "verify_kos_mint_execute_claim",
]
