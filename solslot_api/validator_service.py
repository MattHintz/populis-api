"""Independent evidence verification for a private validator signer."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Mapping

import httpx
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.trading.offer import Offer
from chia_rs import AugSchemeMPL, Coin, G1Element, G2Element, PrivateKey
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    DEFAULT_IDENTITY_ATTEST_ROOT,
    eip712_typed_data_for_vault_spend,
    one_leaf_merkle_root,
    puzzle_for_vault_full,
)
from solslot_puzzles.mint_publish_driver import (
    deed_singleton_struct,
)
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentRail,
    purchase_artifact_from_json,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    PRIMARY_PURCHASE_PROVIDER_ID,
    PrimaryMintTermsV2,
    make_mint_offer_v2_inner,
    validate_chia_buyer_offer,
)
from solslot_puzzles.protocol_deployment import singleton_struct

from .config import Settings
from .evm_auth import recover_evm_signer
from .faucet import AGG_SIG_ME_DATA
from .public_artifact import (
    PublicArtifactError,
    verify_signed_public_artifact_file,
)
from .release_metadata import ReleaseMetadata, load_release_metadata
from .validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from .validator_quorum import PrimaryPurchaseClaim, ValidatorClaim
from .validator_settings import ValidatorSettings
from .zkpassport_enrollments import _fetch_verified_evm_attestation


class ValidatorEvidenceError(RuntimeError):
    """The coordinator claim is not independently provable."""


def _is_protected_systemd_credential(path: Path, mode: int) -> bool:
    """Recognize systemd's read-only credential mount across supported hosts."""
    credentials_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not credentials_directory or path.name != "validator-seed":
        return False
    try:
        directory = Path(credentials_directory)
        directory_stat = directory.stat()
        path_stat = path.stat()
        if path.parent.resolve(strict=True) != directory.resolve(strict=True):
            return False
    except OSError:
        return False

    # Ubuntu's id-mapped credential mount reports 0440/root:root to the
    # service while Amazon Linux reports 0400 owned by the service account.
    # In both cases the mount and credential are immutable to the signer.
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


def canonical_claim_json(claim: ValidatorClaim) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def load_validator_private_key(settings: ValidatorSettings) -> PrivateKey:
    """Load a BLS seed from a protected file and bind it to the roster."""
    path = Path(settings.seed_file)
    if path.is_symlink() or not path.is_file():
        raise ValidatorEvidenceError("validator seed file is missing or is a symlink")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO) and not _is_protected_systemd_credential(
        path, mode
    ):
        raise ValidatorEvidenceError("validator seed file must not be accessible by group/other")
    try:
        seed = bytes.fromhex(path.read_text(encoding="ascii").strip().removeprefix("0x"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValidatorEvidenceError("validator seed file is unreadable or invalid") from exc
    if len(seed) != 32:
        raise ValidatorEvidenceError("validator seed file must contain exactly 32 bytes of hex")
    private_key = AugSchemeMPL.key_gen(seed)
    expected = bytes.fromhex(
        settings.roster_pubkeys[settings.signer_index].removeprefix("0x")
    )
    if bytes(private_key.get_g1()) != expected:
        raise ValidatorEvidenceError("validator seed does not match its configured roster slot")
    return private_key


def load_validator_artifact(
    settings: ValidatorSettings,
) -> tuple[dict[str, Any], ReleaseMetadata]:
    try:
        artifact = verify_signed_public_artifact_file(settings.public_artifact_path)
    except PublicArtifactError as exc:
        raise ValidatorEvidenceError(str(exc)) from exc
    try:
        release = load_release_metadata(settings.release_metadata_path)
    except (OSError, ValueError) as exc:
        raise ValidatorEvidenceError("validator release metadata is invalid") from exc
    if release is None:
        raise ValidatorEvidenceError("validator release metadata is missing")

    source_shas = artifact.get("sourceShas")
    bridge = artifact.get("bridgePolicy")
    validators = artifact.get("validatorSet")
    addresses = artifact.get("evmAddresses")
    if not all(
        isinstance(value, Mapping)
        for value in (source_shas, bridge, validators, addresses)
    ):
        raise ValidatorEvidenceError("signed artifact runtime bindings are incomplete")
    checks = (
        (artifact.get("network"), settings.network, "network"),
        (artifact.get("evmChainId"), settings.evm_chain_id, "EVM chain"),
        (source_shas.get("api"), release.apiCommit, "API commit"),
        (source_shas.get("protocol"), release.protocolCommit, "protocol commit"),
        (bridge.get("policyHash"), settings.bridge_policy_hash, "bridge policy"),
        (validators.get("threshold"), 2, "validator threshold"),
        (validators.get("pubkeys"), settings.roster_pubkeys, "validator roster"),
        (
            str(addresses.get("forwarder", "")).lower(),
            settings.evm_forwarder_address,
            "forwarder",
        ),
        (
            str(addresses.get("verifierAdapter", "")).lower(),
            settings.evm_verifier_adapter_address,
            "verifier adapter",
        ),
        (
            str(addresses.get("attestationEmitter", "")).lower(),
            settings.evm_attestation_emitter_address,
            "attestation emitter",
        ),
    )
    for observed, expected, label in checks:
        if observed != expected:
            raise ValidatorEvidenceError(f"signed artifact {label} does not match signer config")
    return artifact, release


def _coin_from_record(record: Mapping[str, Any], field: str) -> Coin:
    coin = record.get("coin")
    if not isinstance(coin, Mapping):
        raise ValidatorEvidenceError(f"{field} record has no coin")
    try:
        return Coin(
            bytes32.fromhex(str(coin["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(coin["puzzle_hash"]).removeprefix("0x")),
            uint64(int(coin["amount"])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(f"{field} record is malformed") from exc


def _fetch_coin(
    settings: ValidatorSettings,
    coin_id: str,
    field: str,
    *,
    require_unspent: bool = True,
) -> Mapping[str, Any]:
    try:
        with httpx.Client(
            base_url=settings.coinset_base_url.rstrip("/"),
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post("/get_coin_record_by_name", json={"name": coin_id})
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValidatorEvidenceError(f"Coinset could not verify {field}") from exc
    record = payload.get("coin_record") if isinstance(payload, Mapping) else None
    if not isinstance(record, Mapping):
        raise ValidatorEvidenceError(f"{field} is not confirmed on Chia")
    if int(record.get("confirmed_block_index") or 0) <= 0:
        raise ValidatorEvidenceError(f"{field} is not confirmed on Chia")
    if require_unspent and (
        bool(record.get("spent"))
        or int(record.get("spent_block_index") or 0) != 0
    ):
        raise ValidatorEvidenceError(f"{field} is already spent")
    return record


def _verify_vault_and_owner(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
    claim: ValidatorClaim,
) -> None:
    if claim.owner_auth_type not in (AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1):
        raise ValidatorEvidenceError("vault authorization type is not supported for V2 stamps")
    if (
        claim.current_timestamp < 1
        or abs(int(time.time()) - claim.current_timestamp)
        > settings.claim_clock_skew_seconds
    ):
        raise ValidatorEvidenceError("vault action timestamp is stale or in the future")

    coin_record = _fetch_coin(settings, claim.current_vault_coin_id, "current vault coin")
    coin = _coin_from_record(coin_record, "current vault coin")
    if "0x" + bytes(coin.name()).hex() != claim.current_vault_coin_id:
        raise ValidatorEvidenceError("current vault coin id does not match Coinset fields")
    launcher = bytes32.fromhex(claim.vault_launcher_id.removeprefix("0x"))
    if coin.parent_coin_info != launcher or int(coin.amount) != 1:
        raise ValidatorEvidenceError("current vault coin is not the unstamped singleton successor")

    try:
        authorization = bytes.fromhex(claim.owner_authorization.removeprefix("0x"))
    except ValueError as exc:
        raise ValidatorEvidenceError("owner authorization is not hex") from exc
    if "0x" + hashlib.sha256(authorization).hexdigest() != claim.owner_authorization_hash:
        raise ValidatorEvidenceError("owner authorization hash does not match signature bytes")

    owner_pubkey: bytes
    if claim.owner_auth_type == AUTH_TYPE_SECP256K1:
        typed_data = eip712_typed_data_for_vault_spend(
            b"z",
            bytes32.fromhex(claim.identity_attest_root.removeprefix("0x")),
            coin.name(),
        )
        try:
            recovered = recover_evm_signer(typed_data, claim.owner_authorization)
        except ValueError as exc:
            raise ValidatorEvidenceError("EVM owner authorization is invalid") from exc
        if (
            claim.owner_key.lower() != recovered.address.lower()
        ):
            raise ValidatorEvidenceError("EVM owner authorization does not belong to this vault")
        owner_pubkey = recovered.compressed_pubkey
    else:
        try:
            signature = G2Element.from_bytes(authorization)
            owner_pubkey = bytes.fromhex(claim.owner_key.removeprefix("0x"))
            public_key = G1Element.from_bytes(owner_pubkey)
        except ValueError as exc:
            raise ValidatorEvidenceError("BLS owner authorization is malformed") from exc
        owner_inner_message = bytes(
            Program.to(
                [
                    b"z",
                    bytes32.fromhex(claim.identity_attest_root.removeprefix("0x")),
                    coin.name(),
                ]
            ).get_tree_hash()
        )
        owner_message = owner_inner_message + bytes(coin.name()) + AGG_SIG_ME_DATA[settings.network]
        if not AugSchemeMPL.verify(public_key, owner_message, signature):
            raise ValidatorEvidenceError("BLS owner authorization does not belong to this vault")

    try:
        pool_launcher = bytes32.fromhex(
            str(artifact["launcherIds"]["pool"]).removeprefix("0x")
        )
        bridge_policy_hash = bytes32.fromhex(
            claim.bridge_policy_hash.removeprefix("0x")
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError("artifact vault trust coordinates are invalid") from exc
    expected_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        claim.owner_auth_type,
        one_leaf_merkle_root(owner_pubkey),
        pool_launcher,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    if coin.puzzle_hash != bytes32(expected_puzzle.get_tree_hash()):
        raise ValidatorEvidenceError(
            "owner authorization does not reconstruct the current unstamped vault coin"
        )


def _verify_bridge_coin(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
    claim: ValidatorClaim,
) -> None:
    if claim.bridge_amount != 1:
        raise ValidatorEvidenceError("V2 genesis bridge coins must contain exactly one mojo")
    bridge = artifact.get("bridgePolicy")
    if not isinstance(bridge, Mapping):
        raise ValidatorEvidenceError("artifact bridge policy is missing")
    parent_ids = {str(value).lower() for value in bridge.get("parentCoinIds", [])}
    coin_ids = {str(value).lower() for value in bridge.get("bridgeCoinIds", [])}
    if claim.bridge_parent_id not in parent_ids or claim.bridge_coin_id not in coin_ids:
        raise ValidatorEvidenceError("bridge lineage is not committed by the signed artifact")
    record = _fetch_coin(settings, claim.bridge_coin_id, "bridge coin")
    coin = _coin_from_record(record, "bridge coin")
    expected = Coin(
        bytes32.fromhex(claim.bridge_parent_id.removeprefix("0x")),
        bytes32.fromhex(claim.bridge_policy_hash.removeprefix("0x")),
        uint64(claim.bridge_amount),
    )
    if coin != expected or "0x" + bytes(coin.name()).hex() != claim.bridge_coin_id:
        raise ValidatorEvidenceError("bridge coin fields or lineage do not match the claim")


def _coordinator_settings(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
) -> Settings:
    return Settings(
        runtime_environment="test",
        network=settings.network,
        coinset_base_url=settings.coinset_base_url,
        public_artifact_path=settings.public_artifact_path,
        release_metadata_path=settings.release_metadata_path,
        zkpassport_evm_rpc_url=settings.evm_rpc_url,
        zkpassport_evm_chain_id=settings.evm_chain_id,
        zkpassport_evm_min_confirmations=settings.evm_min_confirmations,
        zkpassport_validator_threshold=2,
        zkpassport_validator_pubkeys=list(settings.roster_pubkeys),
        zkpassport_bridge_policy_hash=settings.bridge_policy_hash,
        zkpassport_forwarder_address=settings.evm_forwarder_address,
        zkpassport_emitter_address=settings.evm_attestation_emitter_address,
        pool_launcher_id=str(artifact["launcherIds"]["pool"]),
    )


def verify_validator_claim(
    settings: ValidatorSettings,
    claim: ValidatorClaim,
    claim_hash: str,
) -> tuple[dict[str, Any], ReleaseMetadata]:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError("claim hash does not match canonical evidence")
    artifact, release = load_validator_artifact(settings)
    if claim.network != settings.network:
        raise ValidatorEvidenceError("claim network does not match signer")
    if claim.artifact_hash != str(artifact.get("artifactHash", "")).lower():
        raise ValidatorEvidenceError("claim artifact hash is not the active signed artifact")
    if claim.bridge_policy_hash != settings.bridge_policy_hash:
        raise ValidatorEvidenceError("claim bridge policy does not match signer")
    if claim.emitter_address.lower() != settings.evm_attestation_emitter_address:
        raise ValidatorEvidenceError("claim emitter is not the signed attestation emitter")

    event = _fetch_verified_evm_attestation(
        _coordinator_settings(settings, artifact),
        transaction_hash=claim.evm_transaction_hash,
        expected_vault_launcher_id=claim.vault_launcher_id,
    )
    event_fields = {
        "vault_launcher_id": claim.vault_launcher_id,
        "transaction_hash": claim.evm_transaction_hash,
        "block_number": claim.evm_block_number,
        "policy_version": claim.policy_version,
        "identity_attest_root": claim.identity_attest_root,
        "attestation_leaf_hash": claim.attestation_leaf_hash,
        "scoped_nullifier": claim.scoped_nullifier,
        "nullifier_type": claim.nullifier_type,
        "service_scope_hash": claim.service_scope_hash,
        "service_subscope_hash": claim.service_subscope_hash,
        "proof_timestamp": claim.proof_timestamp,
        "bridge_policy_hash": claim.bridge_policy_hash,
        "bridge_parent_id": claim.bridge_parent_id,
        "bridge_amount": claim.bridge_amount,
        "bridge_coin_id": claim.bridge_coin_id,
        "validator_message": claim.validator_message,
    }
    for field, expected in event_fields.items():
        if getattr(event, field) != expected:
            raise ValidatorEvidenceError(f"canonical EVM event {field} does not match claim")
    now = int(time.time())
    if claim.proof_timestamp > now or now - claim.proof_timestamp > settings.proof_max_age_seconds:
        raise ValidatorEvidenceError("zkPassport proof timestamp is stale or in the future")
    if claim.scoped_nullifier == "0x" + "00" * 32:
        raise ValidatorEvidenceError("scoped nullifier must be nonzero")
    if claim.service_scope_hash == "0x" + "00" * 32 or claim.service_subscope_hash == "0x" + "00" * 32:
        raise ValidatorEvidenceError("zkPassport scope commitments must be nonzero")

    _verify_vault_and_owner(settings, artifact, claim)
    if claim.owner_auth_type == AUTH_TYPE_SECP256K1 and event.sender.lower() != claim.owner_key.lower():
        raise ValidatorEvidenceError("EVM attestation sender is not the EVM vault owner")
    _verify_bridge_coin(settings, artifact, claim)
    return artifact, release


def sign_validator_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: ValidatorClaim,
    claim_hash: str,
) -> str:
    verify_validator_claim(settings, claim, claim_hash)
    private_key = load_validator_private_key(settings)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(private_key, claim.signature_message())
    ).hex()
    try:
        return ledger.record_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_claim_json(claim),
            scoped_nullifier=claim.scoped_nullifier,
            bridge_coin_id=claim.bridge_coin_id,
            vault_action=(
                f"{claim.vault_launcher_id}:{claim.current_vault_coin_id}:"
                f"{claim.identity_attest_root}:update_identity"
            ),
            evm_transaction_hash=claim.evm_transaction_hash,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_primary_purchase_claim_json(
    claim: PrimaryPurchaseClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def verify_primary_purchase_claim(
    settings: ValidatorSettings,
    claim: PrimaryPurchaseClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "purchase claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if claim.network != settings.network:
        raise ValidatorEvidenceError("purchase network does not match signer")
    if claim.genesis_artifact_hash != str(
        artifact.get("artifactHash", "")
    ).lower():
        raise ValidatorEvidenceError(
            "purchase does not reference the active signed artifact"
        )
    try:
        purchase = purchase_artifact_from_json(claim.purchase_artifact)
        purchase.assert_live(int(time.time()))
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "purchase artifact is invalid or expired"
        ) from exc
    if purchase.rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise ValidatorEvidenceError("purchase is not a native Chia rail")
    if "0x" + bytes(purchase.artifact_hash).hex() != (
        claim.purchase_artifact_hash()
    ):
        raise ValidatorEvidenceError("purchase artifact hash is not canonical")

    bridge = artifact.get("bridgePolicy")
    validator_set = artifact.get("validatorSet")
    launchers = artifact.get("launcherIds")
    puzzle_hashes = artifact.get("puzzleHashes")
    if not all(
        isinstance(value, Mapping)
        for value in (bridge, validator_set, launchers, puzzle_hashes)
    ):
        raise ValidatorEvidenceError(
            "signed artifact purchase coordinates are incomplete"
        )
    if (
        claim.credential_policy_version != 2
        or claim.credential_bridge_policy_hash
        != str(bridge.get("policyHash", "")).lower()
        or claim.credential_identity_root
        == "0x" + bytes(DEFAULT_IDENTITY_ATTEST_ROOT).hex()
    ):
        raise ValidatorEvidenceError(
            "purchase has no current zkPassport credential"
        )
    credential_record = _fetch_coin(
        settings,
        claim.credential_vault_coin_id,
        "credential vault coin",
    )
    credential_coin = _coin_from_record(
        credential_record,
        "credential vault coin",
    )
    credential_parent_record = _fetch_coin(
        settings,
        "0x" + bytes(credential_coin.parent_coin_info).hex(),
        "pre-credential vault coin",
        require_unspent=False,
    )
    credential_parent = _coin_from_record(
        credential_parent_record,
        "pre-credential vault coin",
    )
    if (
        credential_parent.parent_coin_info != purchase.vault_launcher_id
        or int(credential_parent.amount) != 1
        or int(credential_coin.amount) != 1
    ):
        raise ValidatorEvidenceError(
            "credential coin is not the stamped successor of this vault"
        )

    try:
        owner_key = bytes.fromhex(claim.credential_owner_key.removeprefix("0x"))
        pool_launcher = bytes32.fromhex(
            str(launchers["pool"]).removeprefix("0x")
        )
        bridge_policy_hash = bytes32.fromhex(
            claim.credential_bridge_policy_hash.removeprefix("0x")
        )
        member_root = one_leaf_merkle_root(owner_key)
        unstamped_puzzle = puzzle_for_vault_full(
            purchase.vault_launcher_id,
            owner_key,
            claim.credential_owner_auth_type,
            member_root,
            pool_launcher,
            identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
        stamped_puzzle = puzzle_for_vault_full(
            purchase.vault_launcher_id,
            owner_key,
            claim.credential_owner_auth_type,
            member_root,
            pool_launcher,
            identity_attest_root=bytes32.fromhex(
                claim.credential_identity_root.removeprefix("0x")
            ),
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "credential vault ownership data is malformed"
        ) from exc
    if (
        credential_parent.puzzle_hash != unstamped_puzzle.get_tree_hash()
        or credential_coin.puzzle_hash != stamped_puzzle.get_tree_hash()
    ):
        raise ValidatorEvidenceError(
            "credential root is not committed by the current vault puzzle"
        )

    raw_pubkeys = validator_set.get("pubkeys")
    if (
        validator_set.get("threshold") != 2
        or not isinstance(raw_pubkeys, list)
        or raw_pubkeys != settings.roster_pubkeys
    ):
        raise ValidatorEvidenceError(
            "signed artifact validator roster is inconsistent"
        )
    try:
        terms = PrimaryMintTermsV2(
            network=purchase.network,
            smart_deed_inner_hash=bytes32.fromhex(
                claim.smart_deed_inner_hash.removeprefix("0x")
            ),
            deed_launcher_id=purchase.deed_launcher_id,
            collection_id=purchase.collection_id,
            metadata_root=purchase.metadata_root,
            metadata_anchor_id=purchase.metadata_anchor_id,
            share_ppm=purchase.share_ppm,
            usd_amount_minor=purchase.usd_amount_minor,
            protocol_puzhash=bytes32.fromhex(
                claim.protocol_puzzle_hash.removeprefix("0x")
            ),
            validator_pubkeys=tuple(
                bytes.fromhex(str(value).removeprefix("0x"))
                for value in raw_pubkeys
            ),
            provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
        )
        did_launcher = bytes32.fromhex(
            str(launchers["did"]).removeprefix("0x")
        )
        did_struct = singleton_struct(did_launcher)
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
        expected_puzzle = SINGLETON_MOD.curry(
            deed_struct,
            make_mint_offer_v2_inner(terms),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "purchase mint terms cannot be reconstructed"
        ) from exc
    if (
        claim.protocol_puzzle_hash
        != str(puzzle_hashes.get("protocolTreasuryPuzzleHash", "")).lower()
        or claim.deed_puzzle_hash
        != "0x" + bytes(expected_puzzle.get_tree_hash()).hex()
    ):
        raise ValidatorEvidenceError(
            "purchase puzzle does not match the signed mint coordinates"
        )
    deed_record = _fetch_coin(
        settings,
        claim.deed_coin_id,
        "primary SmartDeed coin",
    )
    deed_coin = _coin_from_record(deed_record, "primary SmartDeed coin")
    if (
        deed_coin.parent_coin_info != purchase.deed_launcher_id
        or int(deed_coin.amount) != 1
        or deed_coin.puzzle_hash != expected_puzzle.get_tree_hash()
        or "0x" + bytes(deed_coin.name()).hex() != claim.deed_coin_id
    ):
        raise ValidatorEvidenceError(
            "primary SmartDeed coin does not match the governed mint"
        )

    try:
        buyer_offer = Offer.from_bech32(claim.buyer_offer)
        validate_chia_buyer_offer(
            buyer_offer=buyer_offer,
            artifact=purchase,
            terms=terms,
        )
        if len(buyer_offer.coin_spends()) != 1 or buyer_offer.fees() != 0:
            raise ValueError("buyer offer must use one zero-fee payment coin")
        pairs: list[tuple[G1Element, bytes]] = []
        for spend in buyer_offer.coin_spends():
            conditions = conditions_dict_for_solution(
                spend.puzzle_reveal,
                spend.solution,
                INFINITE_COST,
            )
            pairs.extend(
                pkm_pairs_for_conditions_dict(
                    conditions,
                    spend.coin,
                    AGG_SIG_ME_DATA[settings.network],
                )
            )
        if not pairs or not AugSchemeMPL.aggregate_verify(
            [pair[0] for pair in pairs],
            [pair[1] for pair in pairs],
            buyer_offer.aggregated_signature(),
        ):
            raise ValueError("buyer offer signature is invalid")
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "wallet-signed buyer offer is invalid"
        ) from exc


def sign_primary_purchase_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: PrimaryPurchaseClaim,
    claim_hash: str,
) -> str:
    verify_primary_purchase_claim(settings, claim, claim_hash)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_primary_purchase_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_primary_purchase_claim_json(claim),
            purchase_id=claim.purchase_id(),
            deed_coin_id=claim.deed_coin_id,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


__all__ = [
    "ValidatorEvidenceError",
    "canonical_claim_json",
    "canonical_primary_purchase_claim_json",
    "load_validator_artifact",
    "load_validator_private_key",
    "sign_validator_claim",
    "sign_primary_purchase_claim",
    "verify_validator_claim",
    "verify_primary_purchase_claim",
]
