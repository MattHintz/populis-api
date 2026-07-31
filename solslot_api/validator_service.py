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
from chia.types.coin_spend import make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    lineage_proof_for_coinsol,
)
from chia.wallet.util.compute_additions import compute_additions
from chia.wallet.trading.offer import Offer
from chia_rs import AugSchemeMPL, Coin, G1Element, G2Element, PrivateKey
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from web3 import Web3

from solslot_puzzles import load_puzzle
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    DEFAULT_IDENTITY_ATTEST_ROOT,
    build_vault_receive_spend,
    compact_signature_from_evm,
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
    purchase_artifact_from_json as purchase_artifact_v2_from_json,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseKind,
    STRIPE_PAYMENT_PROVIDER_ID,
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    build_stripe_pending_attestation,
    payment_attestation_from_json,
    purchase_artifact_from_json as purchase_artifact_v3_from_json,
    stripe_evidence_from_json,
    stripe_receipt_from_json,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.primary_purchase_v2_driver import (
    PRIMARY_PURCHASE_PROVIDER_ID,
    PrimaryMintTermsV2,
    PrimaryPurchaseMode,
    build_universal_primary_offer_v4,
    make_mint_offer_v4_inner,
    prepare_base_voucher_redemption_offer,
    prepare_xch_voucher_redemption_offer,
    validate_chia_buyer_offer,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    build_inventory_extension_spend,
    build_inventory_release_spend,
    build_inventory_reservation_spend,
    build_stripe_primary_offer_v5,
    build_stripe_receipt_spend,
    make_inventory_available_inner,
    make_mint_offer_v5_inner,
    make_stripe_receipt_puzzle,
    prepare_stripe_receipt_offer,
    validator_roster_root,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.voucher_presale_v2 import (
    DeedAllocationCommitmentV2,
    VoucherPaymentRail,
    VoucherSeriesState,
    VoucherV2Error,
    allocation_root,
    series_terms_from_json,
    validate_purchase,
    voucher_commitment_from_json,
)
from solslot_puzzles.voucher_presale_v2_driver import (
    SeriesTransition,
    VoucherAction,
    VoucherSeriesStateV2,
    build_base_voucher_terminal_spends,
    build_xch_voucher_terminal_spends,
    build_voucher_issuance_spends,
    build_voucher_series_phase_spend,
    curry_external_receipt,
    curry_xch_escrow,
    external_receipt_evidence_message,
    validate_xch_voucher_offer,
)
from solslot_puzzles.voucher_presale_v3 import (
    VoucherV3Error,
    stripe_original_payer,
    validate_stripe_voucher_purchase,
    voucher_commitment_v3_from_json,
)
from solslot_puzzles.voucher_presale_v3_driver import (
    build_stripe_voucher_issuance_spends,
    build_stripe_voucher_primary_offer_v5,
    build_stripe_voucher_terminal_spends,
    prepare_stripe_voucher_redemption_offer,
)

from .config import Settings
from .evm_auth import recover_evm_signer
from .faucet import AGG_SIG_ME_DATA
from .public_artifact import (
    PublicArtifactError,
    verify_signed_public_artifact_file,
)
from .release_metadata import ReleaseMetadata, load_release_metadata
from .validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from .validator_quorum import (
    InventoryExtensionClaim,
    InventoryReleaseClaim,
    InventoryReservationClaim,
    PrimaryPurchaseClaim,
    StripeSettlementClaim,
    ValidatorClaim,
    VoucherIssuanceClaim,
    VoucherSeriesPhaseClaim,
    VoucherTransitionClaim,
    base_settlement_evidence_hash,
)
from .validator_settings import ValidatorSettings
from .zkpassport_enrollments import _fetch_verified_evm_attestation


class ValidatorEvidenceError(RuntimeError):
    """The coordinator claim is not independently provable."""


def _is_protected_systemd_credential(path: Path, mode: int) -> bool:
    """Recognize systemd's read-only credential mount across supported hosts."""
    credentials_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if (
        not credentials_directory
        or path.name not in {"validator-seed", "stripe-read-key"}
    ):
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


def load_stripe_read_only_key(settings: ValidatorSettings) -> str:
    """Load the validator's restricted Stripe read key from protected storage."""

    if not settings.stripe_read_only_key_file:
        raise ValidatorEvidenceError(
            "Stripe read-only validator credentials are not configured"
        )
    path = Path(settings.stripe_read_only_key_file)
    if path.is_symlink() or not path.is_file():
        raise ValidatorEvidenceError(
            "Stripe read-only key file is missing or is a symlink"
        )
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO) and not (
        _is_protected_systemd_credential(path, mode)
    ):
        raise ValidatorEvidenceError(
            "Stripe read-only key file must not be accessible by group/other"
        )
    try:
        key = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ValidatorEvidenceError(
            "Stripe read-only key file is unreadable"
        ) from exc
    expected_prefix = "rk_live_" if settings.stripe_livemode else "rk_test_"
    if not key.startswith(expected_prefix) or len(key) < len(expected_prefix) + 16:
        raise ValidatorEvidenceError(
            "Stripe validator credential is not a restricted key for the "
            "configured mode"
        )
    return key


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


def _assert_coin_not_confirmed(
    settings: ValidatorSettings,
    coin_id: str,
    field: str,
) -> None:
    """Fail closed unless Coinset proves the deterministic output is absent."""

    try:
        with httpx.Client(
            base_url=settings.coinset_base_url.rstrip("/"),
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post(
                "/get_coin_record_by_name",
                json={"name": coin_id},
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValidatorEvidenceError(
            f"Coinset could not prove {field} is absent"
        ) from exc
    record = payload.get("coin_record") if isinstance(payload, Mapping) else None
    if isinstance(record, Mapping) and int(
        record.get("confirmed_block_index") or 0
    ) > 0:
        raise ValidatorEvidenceError(f"{field} is already confirmed")


def _fetch_coin_spend(
    settings: ValidatorSettings,
    coin: Coin,
    spent_height: int,
    field: str,
):
    if spent_height <= 0:
        raise ValidatorEvidenceError(f"{field} is not spent on Chia")
    try:
        with httpx.Client(
            base_url=settings.coinset_base_url.rstrip("/"),
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post(
                "/get_puzzle_and_solution",
                json={
                    "coin_id": "0x" + bytes(coin.name()).hex(),
                    "height": spent_height,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValidatorEvidenceError(f"Coinset could not verify {field}") from exc
    solution = payload.get("coin_solution") if isinstance(payload, Mapping) else None
    if not isinstance(solution, Mapping):
        raise ValidatorEvidenceError(f"{field} puzzle solution is unavailable")
    try:
        puzzle_reveal = Program.from_bytes(
            bytes.fromhex(str(solution["puzzle_reveal"]).removeprefix("0x"))
        )
        puzzle_solution = Program.from_bytes(
            bytes.fromhex(str(solution["solution"]).removeprefix("0x"))
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(f"{field} puzzle solution is malformed") from exc
    if puzzle_reveal.get_tree_hash() != coin.puzzle_hash:
        raise ValidatorEvidenceError(f"{field} puzzle reveal does not match its coin")
    return make_spend(coin, puzzle_reveal, puzzle_solution)


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


def _verify_purchase_credential(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
    purchase: Any,
    claim: Any,
    *,
    label: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any], tuple[bytes, bytes, bytes]]:
    launchers, puzzle_hashes, validator_pubkeys = _purchase_coordinates(
        settings,
        artifact,
        label=label,
    )
    bridge = artifact.get("bridgePolicy")
    if not isinstance(bridge, Mapping):
        raise ValidatorEvidenceError(
            f"signed artifact {label} coordinates are incomplete"
        )
    expected_identity_root = "0x" + bytes(purchase.zkpassport_root).hex()
    if (
        claim.credential_policy_version != 2
        or claim.credential_bridge_policy_hash
        != str(bridge.get("policyHash", "")).lower()
        or claim.credential_identity_root != expected_identity_root
        or claim.credential_identity_root
        == "0x" + bytes(DEFAULT_IDENTITY_ATTEST_ROOT).hex()
    ):
        raise ValidatorEvidenceError(
            f"{label} has no current zkPassport credential"
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
        owner_key = bytes.fromhex(
            claim.credential_owner_key.removeprefix("0x")
        )
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
            identity_attest_root=purchase.zkpassport_root,
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
    return launchers, puzzle_hashes, validator_pubkeys  # type: ignore[return-value]


def _purchase_coordinates(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
    *,
    label: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any], tuple[bytes, bytes, bytes]]:
    validator_set = artifact.get("validatorSet")
    launchers = artifact.get("launcherIds")
    puzzle_hashes = artifact.get("puzzleHashes")
    if not all(
        isinstance(value, Mapping)
        for value in (validator_set, launchers, puzzle_hashes)
    ):
        raise ValidatorEvidenceError(
            f"signed artifact {label} coordinates are incomplete"
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
        validator_pubkeys = tuple(
            bytes.fromhex(str(value).removeprefix("0x"))
            for value in raw_pubkeys
        )
    except ValueError as exc:
        raise ValidatorEvidenceError(
            "signed artifact validator roster is malformed"
        ) from exc
    if len(validator_pubkeys) != 3:
        raise ValidatorEvidenceError(
            "signed artifact must contain exactly three validators"
        )
    return launchers, puzzle_hashes, validator_pubkeys  # type: ignore[return-value]


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
        purchase = purchase_artifact_v2_from_json(claim.purchase_artifact)
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
        owner_key = bytes.fromhex(
            claim.credential_owner_key.removeprefix("0x")
        )
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
            make_mint_offer_v4_inner(terms),
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


def canonical_inventory_reservation_claim_json(
    claim: InventoryReservationClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def verify_inventory_reservation_claim(
    settings: ValidatorSettings,
    claim: InventoryReservationClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "reservation claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if claim.network != settings.network:
        raise ValidatorEvidenceError(
            "reservation network does not match signer"
        )
    if claim.genesis_artifact_hash != str(
        artifact.get("artifactHash", "")
    ).lower():
        raise ValidatorEvidenceError(
            "reservation does not reference the active signed artifact"
        )
    try:
        purchase = purchase_artifact_v3_from_json(
            claim.purchase_artifact
        )
        now = int(time.time())
        purchase.assert_live(now)
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "reservation purchase artifact is invalid or expired"
        ) from exc
    if purchase.network != settings.network:
        raise ValidatorEvidenceError(
            "reservation artifact network does not match signer"
        )
    if (
        claim.reservation_expires_at <= now
        or claim.reservation_expires_at > purchase.quote_expires_at
        or claim.reservation_expires_at
        > purchase.authorization_expires_at
    ):
        raise ValidatorEvidenceError(
            "reservation expiry exceeds its quote or authorization"
        )
    launchers, puzzle_hashes, validator_pubkeys = (
        _verify_purchase_credential(
            settings,
            artifact,
            purchase,
            claim,
            label="inventory reservation",
        )
    )
    protocol_puzzle_hash = str(
        puzzle_hashes.get("protocolTreasuryPuzzleHash", "")
    ).lower()
    if (
        claim.protocol_puzzle_hash != protocol_puzzle_hash
        or "0x" + bytes(purchase.protocol_treasury_puzzle_hash).hex()
        != protocol_puzzle_hash
    ):
        raise ValidatorEvidenceError(
            "reservation technology fee destination is not the trusted "
            "treasury"
        )
    try:
        terms = PrimaryMintTermsV3.for_artifact(
            artifact=purchase,
            smart_deed_inner_hash=bytes32.fromhex(
                claim.smart_deed_inner_hash.removeprefix("0x")
            ),
            protocol_puzhash=bytes32.fromhex(
                claim.protocol_puzzle_hash.removeprefix("0x")
            ),
            validator_pubkeys=validator_pubkeys,
        )
        did_struct = singleton_struct(
            bytes32.fromhex(
                str(launchers["did"]).removeprefix("0x")
            )
        )
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
        expected_available_puzzle = SINGLETON_MOD.curry(
            deed_struct,
            make_inventory_available_inner(terms),
        )
        reservation = InventoryReservationV1(
            artifact=purchase,
            expires_at=claim.reservation_expires_at,
        )
    except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "reservation mint terms cannot be reconstructed"
        ) from exc
    available_coin, lineage = _confirmed_coin_and_lineage(
        settings,
        claim.available_coin_id,
        "available SmartDeed coin",
    )
    if (
        int(available_coin.amount) != 1
        or available_coin.puzzle_hash
        != expected_available_puzzle.get_tree_hash()
        or "0x" + bytes(available_coin.name()).hex()
        != claim.available_coin_id
        or claim.available_puzzle_hash
        != "0x" + bytes(available_coin.puzzle_hash).hex()
    ):
        raise ValidatorEvidenceError(
            "available SmartDeed does not match governed inventory"
        )
    try:
        derived = build_inventory_reservation_spend(
            available_coin=available_coin,
            deed_singleton_struct=deed_struct,
            lineage_proof=lineage,
            reservation=reservation,
            signer_indices=(0, 1),
            terms=terms,
        )
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "inventory reservation spend cannot be re-derived"
        ) from exc
    if (
        claim.validator_message
        != "0x" + bytes(derived.validator_message).hex()
        or claim.reserved_coin_id
        != "0x" + bytes(derived.reserved_coin.name()).hex()
        or claim.reserved_puzzle_hash
        != "0x" + bytes(derived.reserved_coin.puzzle_hash).hex()
    ):
        raise ValidatorEvidenceError(
            "reservation output or validator message is not canonical"
        )


def sign_inventory_reservation_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: InventoryReservationClaim,
    claim_hash: str,
) -> str:
    verify_inventory_reservation_claim(settings, claim, claim_hash)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_inventory_reservation_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_inventory_reservation_claim_json(
                claim
            ),
            purchase_id=claim.purchase_id(),
            artifact_hash=claim.purchase_artifact_hash(),
            available_coin_id=claim.available_coin_id,
            reserved_coin_id=claim.reserved_coin_id,
            reservation_expires_at=claim.reservation_expires_at,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_inventory_extension_claim_json(
    claim: InventoryExtensionClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def verify_inventory_extension_claim(
    settings: ValidatorSettings,
    claim: InventoryExtensionClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "extension claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if claim.network != settings.network:
        raise ValidatorEvidenceError(
            "extension network does not match signer"
        )
    if claim.genesis_artifact_hash != str(
        artifact.get("artifactHash", "")
    ).lower():
        raise ValidatorEvidenceError(
            "extension does not reference the active signed artifact"
        )
    try:
        purchase = purchase_artifact_v3_from_json(
            claim.purchase_artifact
        )
        evidence = stripe_evidence_from_json(claim.stripe_evidence)
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "extension payment evidence is invalid"
        ) from exc
    now = int(time.time())
    if purchase.network != settings.network or purchase.rail != PaymentRail.STRIPE:
        raise ValidatorEvidenceError(
            "extension is not for the configured Stripe rail"
        )
    if (
        claim.current_expires_at <= now
        or claim.next_expires_at <= claim.current_expires_at
        or claim.next_expires_at
        > claim.current_expires_at + 11 * 24 * 60 * 60
    ):
        raise ValidatorEvidenceError(
            "extension is outside the live eleven-day reservation limit"
        )
    expected_status = (
        StripePaymentStatus.PROCESSING
        if claim.phase == "PROCESSING"
        else StripePaymentStatus.SUCCEEDED
    )
    expected_event_type = (
        "payment_intent.processing"
        if claim.phase == "PROCESSING"
        else "payment_intent.succeeded"
    )
    if (
        evidence.status != expected_status
        or evidence.amount_minor
        != purchase.subtotal_minor + evidence.processing_charge_minor
        or evidence.refunded_minor != 0
        or evidence.refund_state != StripeRefundState.NONE
        or evidence.dispute_state != StripeDisputeState.NONE
    ):
        raise ValidatorEvidenceError(
            "extension Stripe state is not eligible to retain inventory"
        )
    launchers, puzzle_hashes, validator_pubkeys = (
        _verify_purchase_credential(
            settings,
            artifact,
            purchase,
            claim,
            label="inventory extension",
        )
    )
    protocol_puzzle_hash = str(
        puzzle_hashes.get("protocolTreasuryPuzzleHash", "")
    ).lower()
    if (
        claim.protocol_puzzle_hash != protocol_puzzle_hash
        or "0x" + bytes(purchase.protocol_treasury_puzzle_hash).hex()
        != protocol_puzzle_hash
    ):
        raise ValidatorEvidenceError(
            "extension technology fee destination is not trusted"
        )
    try:
        terms = PrimaryMintTermsV3.for_artifact(
            artifact=purchase,
            smart_deed_inner_hash=bytes32.fromhex(
                claim.smart_deed_inner_hash.removeprefix("0x")
            ),
            protocol_puzhash=bytes32.fromhex(
                claim.protocol_puzzle_hash.removeprefix("0x")
            ),
            validator_pubkeys=validator_pubkeys,
        )
        did_struct = singleton_struct(
            bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
        )
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
        reservation = InventoryReservationV1(
            artifact=purchase,
            expires_at=claim.current_expires_at,
        )
        expected_current_puzzle = SINGLETON_MOD.curry(
            deed_struct,
            make_mint_offer_v5_inner(terms, reservation),
        )
    except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "extension mint terms cannot be reconstructed"
        ) from exc
    current_coin, lineage = _confirmed_coin_and_lineage(
        settings,
        claim.current_coin_id,
        "reserved SmartDeed coin",
    )
    if (
        int(current_coin.amount) != 1
        or current_coin.puzzle_hash != expected_current_puzzle.get_tree_hash()
        or claim.current_puzzle_hash
        != "0x" + bytes(current_coin.puzzle_hash).hex()
    ):
        raise ValidatorEvidenceError(
            "extension input is not the exact reserved SmartDeed"
        )
    try:
        derived = build_inventory_extension_spend(
            reserved_coin=current_coin,
            deed_singleton_struct=deed_struct,
            lineage_proof=lineage,
            reservation=reservation,
            next_expires_at=claim.next_expires_at,
            signer_indices=(0, 1),
            terms=terms,
        )
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "inventory extension spend cannot be re-derived"
        ) from exc
    if (
        claim.validator_message
        != "0x" + bytes(derived.validator_message or b"").hex()
        or claim.next_coin_id
        != "0x" + bytes(derived.next_coin.name()).hex()
        or claim.next_puzzle_hash
        != "0x" + bytes(derived.next_coin.puzzle_hash).hex()
    ):
        raise ValidatorEvidenceError(
            "extension output or validator message is not canonical"
        )
    _stripe_retrieved_evidence(
        settings,
        artifact=purchase,
        expected=evidence,
        expected_event_type=expected_event_type,
    )


def sign_inventory_extension_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: InventoryExtensionClaim,
    claim_hash: str,
) -> str:
    verify_inventory_extension_claim(settings, claim, claim_hash)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_inventory_extension_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_inventory_extension_claim_json(claim),
            purchase_id=claim.purchase_id(),
            phase=claim.phase,
            current_coin_id=claim.current_coin_id,
            next_coin_id=claim.next_coin_id,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_inventory_release_claim_json(
    claim: InventoryReleaseClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def verify_inventory_release_claim(
    settings: ValidatorSettings,
    claim: InventoryReleaseClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "release claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if claim.network != settings.network:
        raise ValidatorEvidenceError(
            "release network does not match signer"
        )
    if claim.genesis_artifact_hash != str(
        artifact.get("artifactHash", "")
    ).lower():
        raise ValidatorEvidenceError(
            "release does not reference the active signed artifact"
        )
    try:
        purchase = purchase_artifact_v3_from_json(
            claim.purchase_artifact
        )
        evidence = stripe_evidence_from_json(claim.stripe_evidence)
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "release payment evidence is invalid"
        ) from exc
    if purchase.network != settings.network or purchase.rail != PaymentRail.STRIPE:
        raise ValidatorEvidenceError(
            "release is not for the configured Stripe rail"
        )
    if (
        evidence.amount_minor
        != purchase.subtotal_minor + evidence.processing_charge_minor
        or evidence.refunded_minor != 0
        or evidence.refund_state != StripeRefundState.NONE
        or evidence.dispute_state != StripeDisputeState.NONE
    ):
        raise ValidatorEvidenceError(
            "release Stripe evidence is not exact and undisputed"
        )
    now = int(time.time())
    if claim.reason == "PAYMENT_FAILED":
        if (
            claim.event_type
            not in {
                "payment_intent.payment_failed",
                "payment_intent.canceled",
            }
            or evidence.status
            not in {
                StripePaymentStatus.REQUIRES_PAYMENT_METHOD,
                StripePaymentStatus.CANCELED,
            }
        ):
            raise ValidatorEvidenceError(
                "failed-payment release is not terminal"
            )
    elif claim.reason == "DELIVERY_TIMEOUT":
        if (
            claim.event_type != "payment_intent.succeeded"
            or evidence.status != StripePaymentStatus.SUCCEEDED
            or now < evidence.observed_at + 48 * 60 * 60
        ):
            raise ValidatorEvidenceError(
                "delivery-failure release is not yet eligible"
            )
    else:
        if (
            claim.event_type != "payment_intent.succeeded"
            or evidence.status != StripePaymentStatus.SUCCEEDED
            or claim.request_hash is None
            or claim.requested_at is None
            or claim.requested_at > now
        ):
            raise ValidatorEvidenceError(
                "presale refund release request is invalid"
            )
    launchers, puzzle_hashes, validator_pubkeys = _purchase_coordinates(
        settings,
        artifact,
        label="inventory release",
    )
    protocol_puzzle_hash = str(
        puzzle_hashes.get("protocolTreasuryPuzzleHash", "")
    ).lower()
    if (
        claim.protocol_puzzle_hash != protocol_puzzle_hash
        or "0x" + bytes(purchase.protocol_treasury_puzzle_hash).hex()
        != protocol_puzzle_hash
    ):
        raise ValidatorEvidenceError(
            "release technology fee destination is not trusted"
        )
    try:
        terms = PrimaryMintTermsV3.for_artifact(
            artifact=purchase,
            smart_deed_inner_hash=bytes32.fromhex(
                claim.smart_deed_inner_hash.removeprefix("0x")
            ),
            protocol_puzhash=bytes32.fromhex(
                claim.protocol_puzzle_hash.removeprefix("0x")
            ),
            validator_pubkeys=validator_pubkeys,
        )
        did_struct = singleton_struct(
            bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
        )
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
        reservation = InventoryReservationV1(
            artifact=purchase,
            expires_at=claim.current_expires_at,
        )
        expected_current_puzzle = SINGLETON_MOD.curry(
            deed_struct,
            make_mint_offer_v5_inner(terms, reservation),
        )
    except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "release mint terms cannot be reconstructed"
        ) from exc
    current_coin, lineage = _confirmed_coin_and_lineage(
        settings,
        claim.current_coin_id,
        "reserved SmartDeed coin",
    )
    if (
        int(current_coin.amount) != 1
        or current_coin.puzzle_hash != expected_current_puzzle.get_tree_hash()
        or claim.current_puzzle_hash
        != "0x" + bytes(current_coin.puzzle_hash).hex()
    ):
        raise ValidatorEvidenceError(
            "release input is not the exact reserved SmartDeed"
        )
    expected_delivery = Coin(
        current_coin.name(),
        purchase.vault_p2_puzzle_hash,
        uint64(1),
    )
    expected_delivery_id = "0x" + bytes(expected_delivery.name()).hex()
    if claim.expected_delivery_coin_id != expected_delivery_id:
        raise ValidatorEvidenceError(
            "release references a different delivery output"
        )
    _assert_coin_not_confirmed(
        settings,
        expected_delivery_id,
        "expected SmartDeed delivery",
    )
    try:
        derived = build_inventory_release_spend(
            reserved_coin=current_coin,
            deed_singleton_struct=deed_struct,
            lineage_proof=lineage,
            reservation=reservation,
            terms=terms,
            timed_out=False,
            signer_indices=(0, 1),
        )
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "inventory release spend cannot be re-derived"
        ) from exc
    if (
        claim.validator_message
        != "0x" + bytes(derived.validator_message or b"").hex()
        or claim.next_coin_id
        != "0x" + bytes(derived.next_coin.name()).hex()
        or claim.next_puzzle_hash
        != "0x" + bytes(derived.next_coin.puzzle_hash).hex()
    ):
        raise ValidatorEvidenceError(
            "release output or validator message is not canonical"
        )
    _stripe_retrieved_evidence(
        settings,
        artifact=purchase,
        expected=evidence,
        expected_event_type=claim.event_type,
    )


def sign_inventory_release_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: InventoryReleaseClaim,
    claim_hash: str,
) -> str:
    verify_inventory_release_claim(settings, claim, claim_hash)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_inventory_release_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_inventory_release_claim_json(claim),
            purchase_id=claim.purchase_id(),
            reason=claim.reason,
            current_coin_id=claim.current_coin_id,
            next_coin_id=claim.next_coin_id,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_stripe_settlement_claim_json(
    claim: StripeSettlementClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _stripe_get(
    settings: ValidatorSettings,
    path: str,
    *,
    params: list[tuple[str, str]] | None = None,
) -> Mapping[str, Any]:
    key = load_stripe_read_only_key(settings)
    try:
        with httpx.Client(
            base_url=settings.stripe_api_base_url,
            timeout=20.0,
            headers={
                "authorization": f"Bearer {key}",
                "stripe-version": settings.stripe_api_version,
                "user-agent": "solslot-validator-rc24",
            },
        ) as client:
            response = client.get(path, params=params)
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe could not be independently retrieved"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ValidatorEvidenceError("Stripe returned malformed evidence")
    return payload


def _stripe_retrieved_evidence(
    settings: ValidatorSettings,
    *,
    artifact,
    expected: StripeSettlementEvidenceV1,
    expected_event_type: str,
) -> StripeSettlementEvidenceV1:
    account = _stripe_get(settings, "/v1/account")
    event = _stripe_get(
        settings,
        f"/v1/events/{expected.event_id}",
    )
    payment_intent = _stripe_get(
        settings,
        f"/v1/payment_intents/{expected.payment_intent_id}",
        params=[
            ("expand[]", "payment_method"),
            ("expand[]", "latest_charge"),
        ],
    )
    if (
        account.get("id") != settings.stripe_account_id
        or expected.stripe_account_id != settings.stripe_account_id
    ):
        raise ValidatorEvidenceError(
            "Stripe account does not match the validator configuration"
        )
    event_data = event.get("data")
    event_object = (
        event_data.get("object")
        if isinstance(event_data, Mapping)
        else None
    )
    if (
        event.get("id") != expected.event_id
        or event.get("type") != expected_event_type
        or not isinstance(event_object, Mapping)
        or event_object.get("id") != expected.payment_intent_id
    ):
        raise ValidatorEvidenceError(
            "Stripe event is not the exact succeeded PaymentIntent event"
        )
    if event.get("api_version") != settings.stripe_api_version:
        raise ValidatorEvidenceError(
            "Stripe event API version does not match the pinned release"
        )
    if payment_intent.get("id") != expected.payment_intent_id:
        raise ValidatorEvidenceError("Stripe PaymentIntent ID mismatch")
    metadata = payment_intent.get("metadata")
    if not isinstance(metadata, Mapping):
        raise ValidatorEvidenceError(
            "Stripe PaymentIntent has no protocol metadata"
        )
    expected_metadata = {
        "purchase_id": "0x" + bytes(artifact.purchase_id).hex(),
        "artifact_hash": "0x" + bytes(artifact.artifact_hash).hex(),
        "deed_launcher_id": "0x" + bytes(
            artifact.deed_launcher_id
        ).hex(),
        "vault_launcher_id": "0x" + bytes(
            artifact.vault_launcher_id
        ).hex(),
        "base_amount_minor": str(artifact.base_amount_minor),
        "technology_fee_minor": str(artifact.technology_fee_minor),
        "processing_charge_minor": str(
            expected.processing_charge_minor
        ),
        "purchase_kind": artifact.purchase_kind.name,
    }
    if expected.method_family == StripeMethodFamily.CARD:
        expected_metadata["card_3ds_policy"] = "any"
    elif expected.method_family == StripeMethodFamily.US_BANK_ACCOUNT:
        expected_metadata["bank_verification_policy"] = "instant"
    for field, expected_value in expected_metadata.items():
        if metadata.get(field) != expected_value:
            raise ValidatorEvidenceError(
                f"Stripe PaymentIntent metadata {field} mismatch"
            )

    method = payment_intent.get("payment_method")
    charge = payment_intent.get("latest_charge")
    if not isinstance(method, Mapping):
        raise ValidatorEvidenceError(
            "Stripe payment method was not expanded"
        )
    if expected.status == StripePaymentStatus.SUCCEEDED and not isinstance(
        charge, Mapping
    ):
        raise ValidatorEvidenceError(
            "succeeded Stripe payment has no expanded charge"
        )
    method_type = method.get("type")
    if method_type == "us_bank_account":
        method_family = StripeMethodFamily.US_BANK_ACCOUNT
        funding_type = StripeFundingType.BANK_ACCOUNT
    elif method_type == "card":
        method_family = StripeMethodFamily.CARD
        card = method.get("card")
        funding = card.get("funding") if isinstance(card, Mapping) else None
        funding_type = {
            "credit": StripeFundingType.CREDIT,
            "debit": StripeFundingType.DEBIT,
            "prepaid": StripeFundingType.PREPAID,
            "unknown": StripeFundingType.UNKNOWN,
        }.get(str(funding), StripeFundingType.UNKNOWN)
    else:
        raise ValidatorEvidenceError(
            "Stripe payment method is not enabled for SmartDeed purchases"
        )

    _validate_stripe_purchase_method(
        artifact=artifact,
        method_family=method_family,
    )
    _validate_stripe_card_risk(
        settings,
        artifact=artifact,
        method_family=method_family,
        charge=charge,
    )

    amount_field = (
        "amount_received"
        if expected.status == StripePaymentStatus.SUCCEEDED
        else "amount"
    )
    amount_minor = _stripe_int(
        payment_intent.get(amount_field),
        f"PaymentIntent {amount_field}",
    )
    refunded_minor = (
        _stripe_int(
            charge.get("amount_refunded"),
            "Charge amount_refunded",
        )
        if isinstance(charge, Mapping)
        else 0
    )
    refund_state = (
        StripeRefundState.NONE
        if refunded_minor == 0
        else (
            StripeRefundState.FULL
            if refunded_minor >= amount_minor
            else StripeRefundState.PARTIAL
        )
    )
    dispute_state = (
        StripeDisputeState.OPEN
        if isinstance(charge, Mapping) and charge.get("disputed") is True
        else StripeDisputeState.NONE
    )
    status_value = {
        "requires_payment_method": StripePaymentStatus.REQUIRES_PAYMENT_METHOD,
        "processing": StripePaymentStatus.PROCESSING,
        "succeeded": StripePaymentStatus.SUCCEEDED,
        "canceled": StripePaymentStatus.CANCELED,
    }.get(str(payment_intent.get("status")))
    if status_value is None:
        raise ValidatorEvidenceError("Stripe PaymentIntent status is unsupported")
    observed_at = expected.observed_at
    event_created = _stripe_int(event.get("created"), "event created")
    now = int(time.time())
    if (
        observed_at < event_created
        or observed_at > now + settings.claim_clock_skew_seconds
    ):
        raise ValidatorEvidenceError(
            "Stripe evidence observation timestamp predates the event or is in the future"
        )
    retrieved = StripeSettlementEvidenceV1(
        stripe_account_id=settings.stripe_account_id,
        livemode=bool(payment_intent.get("livemode")),
        payment_intent_id=str(payment_intent["id"]),
        event_id=str(event["id"]),
        amount_minor=amount_minor,
        currency=str(payment_intent.get("currency") or ""),
        method_family=method_family,
        funding_type=funding_type,
        processing_charge_minor=_stripe_int(
            metadata.get("processing_charge_minor"),
            "processing charge metadata",
        ),
        status=status_value,
        refunded_minor=refunded_minor,
        refund_state=refund_state,
        dispute_state=dispute_state,
        observed_at=observed_at,
    )
    if (
        retrieved.livemode != settings.stripe_livemode
        or bool(event.get("livemode")) != settings.stripe_livemode
        or retrieved != expected
    ):
        raise ValidatorEvidenceError(
            "retrieved Stripe state does not match the settlement receipt"
        )
    return retrieved


def _validate_stripe_purchase_method(
    *,
    artifact,
    method_family: StripeMethodFamily,
) -> None:
    if (
        method_family == StripeMethodFamily.US_BANK_ACCOUNT
        and artifact.purchase_kind != PurchaseKind.PRESALE
    ):
        raise ValidatorEvidenceError(
            "ACH settlement is valid only for refundable presales"
        )


def _validate_stripe_card_risk(
    settings: ValidatorSettings,
    *,
    artifact,
    method_family: StripeMethodFamily,
    charge: Mapping[str, Any] | None,
) -> None:
    """Apply the reviewed RC24 card policy to Stripe-retrieved evidence."""

    if method_family != StripeMethodFamily.CARD:
        return
    if not isinstance(charge, Mapping):
        raise ValidatorEvidenceError(
            "Stripe card settlement has no expanded charge"
        )
    outcome = charge.get("outcome")
    risk_level = (
        str(outcome.get("risk_level") or "").lower()
        if isinstance(outcome, Mapping)
        else ""
    )
    if settings.stripe_reject_highest_risk and risk_level == "highest":
        raise ValidatorEvidenceError(
            "Stripe classified the card payment as highest risk"
        )
    if (
        artifact.purchase_kind != PurchaseKind.DIRECT
        or not settings.stripe_require_direct_card_3ds
    ):
        return
    payment_method_details = charge.get("payment_method_details")
    card = (
        payment_method_details.get("card")
        if isinstance(payment_method_details, Mapping)
        else None
    )
    three_d_secure = (
        card.get("three_d_secure") if isinstance(card, Mapping) else None
    )
    result = (
        str(three_d_secure.get("result") or "").lower()
        if isinstance(three_d_secure, Mapping)
        else ""
    )
    if result != "authenticated":
        raise ValidatorEvidenceError(
            "direct card delivery requires authenticated 3DS evidence"
        )


def _stripe_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValidatorEvidenceError(f"{label} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        result = int(value)
    else:
        raise ValidatorEvidenceError(f"{label} must be an integer")
    if result < 0:
        raise ValidatorEvidenceError(f"{label} cannot be negative")
    return result


def verify_stripe_settlement_claim(
    settings: ValidatorSettings,
    claim: StripeSettlementClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "Stripe claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    receipt = stripe_receipt_from_json(claim.stripe_receipt)
    purchase = receipt.artifact
    pending = payment_attestation_from_json(claim.pending_attestation)
    now = int(time.time())
    if claim.network != settings.network or purchase.network != settings.network:
        raise ValidatorEvidenceError(
            "Stripe settlement network does not match signer"
        )
    if claim.genesis_artifact_hash != str(
        artifact.get("artifactHash", "")
    ).lower():
        raise ValidatorEvidenceError(
            "Stripe settlement does not reference the active signed artifact"
        )
    if purchase.rail != PaymentRail.STRIPE:
        raise ValidatorEvidenceError(
            "Stripe settlement artifact is not a Stripe rail"
        )
    if receipt.attestation.provider_id != STRIPE_PAYMENT_PROVIDER_ID:
        raise ValidatorEvidenceError(
            "Stripe payment attestation provider is not canonical"
        )
    expected_pending = build_stripe_pending_attestation(
        artifact=purchase,
        evidence=receipt.evidence,
        observed_at=pending.observed_at,
    )
    if pending != expected_pending:
        raise ValidatorEvidenceError(
            "Stripe pending attestation is not canonical"
        )
    receipt.assert_live(now)
    if (
        claim.reservation_expires_at <= now
        or claim.reservation_expires_at < receipt.expires_at
    ):
        raise ValidatorEvidenceError(
            "Stripe delivery is outside the exact inventory reservation"
        )

    launchers, puzzle_hashes, validator_pubkeys = (
        _verify_purchase_credential(
            settings,
            artifact,
            purchase,
            claim,
            label="Stripe settlement",
        )
    )
    if receipt.validator_roster_root != validator_roster_root(
        validator_pubkeys
    ):
        raise ValidatorEvidenceError(
            "Stripe receipt validator roster is not canonical"
        )

    protocol_puzzle_hash = str(
        puzzle_hashes.get("protocolTreasuryPuzzleHash", "")
    ).lower()
    if (
        claim.protocol_puzzle_hash != protocol_puzzle_hash
        or "0x" + bytes(purchase.protocol_treasury_puzzle_hash).hex()
        != protocol_puzzle_hash
    ):
        raise ValidatorEvidenceError(
            "Stripe technology fee destination is not the trusted treasury"
        )
    try:
        terms = PrimaryMintTermsV3.for_artifact(
            artifact=purchase,
            smart_deed_inner_hash=bytes32.fromhex(
                claim.smart_deed_inner_hash.removeprefix("0x")
            ),
            protocol_puzhash=bytes32.fromhex(
                claim.protocol_puzzle_hash.removeprefix("0x")
            ),
            validator_pubkeys=validator_pubkeys,
        )
        did_struct = singleton_struct(
            bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
        )
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
        reservation = InventoryReservationV1(
            artifact=purchase,
            expires_at=claim.reservation_expires_at,
        )
        expected_deed_puzzle = SINGLETON_MOD.curry(
            deed_struct,
            make_mint_offer_v5_inner(terms, reservation),
        )
    except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe SmartDeed terms cannot be reconstructed"
        ) from exc
    if claim.deed_puzzle_hash != (
        "0x" + bytes(expected_deed_puzzle.get_tree_hash()).hex()
    ):
        raise ValidatorEvidenceError(
            "Stripe SmartDeed puzzle does not match governed mint terms"
        )
    deed_coin, deed_lineage = _confirmed_coin_and_lineage(
        settings,
        claim.deed_coin_id,
        "Stripe SmartDeed coin",
    )
    if (
        int(deed_coin.amount) != 1
        or deed_coin.puzzle_hash != expected_deed_puzzle.get_tree_hash()
        or "0x" + bytes(deed_coin.name()).hex() != claim.deed_coin_id
    ):
        raise ValidatorEvidenceError(
            "Stripe SmartDeed coin does not match the governed mint"
        )

    receipt_puzzle = make_stripe_receipt_puzzle(
        receipt=receipt,
        validator_pubkeys=validator_pubkeys,
    )
    if claim.receipt_puzzle_hash != (
        "0x" + bytes(receipt_puzzle.get_tree_hash()).hex()
    ):
        raise ValidatorEvidenceError(
            "Stripe receipt puzzle hash is not canonical"
        )
    receipt_record = _fetch_coin(
        settings,
        claim.receipt_coin_id,
        "Stripe receipt coin",
    )
    receipt_coin = _coin_from_record(receipt_record, "Stripe receipt coin")
    if (
        int(receipt_coin.amount) != 1
        or receipt_coin.puzzle_hash != receipt_puzzle.get_tree_hash()
        or "0x" + bytes(receipt_coin.name()).hex()
        != claim.receipt_coin_id
    ):
        raise ValidatorEvidenceError(
            "Stripe receipt coin does not match the authenticated receipt"
        )
    try:
        receipt_spend = build_stripe_receipt_spend(
            receipt_coin=receipt_coin,
            receipt=receipt,
            validator_pubkeys=validator_pubkeys,
            signer_indices=(0, 1),
        )
        receipt_offer = prepare_stripe_receipt_offer(
            receipt_spend=receipt_spend,
            receipt=receipt,
            terms=terms,
        )
        settlement = build_stripe_primary_offer_v5(
            receipt_offer=receipt_offer,
            receipt_coin=receipt_coin,
            receipt=receipt,
            deed_coin=deed_coin,
            deed_singleton_struct=deed_struct,
            lineage_proof=deed_lineage,
            terms=terms,
            reservation=reservation,
        )
        deed_outputs = compute_additions(settlement.deed_spend)
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe SmartDeed settlement cannot be re-derived"
        ) from exc
    if len(deed_outputs) != 1:
        raise ValidatorEvidenceError(
            "Stripe settlement must create one SmartDeed successor"
        )
    expected_output = deed_outputs[0]
    if (
        claim.expected_deed_output_coin_id
        != "0x" + bytes(expected_output.name()).hex()
        or claim.expected_deed_output_puzzle_hash
        != "0x" + bytes(expected_output.puzzle_hash).hex()
    ):
        raise ValidatorEvidenceError(
            "Stripe delivered SmartDeed output is not canonical"
        )
    _stripe_retrieved_evidence(
        settings,
        artifact=purchase,
        expected=receipt.evidence,
        expected_event_type="payment_intent.succeeded",
    )


def sign_stripe_settlement_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: StripeSettlementClaim,
    claim_hash: str,
) -> str:
    verify_stripe_settlement_claim(settings, claim, claim_hash)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_stripe_settlement_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_stripe_settlement_claim_json(claim),
            purchase_id=claim.purchase_id(),
            payment_intent_id=claim.payment_intent_id(),
            event_id=claim.event_id(),
            receipt_coin_id=claim.receipt_coin_id,
            deed_coin_id=claim.deed_coin_id,
            expected_deed_output_coin_id=(
                claim.expected_deed_output_coin_id
            ),
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_voucher_issuance_claim_json(
    claim: VoucherIssuanceClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _verify_base_voucher_payment(
    settings: ValidatorSettings,
    evidence: Mapping[str, Any],
    *,
    purchase: Any,
    voucher: Any,
) -> None:
    source = evidence.get("source")
    if not isinstance(source, Mapping):
        raise ValidatorEvidenceError("Base voucher has no chain provenance")
    if (
        not settings.base_sepolia_rpc_url
        or not settings.base_sepolia_spoke_address
        or not settings.base_sepolia_usdc_address
    ):
        raise ValidatorEvidenceError("Base Sepolia validator rail is not configured")
    spoke = settings.base_sepolia_spoke_address.lower()
    usdc = settings.base_sepolia_usdc_address.lower()
    expected_payer = "0x" + bytes(voucher.original_payer)[-20:].hex()
    expected = {
        "globalPaymentId": "0x" + bytes(voucher.global_payment_id).hex(),
        "purchaseId": "0x" + bytes(purchase.purchase_id).hex(),
        "artifactHash": "0x" + bytes(purchase.artifact_hash).hex(),
        "amount": int(voucher.payment_principal),
        "quantity": 1,
        "collectionId": "0x" + bytes(voucher.collection_id).hex(),
        "deedLauncherId": "0x" + bytes(voucher.deed_launcher_id).hex(),
        "vaultLauncherId": "0x" + bytes(voucher.approved_vault_launcher_id).hex(),
        "destinationPuzzle": "0x" + bytes(voucher.approved_vault_p2_puzzle_hash).hex(),
        "depositor": expected_payer,
        "settlementToken": usdc,
    }
    for field, expected_value in expected.items():
        observed = evidence.get(field)
        if isinstance(expected_value, str):
            observed = str(observed or "").lower()
        if observed != expected_value:
            raise ValidatorEvidenceError(
                f"Base voucher payment {field} does not match commitments"
            )
    if (
        int(source.get("chainId") or 0) != 84532
        or str(source.get("spoke") or "").lower() != spoke
        or int(source.get("confirmations") or 0)
        < settings.base_sepolia_min_confirmations
    ):
        raise ValidatorEvidenceError("Base voucher source route is invalid")

    w3 = Web3(
        Web3.HTTPProvider(
            settings.base_sepolia_rpc_url,
            request_kwargs={"timeout": 20.0},
        )
    )
    tx_hash = str(source.get("transactionHash") or "")
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        block = w3.eth.get_block(int(source["blockNumber"]))
        latest = int(w3.eth.block_number)
    except Exception as exc:  # noqa: BLE001
        raise ValidatorEvidenceError(
            "Base Sepolia could not independently verify the payment"
        ) from exc
    block_number = int(receipt.get("blockNumber") or 0)
    if (
        int(receipt.get("status") or 0) != 1
        or block_number != int(source.get("blockNumber") or 0)
        or "0x" + bytes(receipt.get("blockHash") or b"").hex()
        != str(source.get("blockHash") or "").lower()
        or int(block.get("timestamp") or 0) != int(source.get("blockTimestamp") or 0)
        or latest - block_number + 1 < settings.base_sepolia_min_confirmations
    ):
        raise ValidatorEvidenceError("Base voucher receipt provenance changed")

    log_index = int(source.get("logIndex") or 0)
    event_topic = Web3.keccak(
        text=(
            "PaymentDeposited(bytes32,bytes32,address,address,uint256,uint64,"
            "address,bytes32,uint256)"
        )
    )
    matching = []
    for log in receipt.get("logs", []):
        topics = list(log.get("topics") or [])
        if (
            str(log.get("address") or "").lower() == spoke
            and int(log.get("logIndex") or 0) == log_index
            and len(topics) == 4
            and bytes(topics[0]) == bytes(event_topic)
            and "0x" + bytes(topics[1]).hex() == expected["globalPaymentId"]
            and "0x" + bytes(topics[2]).hex()
            == str(evidence.get("localPaymentId") or "").lower()
            and "0x" + bytes(topics[3])[-20:].hex() == expected_payer
        ):
            matching.append(log)
    if len(matching) != 1:
        raise ValidatorEvidenceError("Base voucher deposit event is missing or ambiguous")

    deposit_abi = [
        {
            "inputs": [{"name": "globalPaymentId", "type": "bytes32"}],
            "name": "getDeposit",
            "outputs": [
                {
                    "components": [
                        {"name": "depositor", "type": "address"},
                        {"name": "settlementToken", "type": "address"},
                        {"name": "localPaymentId", "type": "bytes32"},
                        {"name": "purchaseId", "type": "bytes32"},
                        {"name": "artifactHash", "type": "bytes32"},
                        {"name": "collectionId", "type": "bytes32"},
                        {"name": "deedLauncherId", "type": "bytes32"},
                        {"name": "vaultLauncherId", "type": "bytes32"},
                        {"name": "destinationPuzzle", "type": "bytes32"},
                        {"name": "requestMessageId", "type": "bytes32"},
                        {"name": "resultMessageId", "type": "bytes32"},
                        {"name": "warpNonce", "type": "bytes32"},
                        {"name": "amount", "type": "uint256"},
                        {"name": "quantity", "type": "uint256"},
                        {"name": "hubChainSelector", "type": "uint64"},
                        {"name": "hubGateway", "type": "address"},
                        {"name": "createdAt", "type": "uint64"},
                        {"name": "quoteExpiresAt", "type": "uint64"},
                        {"name": "status", "type": "uint8"},
                        {"name": "succeeded", "type": "bool"},
                    ],
                    "name": "",
                    "type": "tuple",
                }
            ],
            "stateMutability": "view",
            "type": "function",
        }
    ]
    try:
        deposit = w3.eth.contract(
            address=Web3.to_checksum_address(spoke), abi=deposit_abi
        ).functions.getDeposit(expected["globalPaymentId"]).call()
    except Exception as exc:  # noqa: BLE001
        raise ValidatorEvidenceError("Base voucher deposit storage is unavailable") from exc
    observed_deposit = {
        "depositor": str(deposit[0]).lower(),
        "settlementToken": str(deposit[1]).lower(),
        "localPaymentId": "0x" + bytes(deposit[2]).hex(),
        "purchaseId": "0x" + bytes(deposit[3]).hex(),
        "artifactHash": "0x" + bytes(deposit[4]).hex(),
        "collectionId": "0x" + bytes(deposit[5]).hex(),
        "deedLauncherId": "0x" + bytes(deposit[6]).hex(),
        "vaultLauncherId": "0x" + bytes(deposit[7]).hex(),
        "destinationPuzzle": "0x" + bytes(deposit[8]).hex(),
        "amount": int(deposit[12]),
        "quantity": int(deposit[13]),
    }
    for field, expected_value in {
        **expected,
        "localPaymentId": str(evidence.get("localPaymentId") or "").lower(),
    }.items():
        if observed_deposit.get(field) != expected_value:
            raise ValidatorEvidenceError(
                f"Base voucher stored deposit {field} does not match"
            )
    status_value = int(deposit[18])
    if status_value not in (1, 2, 3) or (
        status_value >= 2 and bool(deposit[19]) is not True
    ):
        raise ValidatorEvidenceError("Base voucher deposit is not eligible")


def _verify_stripe_voucher_issuance_claim(
    settings: ValidatorSettings,
    claim: VoucherIssuanceClaim,
    *,
    genesis_artifact: Mapping[str, Any],
) -> None:
    try:
        terms = series_terms_from_json(claim.series_terms)
        voucher = voucher_commitment_v3_from_json(
            claim.voucher_commitment
        )
        purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
        if (
            claim.payment_evidence.get("schema")
            != "solslot.stripe-voucher-payment-evidence.v1"
        ):
            raise ValueError("Stripe voucher payment evidence schema is invalid")
        pending_value = claim.payment_evidence.get("pendingAttestation")
        receipt_value = claim.payment_evidence.get("stripeReceipt")
        if not isinstance(pending_value, Mapping) or not isinstance(
            receipt_value, Mapping
        ):
            raise ValueError("Stripe voucher receipt evidence is missing")
        pending = payment_attestation_from_json(pending_value)
        receipt = stripe_receipt_from_json(receipt_value)
        if receipt.artifact != purchase:
            raise ValueError("Stripe voucher receipt targets another purchase")
        if pending != build_stripe_pending_attestation(
            artifact=purchase,
            evidence=receipt.evidence,
            observed_at=pending.observed_at,
        ):
            raise ValueError("Stripe pending attestation is not canonical")
        receipt.assert_live(int(time.time()))
        state = VoucherSeriesStateV2(
            sold_count=claim.series_sold_count,
            redeemed_count=claim.series_redeemed_count,
            refunded_count=claim.series_refunded_count,
            phase=VoucherSeriesState(claim.series_phase),
            launched_at=claim.series_launched_at,
        )
        expected_payer = stripe_original_payer(purchase)
        expected_inner = bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        )
        validate_stripe_voucher_purchase(
            series=terms,
            voucher=voucher,
            artifact=purchase,
            receipt=receipt,
            expected_original_payer=expected_payer,
            expected_smart_deed_inner_hash=expected_inner,
            now_seconds=receipt.evidence.observed_at,
        )
    except (
        PaymentArtifactError,
        VoucherV2Error,
        VoucherV3Error,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValidatorEvidenceError(
            "Stripe voucher issuance commitments are invalid"
        ) from exc

    raw_pubkeys = genesis_artifact.get("validatorSet", {}).get("pubkeys")
    treasury = genesis_artifact.get("puzzleHashes", {}).get(
        "protocolTreasuryPuzzleHash"
    )
    if (
        purchase.purchase_kind != PurchaseKind.PRESALE
        or purchase.rail != PaymentRail.STRIPE
        or purchase.presale_terms_hash != terms.terms_hash
        or purchase.collection_id != terms.collection_id
        or purchase.deed_launcher_id != voucher.deed_launcher_id
        or purchase.vault_launcher_id
        != voucher.approved_vault_launcher_id
        or purchase.vault_p2_puzzle_hash
        != voucher.approved_vault_p2_puzzle_hash
        or raw_pubkeys != settings.roster_pubkeys
        or tuple(
            bytes.fromhex(item.removeprefix("0x")) for item in raw_pubkeys
        )
        != terms.validator_pubkeys
        or receipt.validator_roster_root
        != validator_roster_root(terms.validator_pubkeys)
        or receipt.validator_threshold != 2
        or str(treasury or "").lower()
        != "0x" + bytes(terms.trusted_protocol_treasury).hex()
    ):
        raise ValidatorEvidenceError(
            "Stripe voucher differs from governed series or validator roster"
        )

    series_record = _fetch_coin(
        settings,
        claim.series_coin_id,
        "Stripe voucher series coin",
    )
    series_coin = _coin_from_record(
        series_record,
        "Stripe voucher series coin",
    )
    parent_record = _fetch_coin(
        settings,
        "0x" + bytes(series_coin.parent_coin_info).hex(),
        "Stripe voucher series parent",
        require_unspent=False,
    )
    parent_coin = _coin_from_record(
        parent_record,
        "Stripe voucher series parent",
    )
    series_height = int(series_record.get("confirmed_block_index") or 0)
    parent_spent_height = int(parent_record.get("spent_block_index") or 0)
    if (
        "0x" + bytes(series_coin.name()).hex() != claim.series_coin_id
        or parent_coin.name() != series_coin.parent_coin_info
        or parent_spent_height != series_height
    ):
        raise ValidatorEvidenceError(
            "Stripe voucher series lineage is not canonical"
        )
    series_lineage = lineage_proof_for_coinsol(
        _fetch_coin_spend(
            settings,
            parent_coin,
            parent_spent_height,
            "Stripe voucher series parent",
        )
    )
    purchase_record = _fetch_coin(
        settings,
        claim.purchase_launcher_coin_id,
        "Stripe voucher purchase launcher",
    )
    purchase_coin = _coin_from_record(
        purchase_record,
        "Stripe voucher purchase launcher",
    )
    if (
        "0x" + bytes(purchase_coin.name()).hex()
        != claim.purchase_launcher_coin_id
        or int(purchase_coin.amount) != 2
    ):
        raise ValidatorEvidenceError(
            "Stripe voucher purchase launcher is not canonical"
        )
    try:
        issuance = build_stripe_voucher_issuance_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            artifact=purchase,
            receipt=receipt,
            expected_original_payer=expected_payer,
            smart_deed_inner_hash=expected_inner,
            purchase_launcher_coin=purchase_coin,
            signer_indices=(0, 1),
        )
    except (
        PaymentArtifactError,
        VoucherV2Error,
        VoucherV3Error,
        TypeError,
        ValueError,
    ) as exc:
        raise ValidatorEvidenceError(
            "Stripe voucher issuance bundle cannot be re-derived"
        ) from exc
    if "0x" + bytes(issuance.validator_message).hex() != claim.validator_message:
        raise ValidatorEvidenceError(
            "Stripe voucher validator message changed on re-derivation"
        )
    _stripe_retrieved_evidence(
        settings,
        artifact=purchase,
        expected=receipt.evidence,
        expected_event_type="payment_intent.succeeded",
    )


def verify_voucher_issuance_claim(
    settings: ValidatorSettings,
    claim: VoucherIssuanceClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "voucher claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if (
        claim.network != settings.network
        or claim.genesis_artifact_hash
        != str(artifact.get("artifactHash") or "").lower()
    ):
        raise ValidatorEvidenceError("voucher claim does not match active genesis")
    if (
        claim.voucher_commitment.get("schema")
        == "solslot.voucher-commitment.v3"
    ):
        _verify_stripe_voucher_issuance_claim(
            settings,
            claim,
            genesis_artifact=artifact,
        )
        return
    try:
        terms = series_terms_from_json(claim.series_terms)
        voucher = voucher_commitment_from_json(claim.voucher_commitment)
        purchase = purchase_artifact_v2_from_json(claim.purchase_artifact)
        if voucher.payment_rail == VoucherPaymentRail.BASE_SEPOLIA_USDC:
            payment_source = claim.payment_evidence.get("source")
            if not isinstance(payment_source, Mapping):
                raise ValueError("voucher payment source is missing")
            authorization_time = int(payment_source.get("blockTimestamp") or 0)
            if authorization_time <= 0:
                raise ValueError("voucher payment confirmation time is missing")
        elif voucher.payment_rail == VoucherPaymentRail.CHIA_XCH:
            authorization_time = int(time.time())
        else:
            raise ValueError("voucher payment rail is unsupported")
        purchase.assert_live(authorization_time)
        state = VoucherSeriesStateV2(
            sold_count=claim.series_sold_count,
            redeemed_count=claim.series_redeemed_count,
            refunded_count=claim.series_refunded_count,
            phase=VoucherSeriesState(claim.series_phase),
            launched_at=claim.series_launched_at,
        )
        validate_purchase(
            series=terms,
            voucher=voucher,
            now_seconds=authorization_time,
        )
    except (PaymentArtifactError, VoucherV2Error, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError("voucher issuance commitments are invalid") from exc
    raw_pubkeys = artifact.get("validatorSet", {}).get("pubkeys")
    treasury = artifact.get("puzzleHashes", {}).get("protocolTreasuryPuzzleHash")
    if (
        raw_pubkeys != settings.roster_pubkeys
        or tuple(bytes.fromhex(item.removeprefix("0x")) for item in raw_pubkeys)
        != terms.validator_pubkeys
        or str(treasury or "").lower()
        != "0x" + bytes(terms.trusted_protocol_treasury).hex()
        or purchase.artifact_hash != voucher.purchase_artifact_hash
        or purchase.collection_id != voucher.collection_id
        or purchase.deed_launcher_id != voucher.deed_launcher_id
        or purchase.vault_launcher_id != voucher.approved_vault_launcher_id
        or purchase.vault_p2_puzzle_hash != voucher.approved_vault_p2_puzzle_hash
    ):
        raise ValidatorEvidenceError("voucher issuance differs from governed terms")

    series_record = _fetch_coin(settings, claim.series_coin_id, "voucher series coin")
    series_coin = _coin_from_record(series_record, "voucher series coin")
    if "0x" + bytes(series_coin.name()).hex() != claim.series_coin_id:
        raise ValidatorEvidenceError("voucher issuance coin IDs are not canonical")
    parent_record = _fetch_coin(
        settings,
        "0x" + bytes(series_coin.parent_coin_info).hex(),
        "voucher series parent",
        require_unspent=False,
    )
    parent_coin = _coin_from_record(parent_record, "voucher series parent")
    series_height = int(series_record.get("confirmed_block_index") or 0)
    parent_spent_height = int(parent_record.get("spent_block_index") or 0)
    if (
        parent_coin.name() != series_coin.parent_coin_info
        or parent_spent_height != series_height
    ):
        raise ValidatorEvidenceError(
            "voucher series parent did not create the current series coin"
        )
    parent_spend = _fetch_coin_spend(
        settings,
        parent_coin,
        parent_spent_height,
        "voucher series parent",
    )
    series_lineage = lineage_proof_for_coinsol(parent_spend)
    if voucher.payment_rail == VoucherPaymentRail.BASE_SEPOLIA_USDC:
        if purchase.rail != PaymentRail.EVM_TEST_USD:
            raise ValidatorEvidenceError("Base voucher purchase rail is inconsistent")
        purchase_record = _fetch_coin(
            settings, claim.purchase_launcher_coin_id, "voucher purchase launcher"
        )
        purchase_coin = _coin_from_record(purchase_record, "voucher purchase launcher")
        if (
            "0x" + bytes(purchase_coin.name()).hex()
            != claim.purchase_launcher_coin_id
        ):
            raise ValidatorEvidenceError("voucher purchase launcher ID is not canonical")
        payment_puzzle = curry_external_receipt(terms=terms, voucher=voucher)
        payment_amount = 1
        _verify_base_voucher_payment(
            settings, claim.payment_evidence, purchase=purchase, voucher=voucher
        )
    elif voucher.payment_rail == VoucherPaymentRail.CHIA_XCH:
        if purchase.rail != PaymentRail.CHIA_XCH or claim.buyer_offer is None:
            raise ValidatorEvidenceError("native voucher offer evidence is missing")
        source = claim.payment_evidence.get("source")
        try:
            buyer_offer = Offer.from_bech32(claim.buyer_offer)
            purchase_coin = validate_xch_voucher_offer(
                buyer_offer=buyer_offer,
                terms=terms,
                state=state,
                series_coin=series_coin,
                voucher=voucher,
                purchase=purchase,
            )
            if (
                "0x" + bytes(purchase_coin.name()).hex()
                != claim.purchase_launcher_coin_id
                or not isinstance(source, Mapping)
                or source.get("chain") != "chia"
            ):
                raise ValueError("native voucher launcher evidence changed")
            payment_spends = buyer_offer.coin_spends()
            if len(payment_spends) != 1:
                raise ValueError("native voucher must use one payment coin")
            payment_coin = payment_spends[0].coin
            payment_coin_id = "0x" + bytes(payment_coin.name()).hex()
            if (
                str(source.get("paymentCoinId") or "").lower() != payment_coin_id
                or payment_coin.puzzle_hash != voucher.original_payer
            ):
                raise ValueError("native voucher payer evidence changed")
            payment_record = _fetch_coin(
                settings,
                payment_coin_id,
                "native voucher payment coin",
            )
            if _coin_from_record(payment_record, "native voucher payment coin") != payment_coin:
                raise ValueError("native voucher payment coin record changed")
            pairs: list[tuple[G1Element, bytes]] = []
            for spend in payment_spends:
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
                raise ValueError("native voucher wallet signature is invalid")
        except (PaymentArtifactError, VoucherV2Error, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError("native voucher offer is invalid") from exc
        payment_puzzle = curry_xch_escrow(
            terms=terms,
            voucher=voucher,
            purchase=purchase,
        )
        payment_amount = int(voucher.payment_principal)
    else:
        raise ValidatorEvidenceError("voucher payment rail is unsupported")
    try:
        issuance = build_voucher_issuance_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase_launcher_coin=purchase_coin,
            payment_puzzle=payment_puzzle,
            payment_amount=payment_amount,
            signer_indices=(0, 1),
        )
    except (PaymentArtifactError, VoucherV2Error, ValueError) as exc:
        raise ValidatorEvidenceError("voucher issuance bundle cannot be re-derived") from exc
    if "0x" + bytes(issuance.validator_message).hex() != claim.validator_message:
        raise ValidatorEvidenceError("voucher validator message changed on re-derivation")


def sign_voucher_issuance_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: VoucherIssuanceClaim,
    claim_hash: str,
) -> str:
    verify_voucher_issuance_claim(settings, claim, claim_hash)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_voucher_issuance_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_voucher_issuance_claim_json(claim),
            global_payment_id=claim.global_payment_id(),
            series_coin_id=claim.series_coin_id,
            purchase_launcher_coin_id=claim.purchase_launcher_coin_id,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_voucher_series_phase_claim_json(
    claim: VoucherSeriesPhaseClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _verify_governed_deed_launchers(
    settings: ValidatorSettings,
    claim: VoucherSeriesPhaseClaim,
    terms: Any,
) -> None:
    raw_deeds = claim.series_terms.get("deeds")
    if not isinstance(raw_deeds, list) or len(raw_deeds) != terms.inventory_cap:
        raise ValidatorEvidenceError("series deed allocation evidence is incomplete")
    try:
        ordered = sorted(raw_deeds, key=lambda item: int(item["ordinal"]))
        if [int(item["ordinal"]) for item in ordered] != list(
            range(terms.inventory_cap)
        ):
            raise ValueError("deed ordinals are not contiguous")
        rows = tuple(
            DeedAllocationCommitmentV2(
                deed_id=bytes32.fromhex(
                    str(item["deedIdCanon"]).removeprefix("0x")
                ),
                share_ppm=int(item["sharePpm"]),
                par_value_mojos=int(item["parValueMojos"]),
                deed_launcher_id=bytes32.fromhex(
                    str(item["deedLauncherId"]).removeprefix("0x")
                ),
            )
            for item in ordered
        )
        if any(
            row.deed_id != canonicalise_property_id(str(item["deedId"]))
            for row, item in zip(rows, ordered, strict=True)
        ):
            raise ValueError("canonical deed ID changed")
    except (KeyError, TypeError, ValueError, VoucherV2Error) as exc:
        raise ValidatorEvidenceError("series deed allocation is malformed") from exc
    if allocation_root(rows) != terms.allocation_root:
        raise ValidatorEvidenceError("series deed allocation root changed")
    expected_launchers = [
        "0x" + bytes(row.deed_launcher_id).hex() for row in rows
    ]
    if claim.deed_launcher_ids != expected_launchers:
        raise ValidatorEvidenceError("governed deed launcher order changed")

    for ordinal, launcher_id in enumerate(claim.deed_launcher_ids):
        record = _fetch_coin(
            settings,
            launcher_id,
            f"governed deed launcher {ordinal}",
            require_unspent=False,
        )
        launcher = _coin_from_record(record, f"governed deed launcher {ordinal}")
        spent_height = int(record.get("spent_block_index") or 0)
        if (
            "0x" + bytes(launcher.name()).hex() != launcher_id
            or launcher.puzzle_hash != SINGLETON_LAUNCHER_HASH
            or int(launcher.amount) != 1
            or spent_height <= 0
        ):
            raise ValidatorEvidenceError(
                f"governed deed launcher {ordinal} is not an executed singleton launch"
            )
        spend = _fetch_coin_spend(
            settings,
            launcher,
            spent_height,
            f"governed deed launcher {ordinal}",
        )
        additions = compute_additions(spend)
        if (
            len(additions) != 1
            or additions[0].parent_coin_info != launcher.name()
            or int(additions[0].amount) != 1
        ):
            raise ValidatorEvidenceError(
                f"governed deed launcher {ordinal} did not create one SmartDeed singleton"
            )


def verify_voucher_series_phase_claim(
    settings: ValidatorSettings,
    claim: VoucherSeriesPhaseClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "series phase claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if (
        claim.network != settings.network
        or claim.genesis_artifact_hash
        != str(artifact.get("artifactHash") or "").lower()
    ):
        raise ValidatorEvidenceError("series phase does not match active genesis")
    try:
        terms = series_terms_from_json(claim.series_terms)
        state = VoucherSeriesStateV2(
            sold_count=claim.series_sold_count,
            redeemed_count=claim.series_redeemed_count,
            refunded_count=claim.series_refunded_count,
            phase=VoucherSeriesState(claim.series_phase),
            launched_at=claim.series_launched_at,
        )
        transition = SeriesTransition(claim.transition)
    except (TypeError, ValueError, VoucherV2Error) as exc:
        raise ValidatorEvidenceError("series phase commitments are invalid") from exc
    if state.phase != VoucherSeriesState.PRESALE or state.launched_at != 0:
        raise ValidatorEvidenceError("only a presale series can change phase")
    raw_pubkeys = artifact.get("validatorSet", {}).get("pubkeys")
    treasury = artifact.get("puzzleHashes", {}).get("protocolTreasuryPuzzleHash")
    if (
        raw_pubkeys != settings.roster_pubkeys
        or tuple(bytes.fromhex(item.removeprefix("0x")) for item in raw_pubkeys)
        != terms.validator_pubkeys
        or str(treasury or "").lower()
        != "0x" + bytes(terms.trusted_protocol_treasury).hex()
    ):
        raise ValidatorEvidenceError("series phase trust coordinates changed")
    if transition == SeriesTransition.LAUNCH:
        if abs(int(time.time()) - claim.launch_anchor) > 90:
            raise ValidatorEvidenceError("series launch anchor is stale")
        _verify_governed_deed_launchers(settings, claim, terms)
    elif claim.deed_launcher_ids or claim.governance_execution_ids:
        raise ValidatorEvidenceError("series cancellation carried launch evidence")

    series_coin, lineage = _confirmed_coin_and_lineage(
        settings,
        claim.series_coin_id,
        "voucher series coin",
    )
    try:
        phase = build_voucher_series_phase_spend(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=lineage,
            transition=transition,
            launch_anchor=claim.launch_anchor,
            signer_indices=(0, 1),
        )
    except (TypeError, ValueError, VoucherV2Error) as exc:
        raise ValidatorEvidenceError("series phase spend cannot be re-derived") from exc
    if "0x" + bytes(phase.validator_message).hex() != claim.validator_message:
        raise ValidatorEvidenceError(
            "series phase validator message changed on re-derivation"
        )


def sign_voucher_series_phase_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: VoucherSeriesPhaseClaim,
    claim_hash: str,
) -> str:
    verify_voucher_series_phase_claim(settings, claim, claim_hash)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_voucher_series_phase_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_voucher_series_phase_claim_json(claim),
            series_coin_id=claim.series_coin_id,
            transition=claim.transition,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_voucher_transition_claim_json(
    claim: VoucherTransitionClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _confirmed_coin_and_lineage(
    settings: ValidatorSettings,
    coin_id: str,
    field: str,
) -> tuple[Coin, LineageProof]:
    record = _fetch_coin(settings, coin_id, field)
    coin = _coin_from_record(record, field)
    if "0x" + bytes(coin.name()).hex() != coin_id:
        raise ValidatorEvidenceError(f"{field} ID is not canonical")
    parent_id = "0x" + bytes(coin.parent_coin_info).hex()
    parent_record = _fetch_coin(
        settings,
        parent_id,
        f"{field} parent",
        require_unspent=False,
    )
    parent_coin = _coin_from_record(parent_record, f"{field} parent")
    child_height = int(record.get("confirmed_block_index") or 0)
    parent_spent_height = int(parent_record.get("spent_block_index") or 0)
    if parent_coin.name() != coin.parent_coin_info or parent_spent_height != child_height:
        raise ValidatorEvidenceError(f"{field} lineage is not atomic")
    parent_spend = _fetch_coin_spend(
        settings,
        parent_coin,
        parent_spent_height,
        f"{field} parent",
    )
    return coin, lineage_proof_for_coinsol(parent_spend)


def _verify_stripe_voucher_transition_claim(
    settings: ValidatorSettings,
    claim: VoucherTransitionClaim,
    *,
    genesis_artifact: Mapping[str, Any],
) -> None:
    """Re-derive one Voucher V3 terminal path from chain and Stripe state."""

    try:
        terms = series_terms_from_json(claim.series_terms)
        voucher = voucher_commitment_v3_from_json(claim.voucher_commitment)
        purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
        state = VoucherSeriesStateV2(
            sold_count=claim.series_sold_count,
            redeemed_count=claim.series_redeemed_count,
            refunded_count=claim.series_refunded_count,
            phase=VoucherSeriesState(claim.series_phase),
            launched_at=claim.series_launched_at,
        )
        action = VoucherAction(claim.action)
        evidence = claim.payment_evidence
        if (
            not isinstance(evidence, Mapping)
            or evidence.get("schema")
            != "solslot.stripe-voucher-terminal-evidence.v1"
        ):
            raise ValueError("Stripe voucher terminal evidence schema is invalid")
        pending_value = evidence.get("pendingAttestation")
        receipt_value = evidence.get("stripeReceipt")
        if not isinstance(pending_value, Mapping) or not isinstance(
            receipt_value, Mapping
        ):
            raise ValueError("Stripe voucher terminal receipt is missing")
        pending = payment_attestation_from_json(pending_value)
        receipt = stripe_receipt_from_json(receipt_value)
        if receipt.artifact != purchase:
            raise ValueError("Stripe voucher receipt targets another purchase")
        if pending != build_stripe_pending_attestation(
            artifact=purchase,
            evidence=receipt.evidence,
            observed_at=pending.observed_at,
        ):
            raise ValueError("Stripe voucher pending attestation is not canonical")
        terminal_hash = bytes32.fromhex(
            str(claim.external_settlement_evidence_hash).removeprefix("0x")
        )
        evidence_hash = evidence.get("terminalEvidenceHash")
        if evidence_hash != "0x" + bytes(terminal_hash).hex():
            raise ValueError("Stripe voucher terminal evidence hash changed")
        if action in {
            VoucherAction.REFUND_PRESALE,
            VoucherAction.REFUND_CANCELED,
        }:
            if evidence.get("refundRequestHash") != evidence_hash:
                raise ValueError("Stripe voucher refund request is not exact")
        elif terminal_hash != receipt.receipt_hash:
            raise ValueError("automatic Stripe voucher action changed its receipt")
        expected_inner = bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        )
        validate_stripe_voucher_purchase(
            series=terms,
            voucher=voucher,
            artifact=purchase,
            receipt=receipt,
            expected_original_payer=stripe_original_payer(purchase),
            expected_smart_deed_inner_hash=expected_inner,
            now_seconds=receipt.evidence.observed_at,
        )
    except (
        PaymentArtifactError,
        VoucherV2Error,
        VoucherV3Error,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValidatorEvidenceError(
            "Stripe voucher terminal commitments are invalid"
        ) from exc

    raw_pubkeys = genesis_artifact.get("validatorSet", {}).get("pubkeys")
    puzzle_hashes = genesis_artifact.get("puzzleHashes", {})
    launchers = genesis_artifact.get("launcherIds", {})
    treasury = str(
        puzzle_hashes.get("protocolTreasuryPuzzleHash") or ""
    ).lower()
    if (
        purchase.purchase_kind != PurchaseKind.PRESALE
        or purchase.rail != PaymentRail.STRIPE
        or purchase.presale_terms_hash != terms.terms_hash
        or purchase.artifact_hash != voucher.purchase_artifact_hash
        or purchase.deed_launcher_id != voucher.deed_launcher_id
        or purchase.vault_launcher_id
        != voucher.approved_vault_launcher_id
        or claim.vault_launcher_id
        != "0x" + bytes(voucher.approved_vault_launcher_id).hex()
        or raw_pubkeys != settings.roster_pubkeys
        or tuple(
            bytes.fromhex(item.removeprefix("0x")) for item in raw_pubkeys
        )
        != terms.validator_pubkeys
        or receipt.validator_roster_root
        != validator_roster_root(terms.validator_pubkeys)
        or receipt.validator_threshold != 2
        or treasury != "0x" + bytes(terms.trusted_protocol_treasury).hex()
        or purchase.protocol_treasury_puzzle_hash
        != terms.trusted_protocol_treasury
    ):
        raise ValidatorEvidenceError(
            "Stripe voucher differs from governed series or trust coordinates"
        )

    now = int(time.time())
    delivery_deadline = (
        state.launched_at + DELIVERY_WINDOW_SECONDS
        if state.phase == VoucherSeriesState.LIVE
        else 0
    )
    if (
        action == VoucherAction.REFUND_PRESALE
        and (
            state.phase != VoucherSeriesState.PRESALE
            or now >= terms.refund_deadline
        )
    ):
        raise ValidatorEvidenceError("Stripe presale refund is not available")
    if (
        action == VoucherAction.REFUND_CANCELED
        and state.phase != VoucherSeriesState.CANCELED
    ):
        raise ValidatorEvidenceError("Stripe canceled-series refund is not available")
    if (
        action == VoucherAction.REFUND_EXPIRED
        and (
            state.phase != VoucherSeriesState.LIVE
            or delivery_deadline <= 0
            or now < delivery_deadline
        )
    ):
        raise ValidatorEvidenceError("Stripe voucher delivery has not expired")
    if (
        action == VoucherAction.REDEEM
        and (
            state.phase != VoucherSeriesState.LIVE
            or delivery_deadline <= 0
            or now >= delivery_deadline
        )
    ):
        raise ValidatorEvidenceError("Stripe voucher delivery window is closed")

    series_coin, series_lineage = _confirmed_coin_and_lineage(
        settings,
        claim.series_coin_id,
        "Stripe voucher series coin",
    )
    voucher_coin, voucher_lineage = _confirmed_coin_and_lineage(
        settings,
        claim.voucher_coin_id,
        "Stripe voucher coin",
    )
    receipt_record = _fetch_coin(
        settings,
        claim.payment_coin_id,
        "Stripe voucher receipt coin",
    )
    receipt_coin = _coin_from_record(
        receipt_record,
        "Stripe voucher receipt coin",
    )
    if (
        "0x" + bytes(receipt_coin.name()).hex() != claim.payment_coin_id
        or voucher_coin.parent_coin_info
        != bytes32.fromhex(claim.voucher_launcher_id.removeprefix("0x"))
    ):
        raise ValidatorEvidenceError(
            "Stripe voucher terminal coin bindings are not canonical"
        )

    vault_coin_id = bytes32.zeros
    vault_inner_puzzle_hash = bytes32.zeros
    if action != VoucherAction.REFUND_EXPIRED:
        if (
            claim.vault_coin_id is None
            or claim.vault_identity_attest_root is None
            or claim.vault_owner_auth_type is None
            or claim.vault_owner_key is None
            or claim.vault_identity_attest_root
            == "0x" + bytes(DEFAULT_IDENTITY_ATTEST_ROOT).hex()
        ):
            raise ValidatorEvidenceError(
                "Stripe voucher has no current approved-vault evidence"
            )
        vault_coin, vault_lineage = _confirmed_coin_and_lineage(
            settings,
            claim.vault_coin_id,
            "Stripe voucher approved vault coin",
        )
        try:
            owner_key = bytes.fromhex(claim.vault_owner_key.removeprefix("0x"))
            launcher = bytes32.fromhex(
                claim.vault_launcher_id.removeprefix("0x")
            )
            identity_root = bytes32.fromhex(
                claim.vault_identity_attest_root.removeprefix("0x")
            )
            pool_launcher = bytes32.fromhex(
                str(launchers["pool"]).removeprefix("0x")
            )
            bridge_policy_hash = bytes32.fromhex(
                str(
                    genesis_artifact["bridgePolicy"]["policyHash"]
                ).removeprefix("0x")
            )
            expected_vault = puzzle_for_vault_full(
                launcher,
                owner_key,
                claim.vault_owner_auth_type,
                one_leaf_merkle_root(owner_key),
                pool_launcher,
                identity_attest_root=identity_root,
                zkpassport_bridge_policy_hash=bridge_policy_hash,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "Stripe voucher vault ownership evidence is malformed"
            ) from exc
        if (
            vault_coin.puzzle_hash != expected_vault.get_tree_hash()
            or int(vault_coin.amount) != 1
        ):
            raise ValidatorEvidenceError(
                "Stripe voucher vault coin does not match its owner"
            )
        if action in {
            VoucherAction.REFUND_PRESALE,
            VoucherAction.REFUND_CANCELED,
        }:
            try:
                owner_authorization = bytes.fromhex(
                    claim.owner_authorization.removeprefix("0x")
                )
                signature_data: bytes | None = None
                if claim.vault_owner_auth_type == AUTH_TYPE_SECP256K1:
                    typed_data = eip712_typed_data_for_vault_spend(
                        b"i",
                        bytes32.fromhex(
                            claim.voucher_launcher_id.removeprefix("0x")
                        ),
                        vault_coin.name(),
                    )
                    recovered = recover_evm_signer(
                        typed_data,
                        claim.owner_authorization,
                    )
                    if recovered.compressed_pubkey != owner_key:
                        raise ValueError(
                            "EVM signature does not belong to the vault owner"
                        )
                    signature_data = compact_signature_from_evm(
                        claim.owner_authorization
                    )
                vault_spend = build_vault_receive_spend(
                    vault_coin=vault_coin,
                    vault_launcher_id=launcher,
                    owner_pubkey_bytes=owner_key,
                    auth_type=claim.vault_owner_auth_type,
                    members_merkle_root=one_leaf_merkle_root(owner_key),
                    pool_launcher_id=pool_launcher,
                    deed_launcher_id=bytes32.fromhex(
                        claim.voucher_launcher_id.removeprefix("0x")
                    ),
                    p2_vault_coin_id=voucher_coin.name(),
                    current_timestamp=claim.current_timestamp,
                    lineage_proof=vault_lineage,
                    signature_data=signature_data,
                    identity_attest_root=identity_root,
                    zkpassport_bridge_policy_hash=bridge_policy_hash,
                )
                if claim.vault_owner_auth_type == AUTH_TYPE_BLS:
                    signature = G2Element.from_bytes(owner_authorization)
                    conditions = conditions_dict_for_solution(
                        vault_spend.puzzle_reveal,
                        vault_spend.solution,
                        INFINITE_COST,
                    )
                    pairs = pkm_pairs_for_conditions_dict(
                        conditions,
                        vault_spend.coin,
                        AGG_SIG_ME_DATA[settings.network],
                    )
                    if not pairs or not AugSchemeMPL.aggregate_verify(
                        [pair[0] for pair in pairs],
                        [pair[1] for pair in pairs],
                        signature,
                    ):
                        raise ValueError(
                            "BLS signature does not authorize the vault spend"
                        )
            except ValueError as exc:
                raise ValidatorEvidenceError(
                    "Stripe voucher owner authorization is invalid"
                ) from exc
            uncurried_vault = expected_vault.uncurry()
            if uncurried_vault is None:
                raise ValidatorEvidenceError(
                    "Stripe voucher vault puzzle is not a singleton"
                )
            try:
                vault_args = list(uncurried_vault[1].as_iter())
            except ValueError as exc:
                raise ValidatorEvidenceError(
                    "Stripe voucher vault curry is malformed"
                ) from exc
            if len(vault_args) != 2:
                raise ValidatorEvidenceError(
                    "Stripe voucher vault singleton shape is invalid"
                )
            vault_coin_id = vault_coin.name()
            vault_inner_puzzle_hash = bytes32(
                vault_args[1].get_tree_hash()
            )

    try:
        transition = build_stripe_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            artifact=purchase,
            voucher_launcher_id=bytes32.fromhex(
                claim.voucher_launcher_id.removeprefix("0x")
            ),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=vault_coin_id,
            vault_inner_puzzle_hash=vault_inner_puzzle_hash,
            action=action,
            terminal_evidence_hash=terminal_hash,
            signer_indices=(0, 1),
        )
    except (PaymentArtifactError, VoucherV3Error, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe voucher terminal spends cannot be re-derived"
        ) from exc
    if (
        claim.validator_message
        != "0x" + bytes(transition.validator_message).hex()
        or claim.external_validator_message
        != "0x" + bytes(transition.receipt_validator_message).hex()
    ):
        raise ValidatorEvidenceError(
            "Stripe voucher terminal validator messages changed"
        )

    if action == VoucherAction.REDEEM:
        if (
            claim.reservation_expires_at is None
            or claim.deed_coin_id is None
            or claim.deed_puzzle_hash is None
            or claim.smart_deed_inner_hash is None
            or claim.protocol_puzzle_hash is None
            or claim.buyer_offer is None
        ):
            raise ValidatorEvidenceError(
                "Stripe voucher redemption evidence is incomplete"
            )
        try:
            mint_terms = PrimaryMintTermsV3.for_artifact(
                artifact=purchase,
                smart_deed_inner_hash=expected_inner,
                protocol_puzhash=terms.trusted_protocol_treasury,
                validator_pubkeys=terms.validator_pubkeys,
            )
            did_struct = singleton_struct(
                bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
            )
            deed_struct = deed_singleton_struct(
                deed_launcher_id=purchase.deed_launcher_id,
                protocol_did_singleton_struct=did_struct,
            )
            reservation = InventoryReservationV1(
                artifact=purchase,
                expires_at=claim.reservation_expires_at,
            )
            expected_deed_puzzle = SINGLETON_MOD.curry(
                deed_struct,
                make_mint_offer_v5_inner(mint_terms, reservation),
            )
            deed_coin, deed_lineage = _confirmed_coin_and_lineage(
                settings,
                claim.deed_coin_id,
                "Stripe voucher reserved SmartDeed",
            )
            if (
                deed_coin.puzzle_hash != expected_deed_puzzle.get_tree_hash()
                or int(deed_coin.amount) != 1
                or claim.deed_puzzle_hash
                != "0x" + bytes(deed_coin.puzzle_hash).hex()
                or claim.smart_deed_inner_hash
                != "0x" + bytes(expected_inner).hex()
                or claim.protocol_puzzle_hash != treasury
            ):
                raise ValueError("reserved SmartDeed is not canonical")
            expected_buyer = prepare_stripe_voucher_redemption_offer(
                terminal=transition,
                receipt_coin=receipt_coin,
                artifact=purchase,
                terms=mint_terms,
            )
            claimed_buyer = Offer.from_bech32(claim.buyer_offer)
            if (
                claimed_buyer.aggregated_signature() != G2Element()
                or claimed_buyer.to_bech32() != expected_buyer.to_bech32()
            ):
                raise ValueError("Stripe voucher buyer offer changed")
            primary = build_stripe_voucher_primary_offer_v5(
                voucher_offer=claimed_buyer,
                terminal=transition,
                receipt_coin=receipt_coin,
                receipt=receipt,
                deed_coin=deed_coin,
                deed_singleton_struct=deed_struct,
                lineage_proof=deed_lineage,
                signer_indices=(0, 1),
                terms=mint_terms,
                reservation=reservation,
            )
            if not primary.aggregate_offer.is_valid():
                raise ValueError("Stripe voucher redemption does not balance")
        except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "Stripe voucher redemption cannot be re-derived"
            ) from exc

    _stripe_retrieved_evidence(
        settings,
        artifact=purchase,
        expected=receipt.evidence,
        expected_event_type="payment_intent.succeeded",
    )


def verify_voucher_transition_claim(
    settings: ValidatorSettings,
    claim: VoucherTransitionClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "voucher transition claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if (
        claim.network != settings.network
        or claim.genesis_artifact_hash
        != str(artifact.get("artifactHash") or "").lower()
    ):
        raise ValidatorEvidenceError("voucher transition does not match active genesis")
    if abs(int(time.time()) - claim.current_timestamp) > settings.claim_clock_skew_seconds:
        raise ValidatorEvidenceError("voucher owner authorization timestamp is stale")
    if (
        claim.voucher_commitment.get("schema")
        == "solslot.voucher-commitment.v3"
    ):
        _verify_stripe_voucher_transition_claim(
            settings,
            claim,
            genesis_artifact=artifact,
        )
        return
    try:
        terms = series_terms_from_json(claim.series_terms)
        voucher = voucher_commitment_from_json(claim.voucher_commitment)
        purchase = purchase_artifact_v2_from_json(claim.purchase_artifact)
        state = VoucherSeriesStateV2(
            sold_count=claim.series_sold_count,
            redeemed_count=claim.series_redeemed_count,
            refunded_count=claim.series_refunded_count,
            phase=VoucherSeriesState(claim.series_phase),
            launched_at=claim.series_launched_at,
        )
        action = VoucherAction(claim.action)
    except (PaymentArtifactError, VoucherV2Error, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError("voucher transition commitments are invalid") from exc
    is_base = (
        voucher.payment_rail == VoucherPaymentRail.BASE_SEPOLIA_USDC
        and purchase.rail == PaymentRail.EVM_TEST_USD
    )
    is_native = (
        voucher.payment_rail == VoucherPaymentRail.CHIA_XCH
        and purchase.rail == PaymentRail.CHIA_XCH
    )
    if not is_base and not is_native:
        raise ValidatorEvidenceError("voucher transition payment rail is inconsistent")
    if is_base:
        if (
            claim.payment_evidence is None
            or claim.external_settlement_evidence_hash is None
            or claim.external_validator_message is None
        ):
            raise ValidatorEvidenceError(
                "Base voucher transition has no authenticated payment evidence"
            )
        expected_evidence_hash = base_settlement_evidence_hash(
            claim.payment_evidence
        )
        if claim.external_settlement_evidence_hash != expected_evidence_hash:
            raise ValidatorEvidenceError(
                "Base voucher settlement evidence hash changed"
            )
        try:
            expected_validator_message = external_receipt_evidence_message(
                voucher=voucher,
                action=action,
                external_settlement_evidence_hash=bytes32.fromhex(
                    expected_evidence_hash.removeprefix("0x")
                ),
            )
        except (TypeError, ValueError, VoucherV2Error) as exc:
            raise ValidatorEvidenceError(
                "Base voucher settlement message cannot be reconstructed"
            ) from exc
        if (
            claim.external_validator_message
            != "0x" + bytes(expected_validator_message).hex()
        ):
            raise ValidatorEvidenceError(
                "Base voucher settlement validator message changed"
            )
        _verify_base_voucher_payment(
            settings,
            claim.payment_evidence,
            purchase=purchase,
            voucher=voucher,
        )
    if (
        claim.vault_launcher_id
        != "0x" + bytes(voucher.approved_vault_launcher_id).hex()
        or purchase.artifact_hash != voucher.purchase_artifact_hash
    ):
        raise ValidatorEvidenceError("voucher transition vault or purchase binding changed")
    now = int(time.time())
    delivery_deadline = (
        state.launched_at + DELIVERY_WINDOW_SECONDS
        if state.phase == VoucherSeriesState.LIVE
        else 0
    )
    if action == VoucherAction.REFUND_PRESALE and now >= terms.refund_deadline:
        raise ValidatorEvidenceError("presale refund deadline has passed")
    if action == VoucherAction.REFUND_EXPIRED and now < delivery_deadline:
        raise ValidatorEvidenceError("voucher delivery window has not expired")
    if action == VoucherAction.REDEEM and now >= delivery_deadline:
        raise ValidatorEvidenceError("voucher delivery window has expired")

    raw_pubkeys = artifact.get("validatorSet", {}).get("pubkeys")
    treasury = artifact.get("puzzleHashes", {}).get("protocolTreasuryPuzzleHash")
    if (
        raw_pubkeys != settings.roster_pubkeys
        or tuple(bytes.fromhex(item.removeprefix("0x")) for item in raw_pubkeys)
        != terms.validator_pubkeys
        or str(treasury or "").lower()
        != "0x" + bytes(terms.trusted_protocol_treasury).hex()
    ):
        raise ValidatorEvidenceError("voucher transition trust coordinates changed")

    series_coin, series_lineage = _confirmed_coin_and_lineage(
        settings,
        claim.series_coin_id,
        "voucher series coin",
    )
    voucher_coin, voucher_lineage = _confirmed_coin_and_lineage(
        settings,
        claim.voucher_coin_id,
        "voucher coin",
    )
    payment_record = _fetch_coin(settings, claim.payment_coin_id, "voucher payment coin")
    payment_coin = _coin_from_record(payment_record, "voucher payment coin")
    if "0x" + bytes(payment_coin.name()).hex() != claim.payment_coin_id:
        raise ValidatorEvidenceError("voucher payment coin ID is not canonical")
    if voucher_coin.parent_coin_info != bytes32.fromhex(
        claim.voucher_launcher_id.removeprefix("0x")
    ):
        raise ValidatorEvidenceError("voucher singleton launcher lineage changed")

    vault_coin_id = bytes32.zeros
    vault_inner_puzzle_hash = bytes32.zeros
    if action != VoucherAction.REFUND_EXPIRED:
        if (
            claim.vault_coin_id is None
            or claim.vault_identity_attest_root is None
            or claim.vault_owner_auth_type is None
            or claim.vault_owner_key is None
            or claim.vault_identity_attest_root
            == "0x" + bytes(DEFAULT_IDENTITY_ATTEST_ROOT).hex()
        ):
            raise ValidatorEvidenceError(
                "voucher transition has no current approved-vault evidence"
            )
        vault_coin, vault_lineage = _confirmed_coin_and_lineage(
            settings,
            claim.vault_coin_id,
            "approved vault coin",
        )
        try:
            owner_key = bytes.fromhex(claim.vault_owner_key.removeprefix("0x"))
            launcher = bytes32.fromhex(claim.vault_launcher_id.removeprefix("0x"))
            identity_root = bytes32.fromhex(
                claim.vault_identity_attest_root.removeprefix("0x")
            )
            pool_launcher = bytes32.fromhex(
                str(artifact["launcherIds"]["pool"]).removeprefix("0x")
            )
            bridge_policy_hash = bytes32.fromhex(
                str(artifact["bridgePolicy"]["policyHash"]).removeprefix("0x")
            )
            expected_vault = puzzle_for_vault_full(
                launcher,
                owner_key,
                claim.vault_owner_auth_type,
                one_leaf_merkle_root(owner_key),
                pool_launcher,
                identity_attest_root=identity_root,
                zkpassport_bridge_policy_hash=bridge_policy_hash,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "approved vault ownership evidence is malformed"
            ) from exc
        if (
            vault_coin.puzzle_hash != expected_vault.get_tree_hash()
            or int(vault_coin.amount) != 1
        ):
            raise ValidatorEvidenceError(
                "approved vault coin does not match its owner"
            )

    if action in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_CANCELED,
    }:
        try:
            owner_authorization = bytes.fromhex(
                claim.owner_authorization.removeprefix("0x")
            )
        except ValueError as exc:
            raise ValidatorEvidenceError(
                "voucher owner authorization is malformed"
            ) from exc
        signature_data: bytes | None = None
        if claim.vault_owner_auth_type == AUTH_TYPE_SECP256K1:
            typed_data = eip712_typed_data_for_vault_spend(
                b"i",
                bytes32.fromhex(claim.voucher_launcher_id.removeprefix("0x")),
                vault_coin.name(),
            )
            try:
                recovered = recover_evm_signer(
                    typed_data, claim.owner_authorization
                )
                if recovered.compressed_pubkey != owner_key:
                    raise ValueError(
                        "EVM signature does not belong to the vault owner"
                    )
                signature_data = compact_signature_from_evm(
                    claim.owner_authorization
                )
            except ValueError as exc:
                raise ValidatorEvidenceError(
                    "voucher EVM owner authorization is invalid"
                ) from exc
        vault_spend = build_vault_receive_spend(
            vault_coin=vault_coin,
            vault_launcher_id=launcher,
            owner_pubkey_bytes=owner_key,
            auth_type=claim.vault_owner_auth_type,
            members_merkle_root=one_leaf_merkle_root(owner_key),
            pool_launcher_id=pool_launcher,
            deed_launcher_id=bytes32.fromhex(
                claim.voucher_launcher_id.removeprefix("0x")
            ),
            p2_vault_coin_id=voucher_coin.name(),
            current_timestamp=claim.current_timestamp,
            lineage_proof=vault_lineage,
            signature_data=signature_data,
            identity_attest_root=identity_root,
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
        if claim.vault_owner_auth_type == AUTH_TYPE_BLS:
            try:
                signature = G2Element.from_bytes(owner_authorization)
                conditions = conditions_dict_for_solution(
                    vault_spend.puzzle_reveal,
                    vault_spend.solution,
                    INFINITE_COST,
                )
                pairs = pkm_pairs_for_conditions_dict(
                    conditions,
                    vault_spend.coin,
                    AGG_SIG_ME_DATA[settings.network],
                )
                if not pairs or not AugSchemeMPL.aggregate_verify(
                    [pair[0] for pair in pairs],
                    [pair[1] for pair in pairs],
                    signature,
                ):
                    raise ValueError(
                        "BLS signature does not authorize the vault spend"
                    )
            except ValueError as exc:
                raise ValidatorEvidenceError(
                    "voucher BLS owner authorization is invalid"
                ) from exc

        uncurried_vault = expected_vault.uncurry()
        if uncurried_vault is None:
            raise ValidatorEvidenceError(
                "approved vault puzzle is not a curried singleton"
            )
        try:
            vault_args = list(uncurried_vault[1].as_iter())
        except ValueError as exc:
            raise ValidatorEvidenceError(
                "approved vault curry arguments are malformed"
            ) from exc
        if len(vault_args) != 2:
            raise ValidatorEvidenceError(
                "approved vault singleton shape is invalid"
            )
        vault_coin_id = vault_coin.name()
        vault_inner_puzzle_hash = bytes32(vault_args[1].get_tree_hash())

    try:
        if is_base:
            assert claim.external_settlement_evidence_hash is not None
            transition = build_base_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                purchase=purchase,
                voucher_launcher_id=bytes32.fromhex(
                    claim.voucher_launcher_id.removeprefix("0x")
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                receipt_coin=payment_coin,
                vault_coin_id=(
                    vault_coin_id
                    if action
                    in {
                        VoucherAction.REFUND_PRESALE,
                        VoucherAction.REFUND_CANCELED,
                    }
                    else bytes32.zeros
                ),
                vault_inner_puzzle_hash=(
                    vault_inner_puzzle_hash
                    if action
                    in {
                        VoucherAction.REFUND_PRESALE,
                        VoucherAction.REFUND_CANCELED,
                    }
                    else bytes32.zeros
                ),
                action=action,
                external_settlement_evidence_hash=bytes32.fromhex(
                    claim.external_settlement_evidence_hash.removeprefix("0x")
                ),
                signer_indices=(0, 1),
            )
        else:
            transition = build_xch_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                purchase=purchase,
                voucher_launcher_id=bytes32.fromhex(
                    claim.voucher_launcher_id.removeprefix("0x")
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                payment_coin=payment_coin,
                vault_coin_id=vault_coin_id,
                vault_inner_puzzle_hash=vault_inner_puzzle_hash,
                action=action,
                signer_indices=(0, 1),
            )
    except (PaymentArtifactError, VoucherV2Error, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError("voucher terminal spends cannot be re-derived") from exc
    if "0x" + bytes(transition.validator_message).hex() != claim.validator_message:
        raise ValidatorEvidenceError("voucher transition validator message changed")

    if action == VoucherAction.REDEEM:
        if not all(
            isinstance(value, str)
            for value in (
                claim.deed_coin_id,
                claim.deed_puzzle_hash,
                claim.smart_deed_inner_hash,
                claim.protocol_puzzle_hash,
                claim.buyer_offer,
            )
        ):
            raise ValidatorEvidenceError(
                "voucher redemption deed evidence is incomplete"
            )
        try:
            mint_terms = PrimaryMintTermsV2(
                network=purchase.network,
                smart_deed_inner_hash=bytes32.fromhex(
                    claim.smart_deed_inner_hash.removeprefix("0x")  # type: ignore[union-attr]
                ),
                deed_launcher_id=purchase.deed_launcher_id,
                collection_id=purchase.collection_id,
                metadata_root=purchase.metadata_root,
                metadata_anchor_id=purchase.metadata_anchor_id,
                share_ppm=purchase.share_ppm,
                usd_amount_minor=purchase.usd_amount_minor,
                protocol_puzhash=bytes32.fromhex(
                    claim.protocol_puzzle_hash.removeprefix("0x")  # type: ignore[union-attr]
                ),
                validator_pubkeys=terms.validator_pubkeys,
                provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
            )
            did_struct = singleton_struct(
                bytes32.fromhex(
                    str(artifact["launcherIds"]["did"]).removeprefix("0x")
                )
            )
            deed_struct = deed_singleton_struct(
                deed_launcher_id=purchase.deed_launcher_id,
                protocol_did_singleton_struct=did_struct,
            )
            expected_deed_puzzle = SINGLETON_MOD.curry(
                deed_struct,
                make_mint_offer_v4_inner(mint_terms),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "voucher redemption mint terms cannot be reconstructed"
            ) from exc
        if (
            claim.protocol_puzzle_hash != str(treasury).lower()
            or claim.deed_puzzle_hash
            != "0x" + bytes(expected_deed_puzzle.get_tree_hash()).hex()
        ):
            raise ValidatorEvidenceError(
                "voucher redemption puzzle differs from governed mint"
            )
        deed_coin, deed_lineage = _confirmed_coin_and_lineage(
            settings,
            claim.deed_coin_id,  # type: ignore[arg-type]
            "voucher redemption SmartDeed coin",
        )
        if (
            deed_coin.parent_coin_info != purchase.deed_launcher_id
            or deed_coin.puzzle_hash != expected_deed_puzzle.get_tree_hash()
            or int(deed_coin.amount) != 1
        ):
            raise ValidatorEvidenceError(
                "voucher redemption SmartDeed is not the governed coin"
            )
        try:
            expected_buyer_offer = (
                prepare_base_voucher_redemption_offer(
                    terminal_coin_spends=transition.coin_spends,
                    receipt_coin=payment_coin,
                    artifact=purchase,
                    terms=mint_terms,
                )
                if is_base
                else prepare_xch_voucher_redemption_offer(
                    terminal_coin_spends=transition.coin_spends,
                    payment_coin=payment_coin,
                    artifact=purchase,
                    terms=mint_terms,
                )
            )
            claimed_buyer_offer = Offer.from_bech32(
                claim.buyer_offer  # type: ignore[arg-type]
            )
            if (
                claimed_buyer_offer.aggregated_signature() != G2Element()
                or claimed_buyer_offer.to_bech32()
                != expected_buyer_offer.to_bech32()
            ):
                raise ValueError("voucher buyer offer differs from terminal spends")
            primary = (
                build_universal_primary_offer_v4(
                    buyer_offer=claimed_buyer_offer,
                    deed_coin=deed_coin,
                    deed_singleton_struct=deed_struct,
                    lineage_proof=deed_lineage,
                    artifact=purchase,
                    signer_indices=(0, 1),
                    terms=mint_terms,
                    purchase_mode=PrimaryPurchaseMode.VOUCHER,
                    voucher_coin_id=voucher_coin.name(),
                    voucher_transition_message=transition.validator_message,
                    external_receipt_coin=payment_coin,
                    external_settlement_evidence_hash=bytes32.fromhex(
                        claim.external_settlement_evidence_hash.removeprefix("0x")  # type: ignore[union-attr]
                    ),
                )
                if is_base
                else build_universal_primary_offer_v4(
                    buyer_offer=claimed_buyer_offer,
                    deed_coin=deed_coin,
                    deed_singleton_struct=deed_struct,
                    lineage_proof=deed_lineage,
                    artifact=purchase,
                    signer_indices=(0, 1),
                    terms=mint_terms,
                    purchase_mode=PrimaryPurchaseMode.VOUCHER,
                    voucher_coin_id=voucher_coin.name(),
                    voucher_transition_message=transition.validator_message,
                )
            )
            if not primary.aggregate_offer.is_valid():
                raise ValueError("voucher redemption offer does not balance")
        except (PaymentArtifactError, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "voucher redemption offer cannot be re-derived"
            ) from exc


def sign_voucher_transition_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: VoucherTransitionClaim,
    claim_hash: str,
) -> str:
    verify_voucher_transition_claim(settings, claim, claim_hash)
    private_key = load_validator_private_key(settings)
    signature = "0x" + bytes(
        AugSchemeMPL.aggregate(
            [
                AugSchemeMPL.sign(private_key, message)
                for message in claim.signature_messages()
            ]
        )
    ).hex()
    try:
        return ledger.record_voucher_transition_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_voucher_transition_claim_json(claim),
            global_payment_id=claim.global_payment_id(),
            series_coin_id=claim.series_coin_id,
            voucher_coin_id=claim.voucher_coin_id,
            payment_coin_id=claim.payment_coin_id,
            deed_coin_id=claim.deed_coin_id,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


__all__ = [
    "ValidatorEvidenceError",
    "canonical_claim_json",
    "canonical_inventory_reservation_claim_json",
    "canonical_inventory_release_claim_json",
    "canonical_primary_purchase_claim_json",
    "canonical_stripe_settlement_claim_json",
    "canonical_voucher_issuance_claim_json",
    "canonical_voucher_transition_claim_json",
    "load_validator_artifact",
    "load_validator_private_key",
    "load_stripe_read_only_key",
    "sign_validator_claim",
    "sign_inventory_reservation_claim",
    "sign_inventory_release_claim",
    "sign_primary_purchase_claim",
    "sign_stripe_settlement_claim",
    "sign_voucher_issuance_claim",
    "sign_voucher_transition_claim",
    "verify_validator_claim",
    "verify_inventory_reservation_claim",
    "verify_inventory_release_claim",
    "verify_primary_purchase_claim",
    "verify_stripe_settlement_claim",
    "verify_voucher_issuance_claim",
    "verify_voucher_transition_claim",
]
