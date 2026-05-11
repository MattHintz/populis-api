from pathlib import Path


README = Path(__file__).resolve().parents[1] / "GENESIS_README.md"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def test_genesis_readme_pins_first_admin_bootstrap_boundary() -> None:
    text = _readme()

    assert "POPULIS_ADMIN_TOKEN` is a bootstrap operator token" in text
    assert "`POST /admin/deploy/protocol` deploys the base protocol stack" in text
    assert "does not create the `admin_authority_v2` singleton" in text
    assert "The first protocol admin cannot be voted in by an existing admin" in text
    assert "must be born at admin-authority genesis as admin slot" in text


def test_genesis_readme_separates_admins_from_pgt_governance() -> None:
    text = _readme()

    assert "PGT holders are committee/governance participants" in text
    assert "separate authority system from admin login" in text
    assert "Later admin/key rotation is self-governed" in text


def test_genesis_readme_has_extreme_atomic_phase_zero_brick_map() -> None:
    text = _readme()

    for brick in ("Brick -1", "Brick 0.1", "Brick 0.2A", "Brick 0.2B", "Brick 0.3", "Brick 0.4", "Brick 0.5"):
        assert brick in text

    assert "pytest tests/test_genesis_readme_contract.py" in text
    assert "Bootstrap-accessible first-admin authority step" in text
    assert "Combined bootstrap manifest" in text


def test_genesis_readme_pins_hybrid_bootstrapper_shutdown_model() -> None:
    text = _readme()

    assert "Phase 0 is one genesis ceremony" in text
    assert "two visible steps" in text
    assert "genesis is incomplete until admin slot `0` is committed" in text
    assert "run-once bootstrapper" in text
    assert "run one genesis ceremony" in text
    assert "hybrid manifest + runtime-config handoff" in text
    assert "`bootstrap_manifest.json`" in text
    assert "`portal_runtime_config.json`" in text
    assert "After the bootstrapper records success, every mutable bootstrap route" in text
    assert "must fail closed" in text
    assert "read-only runtime config" in text


def test_genesis_readme_forbids_runtime_config_secret_injection() -> None:
    text = _readme()

    assert "public coordinates only" in text
    assert "must never contain" in text
    assert "`POPULIS_ADMIN_TOKEN`" in text
    assert "faucet private keys" in text
    assert "JWT secrets" in text
    assert "No permanent admin membership is ever created by frontend env injection" in text


def test_genesis_readme_pins_two_step_bootstrap_challenge_boundary() -> None:
    text = " ".join(_readme().split())

    assert "two-step challenge" in text
    assert "short-lived bootstrap session cookie" in text
    assert "scoped only to bootstrap routes" in text
    assert "never an admin-desk session" in text
    assert "must not authorize mint proposals" in text
    assert "invalidated for every mutable bootstrap route when the bootstrapper writes a success" in text
    assert "still-live cookie may authorize only the read-only recovery-anchor handoff endpoints until normal expiry" in text


def test_genesis_readme_forbids_persisting_raw_bootstrap_token() -> None:
    text = " ".join(_readme().split())

    assert "raw bootstrap token must never be stored" in text
    assert "`localStorage`" in text
    assert "`sessionStorage`" in text
    assert "URLs" in text
    assert "manifests" in text
    assert "downloaded artifacts" in text


def test_genesis_readme_pins_first_admin_wallet_capture_contract() -> None:
    text = " ".join(_readme().split())

    assert "First-admin wallet capture contract" in text
    assert "first-admin authority step of the genesis ceremony" in text
    assert "one-shot wallet signature" in text
    assert "proof-of-possession only" in text
    assert "not an authority artifact" in text
    assert "admin slot `0`" in text
    assert "`m_within`" in text
    assert "network/domain binding" in text
    assert "MIPS root that will govern the initial `admin_authority_v2` state" in text


def test_genesis_readme_pins_initial_admin_records_artifact_shape() -> None:
    text = " ".join(_readme().split())

    assert "durable off-chain admin artifact is `admin_records.json`" in text
    assert '"admin_idx": 0' in text
    assert '"m_within": 1' in text
    assert "`eip712_member` leaf" in text
    for field in (
        "`leaf_hash`",
        "`evm_address`",
        "`secp256k1_pubkey`",
        "`type_hash`",
        "`prefix_and_domain_separator`",
    ):
        assert field in text
    assert "`admins_hash` is computed from the displayed admin records" in text


def test_genesis_readme_forbids_first_admin_artifact_secret_leakage() -> None:
    text = " ".join(_readme().split())

    assert "Neither `admin_records.json`, `bootstrap_manifest.json`, nor `portal_runtime_config.json` may contain" in text
    assert "`POPULIS_ADMIN_TOKEN`" in text
    assert "bootstrap session cookie/JWT" in text
    assert "raw wallet signatures" in text
    assert "auth nonces" in text
    assert "JWT secrets" in text
    assert "faucet private keys" in text
    assert "any bearer credential" in text


def test_genesis_readme_pins_admin_authority_artifact_boundary() -> None:
    text = " ".join(_readme().split())

    assert "Admin-authority artifact boundary" in text
    assert "`admin_records.json` is the canonical off-chain roster reveal" in text
    assert "`admin_records` ordered by `admin_idx`" in text
    assert "At genesis this file contains admin slot `0` only" in text
    assert "`bootstrap_manifest.json` commits to `admin_authority_v2.launcher_id`" in text
    assert "`admin_authority_v2.admins_hash`" in text
    assert "`admin_authority_v2.mips_root`" in text
    assert "`admin_authority_v2.authority_version`" in text
    assert "`artifact_hashes.admin_records_json`" in text
    assert "The initial authority version is `1`" in text
    assert "must name the live `authority_version`" in text


def test_genesis_readme_pins_runtime_config_as_read_only_discovery() -> None:
    text = " ".join(_readme().split())

    assert "`portal_runtime_config.json` may repeat public coordinates under `admin_authority_v2`" in text
    for field in (
        "`launcher_id`",
        "`admins_hash`",
        "`mips_root`",
        "`authority_version`",
        "`admin_records_hash`",
    ):
        assert field in text
    assert "read-only runtime discovery" in text
    assert "not an authority source" in text
    assert "not an authorization token" in text
    assert "Mutable bootstrap routes must not edit `admin_records.json`" in text
    assert "replace `bootstrap_manifest.json`" in text
    assert "change the runtime-config authority coordinates" in text


def test_genesis_readme_pins_post_genesis_roster_update_boundary() -> None:
    text = " ".join(_readme().split())

    assert "Future roster additions are normal admin-authority spends, not a bootstrap mutation" in text
    assert "`ADMIN_ROSTER_UPDATE`" in text
    assert "`SPEND_ADMIN_ROSTER_UPDATE = 0x07`" in text
    assert "authorized by the current MIPS admin authority" in text
    assert "append exactly one new admin slot" in text
    assert "update `ADMINS_HASH` and `MIPS_ROOT_HASH` atomically" in text
    assert "preserve `PENDING_KEY_OPS_HASH`" in text
    assert "bump `authority_version`" in text
    assert "on-chain announced `ADMINS_HASH`" in text
    assert "Local edits that do not correspond to a confirmed authority spend are invalid" in text
    assert "Key-rotation paths (`KEY_ADD_*` and `KEY_REMOVE_*`) mutate keys inside existing admin slots only" in text
    assert "not admin-slot creation paths" in text


def test_genesis_readme_pins_bootstrap_finalize_endpoint_contract() -> None:
    text = " ".join(_readme().split())

    assert "Bootstrap finalize recordation contract" in text
    assert "final bootstrap mutation is `POST /admin/bootstrap/finalize`" in text
    assert "records completion of the same genesis ceremony" in text
    assert "authorized by `require_bootstrap_session`" in text
    assert "requires a valid short-lived `populis_bootstrap_session` cookie" in text
    assert "A normal admin JWT, bearer token, or raw `POPULIS_ADMIN_TOKEN` is not sufficient" in text
    for field in (
        "`admin_records`",
        "`admin_authority_launcher_id`",
        "`admins_hash`",
        "`mips_root`",
    ):
        assert field in text
    assert "loads the existing `deployment_manifest.json`" in text
    assert "must not invent protocol coordinates from portal env" in text
    assert "Before any artifact is written" in text
    assert "strictly parses `admin_records`" in text
    assert "recomputes the canonical protocol `admins_hash`" in text
    assert "rejects the finalize request if the records do not hash to the submitted `admins_hash`" in text


def test_genesis_readme_pins_finalize_artifact_order_and_lock() -> None:
    text = " ".join(_readme().split())

    assert "persists them in this order: `admin_records.json`, `portal_runtime_config.json`, `bootstrap_recovery_anchor.json`, then `bootstrap_manifest.json`" in text
    assert "`bootstrap_manifest.json` is the lock marker" in text
    assert "It is written last" in text
    assert "challenge issuance and bootstrap finalization must fail closed" in text
    assert "rather than overwrite permanent records" in text
    assert "keeps the short-lived bootstrap session cookie usable only for read-only recovery-anchor handoff until expiry" in text
    assert "returns only public `bootstrap_manifest`, `portal_runtime_config`, and `bootstrap_recovery_anchor` objects" in text


def test_genesis_readme_pins_portal_finalize_ui_contract() -> None:
    text = " ".join(_readme().split())

    assert "portal first-admin authority step calls `AdminBootstrapService.finalizeBootstrap`" in text
    assert "only after the admin-authority launch has been submitted" in text
    assert "first-admin wallet metadata is known" in text
    assert "`admins_hash` is live" in text
    assert "MIPS root is filled" in text
    assert "request is cookie-only (`withCredentials`) and sends no `Authorization` header" in text
    assert "displays returned `bootstrap_manifest.json`, `portal_runtime_config.json`, and `bootstrap_recovery_anchor.json`" in text
    assert "keeps them visible after the bootstrapper flips to locked" in text
    assert "must not store the bootstrap token, session, raw signature, or finalized artifacts" in text
    assert "`localStorage` or `sessionStorage`" in text


def test_genesis_readme_pins_genesis_page_locked_bootstrap_terminal_state() -> None:
    text = " ".join(_readme().split())

    assert "`/admin/genesis` treats locked bootstrap as terminal" in text
    assert "disables starting another bootstrap session" in text
    assert "hides the first-admin launch CTA" in text
    assert "names the durable public artifacts" in text
    assert "points the operator to permanent admin login" in text
    assert "recorded admin slot `0` wallet" in text


def test_genesis_readme_pins_bootstrap_recovery_anchor_boundary() -> None:
    text = " ".join(_readme().split())

    assert "Bootstrap recovery anchor contract" in text
    assert "public JSON artifacts are necessary but not sufficient for disaster recovery" in text
    assert "chain-visible bootstrap recovery anchor" in text
    assert "future operator can discover without trusting the original server" in text
    assert "public discovery marker, not an authority source" in text
    assert "not an authorization credential" in text
    assert "live `admin_authority_v2` singleton state and verified admin records" in text


def test_genesis_readme_pins_recovery_anchor_marker_and_payload_shape() -> None:
    text = " ".join(_readme().split())

    assert "same first-admin bootstrap ceremony after the final public artifact hashes are known" in text
    assert "`POPULIS_BOOTSTRAP_V1`" in text
    assert "memo-bearing marker coin" in text
    assert "Puzzle announcement payloads or other chain-visible spend records may be added later" in text
    assert "preserve the same canonical payload and tag discoverability" in text
    assert "`canonical_json_bytes`: sorted keys, compact separators, UTF-8" in text
    for field in (
        "`version`",
        "`tag`",
        "`network`",
        "`admin_authority_v2_launcher_id`",
        "`authority_version`",
        "`bootstrap_manifest_hash`",
        "`portal_runtime_config_hash`",
        "`admin_records_hash`",
    ):
        assert field in text


def test_genesis_readme_pins_recovery_anchor_hash_and_secret_rules() -> None:
    text = " ".join(_readme().split())

    assert "`bootstrap_manifest_hash`, `portal_runtime_config_hash`, and `admin_records_hash` are `sha256:` content-hash strings" in text
    assert "mirrored artifacts only when their canonical hashes match the anchor" in text
    assert "artifact coordinates match the live on-chain singleton" in text
    assert "URLs are never authority" in text
    assert "If all locators disappear" in text
    assert "verify any independently mirrored artifact copies" in text
    for forbidden in (
        "`POPULIS_ADMIN_TOKEN`",
        "bootstrap session cookies/JWTs",
        "raw wallet signatures",
        "auth nonces",
        "bearer tokens",
        "admin JWT secrets",
        "faucet private keys",
        "private mnemonics",
    ):
        assert forbidden in text


def test_genesis_readme_pins_recovery_anchor_carrier_boundary() -> None:
    text = " ".join(_readme().split())

    assert "Bootstrap recovery anchor carrier contract" in text
    assert "The v1 on-chain carrier for `bootstrap_recovery_anchor.json` is a memo-bearing marker coin" in text
    assert "post-finalize bootstrap recovery-anchor publish transaction in the same genesis ceremony" in text
    assert "emitted only after `/admin/bootstrap/finalize` has returned the final `bootstrap_recovery_anchor.json` payload" in text
    assert "original first-admin launch transaction cannot carry the final anchor unless it already knows the final artifact hashes" in text
    assert "ordinary XCH output created by a `CREATE_COIN` condition with amount at least `1` mojo" in text
    assert "puzzle hash, amount, parent coin, and future spend are not authority" in text
    assert "must not be used as validation inputs" in text


def test_genesis_readme_pins_recovery_anchor_carrier_memos_and_discovery() -> None:
    text = " ".join(_readme().split())

    assert "marker output memo list must contain exactly one UTF-8 tag memo equal to `POPULIS_BOOTSTRAP_V1`" in text
    assert "one payload memo equal to the canonical JSON bytes of `bootstrap_recovery_anchor.json`" in text
    assert "payload memo must parse as JSON" in text
    assert "byte-for-byte equal to `canonical_json_bytes(payload)`" in text
    assert "scanning chain-visible output memos for `POPULIS_BOOTSTRAP_V1`" in text
    assert "parsing the payload memo from the same marker output" in text
    assert "must not require the original API host, original portal host, marker puzzle hash, or marker coin id" in text


def test_genesis_readme_pins_recovery_anchor_carrier_validation_and_conflicts() -> None:
    text = " ".join(_readme().split())

    assert "payload has the pinned v1 fields" in text
    assert '`tag == "POPULIS_BOOTSTRAP_V1"`' in text
    assert "payload bytes are canonical" in text
    assert "mirrored artifact hashes match `bootstrap_manifest_hash`, `portal_runtime_config_hash`, and `admin_records_hash`" in text
    assert "artifact authority coordinates match the live `admin_authority_v2` singleton" in text
    assert "Re-publishing the exact same payload is idempotent" in text
    assert "Conflicting anchors for the same `network`, `admin_authority_v2_launcher_id`, and `authority_version`" in text
    assert "clients must reject them or require manual operator/auditor review" in text


def test_genesis_readme_pins_recovery_anchor_carrier_secret_boundaries() -> None:
    text = " ".join(_readme().split())

    assert "carrier transaction and memos must never include `POPULIS_ADMIN_TOKEN`" in text
    for forbidden in (
        "bootstrap session cookies/JWTs",
        "raw wallet signatures",
        "auth nonces",
        "bearer tokens",
        "admin JWT secrets",
        "faucet private keys",
        "private mnemonics",
        "private URLs",
        "mutable service credentials",
    ):
        assert forbidden in text
    assert "locators remain optional hints outside the authority boundary" in text


def test_genesis_readme_pins_recovery_anchor_publish_intent_api_contract() -> None:
    text = " ".join(_readme().split())

    assert "Bootstrap recovery anchor publish-intent API contract" in text
    assert "`GET /admin/bootstrap/recovery-anchor/publish-intent` exposes a non-broadcasting operator handoff" in text
    assert "available only after `bootstrap_manifest.json` exists and `bootstrap_recovery_anchor.json` is present" in text
    assert "reads the persisted recovery anchor" in text
    assert "never recomputes a different payload from portal env" in text
    assert "authorized by the recovery-anchor handoff guard" in text
    assert "valid admin JWT or the still-live `populis_bootstrap_session` cookie" in text
    assert "raw `POPULIS_ADMIN_TOKEN` is not accepted as publish authority after lock" in text
    for field in (
        "`network`",
        "`marker_coin_amount_mojos`",
        "`admin_authority_v2_launcher_id`",
        "`authority_version`",
        "`bootstrap_manifest_hash`",
        "`portal_runtime_config_hash`",
        "`admin_records_hash`",
        "`tag_memo_utf8`",
        "`tag_memo_hex`",
        "`payload_memo_json`",
        "`payload_memo_utf8`",
        "`payload_memo_hex`",
        "`memos_hex`",
        "`payload_hash`",
    ):
        assert field in text
    assert "`marker_coin_amount_mojos` defaults to `1`" in text
    assert "does not include or require marker puzzle hash, marker coin id, parent coin id, future spend" in text
    assert "raw wallet signature, spend bundle, or wallet private material" in text
    assert "`tag_memo_utf8` must be `POPULIS_BOOTSTRAP_V1`" in text
    assert "`payload_memo_json` must equal the persisted `bootstrap_recovery_anchor.json`" in text
    assert "`payload_memo_utf8` must be canonical JSON bytes decoded as UTF-8" in text
    assert "`memos_hex` must contain exactly the tag memo hex and payload memo hex in carrier order" in text
    assert "does not submit to coinset, push a spend bundle, select a wallet coin, or create authority" in text


def test_genesis_readme_pins_recovery_anchor_create_coin_preview_api_contract() -> None:
    text = " ".join(_readme().split())

    assert "Bootstrap recovery anchor CREATE_COIN preview API contract" in text
    assert "`POST /admin/bootstrap/recovery-anchor/create-coin-preview` exposes the next non-broadcasting handoff" in text
    assert "JSON-safe preview of the marker `CREATE_COIN` condition" in text
    assert "authorized by the recovery-anchor handoff guard" in text
    assert "valid admin JWT or the still-live `populis_bootstrap_session` cookie" in text
    assert "available only after `bootstrap_manifest.json` and `bootstrap_recovery_anchor.json` exist" in text
    assert "reads the persisted recovery anchor and derives the publish intent from that payload" in text
    assert "raw `POPULIS_ADMIN_TOKEN` is not accepted" in text
    assert "request contains only `marker_puzzle_hash`" in text
    assert "32-byte hex puzzle hash for the ordinary marker coin output" in text
    assert "marker puzzle hash is a carrier address only" in text
    assert "not authority and clients must not validate anchors by this value" in text
    for field in (
        "`condition_opcode`",
        "`marker_puzzle_hash`",
        "`marker_coin_amount_mojos`",
        "`tag_memo_hex`",
        "`payload_memo_hex`",
        "`memos_hex`",
        "`condition_hex`",
        "`payload_hash`",
    ):
        assert field in text
    assert "`condition_opcode` must be `51` (`CREATE_COIN`)" in text
    assert "`condition_hex` must be `[51, marker_puzzle_hash, marker_coin_amount_mojos, [tag_memo_hex, payload_memo_hex]]`" in text
    assert "`memos_hex` in the same carrier order" in text
    assert "does not select funding coins, compute a marker coin id, create a spend bundle" in text
    assert "request or return wallet signatures, push to coinset, or broadcast" in text


def test_genesis_readme_pins_genesis_completion_and_handoff_bundle_contract() -> None:
    text = " ".join(_readme().split())

    assert "Genesis ceremony completion and handoff bundle contract" in text
    assert "Completion has separate, visible stages" in text
    assert "Genesis is **recorded and locked** when `POST /admin/bootstrap/finalize` succeeds" in text
    assert "persists `admin_records.json`, `portal_runtime_config.json`, `bootstrap_recovery_anchor.json`, then `bootstrap_manifest.json`" in text
    assert "Genesis is **locally verified** when recovery tooling verifies the returned public artifacts" in text
    assert "compares the recovered `admin_authority_v2` launcher/state hash against live chain state" in text
    assert "Genesis is **operator-exported** when the operator saves `recovery_handoff_bundle.json`" in text
    assert "convenience container, not a new authority source" in text
    assert "validate the contained public artifacts exactly as if each JSON file was supplied separately" in text
    assert "Genesis is **chain-discoverable** only after an operator wallet actually signs and broadcasts the marker-coin transaction" in text
    assert "Portal publish-intent, `CREATE_COIN` preview, and bundle export do not sign, broadcast, create marker coins, or grant admin authority" in text
    assert "Post-genesis admin operation is complete only when normal admin actions are gated by the live `admin_authority_v2` authority" in text


def test_genesis_readme_pins_recovery_handoff_bundle_public_only_shape() -> None:
    text = " ".join(_readme().split())

    assert "The portal-produced `recovery_handoff_bundle.json` must remain public-only" in text
    for field in (
        "`artifacts.bootstrap_manifest`",
        "`artifacts.portal_runtime_config`",
        "`artifacts.bootstrap_recovery_anchor`",
        "`artifacts.admin_records`",
        "current recovery verifier status",
        "current chain-state comparison status",
        "`recovery_anchor_publish_intent`",
        "`recovery_anchor_create_coin_preview`",
    ):
        assert field in text
    for forbidden in (
        "`POPULIS_ADMIN_TOKEN`",
        "bootstrap cookies/JWTs",
        "bearer tokens",
        "raw wallet signatures",
        "auth nonces",
        "admin JWT secrets",
        "faucet private keys",
        "private mnemonics",
        "private URLs",
        "spend bundles",
        "marker coin ids",
        "parent coin ids",
        "future spends",
    ):
        assert forbidden in text
    assert "downloaded as an explicit operator action" in text
    assert "must not persist it to `localStorage` or `sessionStorage`" in text


def test_genesis_readme_pins_bootstrap_off_chain_dependency_ledger() -> None:
    text = " ".join(_readme().split())

    assert "Bootstrap off-chain dependency ledger" in text
    assert "recovery-anchor stack must remain small and auditable" in text
    assert "New off-chain materials are not authority unless this ledger names them" in text
    assert "hash/validation boundary pins them" in text
    assert "complete genesis audit artifact set is exactly" in text
    for artifact in (
        "`deployment_manifest.json`",
        "`admin_records.json`",
        "`portal_runtime_config.json`",
        "`bootstrap_manifest.json`",
        "`bootstrap_recovery_anchor.json`",
    ):
        assert artifact in text
    assert "`deployment_manifest.json` is the base protocol deployment input" in text
    assert "`bootstrap_manifest.artifact_hashes.deployment_manifest_json`" in text
    assert "needed for full genesis replay" in text
    assert "compact recovery anchor does not duplicate every deployment field" in text
    assert "`admin_records.json` is the recovery-critical roster reveal" in text
    assert "`admin_records_hash` proves integrity" in text
    assert "hash alone cannot reconstruct admin slots, leaves, or quorum metadata" in text
    assert "`portal_runtime_config.json` is read-only discovery config" in text
    assert "not an authority source and not an authorization token" in text
    assert "`bootstrap_manifest.json` is the local lock and commitment bundle" in text
    assert "`bootstrap_recovery_anchor.json` is the compact chain-visible payload" in text
    assert "publish intent and `CREATE_COIN` preview are derived, non-authority handoff views" in text
    assert "must not become required durable authority artifacts" in text
    assert "HTTP, GitHub, Git, IPFS, Arweave, API, portal, and coinset URLs are optional locators only" in text
    assert "They help find bytes; they never decide whether bytes are valid" in text
    assert "Marker puzzle hash, marker coin id, parent coin id, future spend, spend bundle" in text
    assert "must not be added to the recovery authority set" in text


def test_genesis_readme_pins_bootstrap_recovery_verification_contract() -> None:
    text = " ".join(_readme().split())

    assert "Bootstrap recovery verification contract" in text
    assert "Recovery tooling must verify the hash chain before trusting a recovered genesis package" in text
    assert "scanning chain-visible output memos for the UTF-8 tag `POPULIS_BOOTSTRAP_V1`" in text
    assert "parse the payload memo from the same marker output" in text
    assert "payload memo to parse as JSON" in text
    assert "pinned v1 recovery-anchor fields" in text
    assert "byte-for-byte equal to `canonical_json_bytes(payload)`" in text
    assert "`bootstrap_manifest_hash`, `portal_runtime_config_hash`, and `admin_records_hash` to be canonical `sha256:` content hashes" in text
    assert "`authority_version` to match the live authority state being recovered" in text
    assert "Obtain candidate `bootstrap_manifest.json`, `portal_runtime_config.json`, and `admin_records.json`" in text
    assert "obtain `deployment_manifest.json` when full genesis replay is required" in text
    assert "`content_hash(bootstrap_manifest.json) == bootstrap_manifest_hash`" in text
    assert "`content_hash(portal_runtime_config.json) == portal_runtime_config_hash`" in text
    assert "`content_hash(admin_records.json) == admin_records_hash`" in text
    assert "`bootstrap_manifest.artifact_hashes.portal_runtime_config_json == portal_runtime_config_hash`" in text
    assert "`bootstrap_manifest.artifact_hashes.admin_records_json == admin_records_hash`" in text
    assert "agree on `admin_authority_v2.launcher_id`, `admins_hash`, `mips_root`, and `authority_version`" in text
    assert "verify those coordinates against the live `admin_authority_v2` singleton state" in text
    assert "Reject any recovered artifact or memo containing forbidden credential markers" in text
    for forbidden in (
        "`POPULIS_ADMIN_TOKEN`",
        "bootstrap cookies/JWTs",
        "bearer tokens",
        "raw signatures",
        "auth nonces",
        "admin JWT secrets",
        "faucet private keys",
        "private mnemonics",
        "private URLs",
        "mutable service credentials",
    ):
        assert forbidden in text
    assert "Ignore non-authority carrier and transport fields during validation" in text
    assert "marker puzzle hash, marker coin id, parent coin id, future spend" in text
    assert "transaction id, spend bundle, API host, portal host, coinset host, and locator URL" in text
    assert "Conflicting anchors for the same `network`, `admin_authority_v2_launcher_id`, and `authority_version`" in text
    assert "must be rejected or escalated for manual operator/auditor review" in text
    assert "first code boundary for this contract is the pure `verify_bootstrap_recovery_artifacts` helper" in text
    assert "treat fetched JSON as untrusted input and call this verifier" in text
    assert "before displaying an admin roster as trusted or using it for admin login decisions" in text


def test_genesis_readme_pins_recovery_verifier_api_contract() -> None:
    text = " ".join(_readme().split())

    assert "Bootstrap recovery verifier API contract" in text
    assert "`POST /admin/bootstrap/recovery-anchor/verify` is a public, non-mutating verification boundary" in text
    for field in (
        "`bootstrap_recovery_anchor`",
        "`bootstrap_manifest`",
        "`portal_runtime_config`",
        "`admin_records`",
        "`deployment_manifest`",
        "`live_admin_authority_v2`",
    ):
        assert field in text
    assert "Every supplied object is treated as untrusted input" in text
    assert "calls `verify_bootstrap_recovery_artifacts`" in text
    assert "returns `verified: true` only when the canonical content hashes" in text
    assert "requires no bootstrap cookie, admin JWT, bearer token, or `POPULIS_ADMIN_TOKEN`" in text
    assert "grants no authority and reads no private server state" in text
    assert "must not read or write persisted bootstrap artifacts" in text
    assert "sign, broadcast, mint, create marker coins, or grant admin login" in text
    assert "Failures return `verified: false` with an error string" in text
    for forbidden in (
        "spend bundles",
        "marker coin ids",
        "marker puzzle hashes",
        "parent coin ids",
        "future spends",
        "wallet signatures",
        "cookies",
        "bearer credentials",
        "private locators",
    ):
        assert forbidden in text
