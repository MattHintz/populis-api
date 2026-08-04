#!/usr/bin/env bash
# Arm or disarm the RC27 Stripe test-mode infrastructure ceiling.
#
# This does not open a signed launch window. The administrator UI remains the
# only transaction-level switch for minting, presales, and purchases.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  manage_stripe_test_rehearsal_ceiling.sh \
    --action arm|disarm \
    --api-sha <40 hex> \
    --protocol-sha <40 hex> \
    --backend-sha <40 hex> \
    --kos-sha <40 hex> \
    --release-tag <coordinated RC tag>
EOF
}

action=""
api_sha=""
protocol_sha=""
backend_sha=""
kos_sha=""
release_tag=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --action) action="${2:-}"; shift 2 ;;
    --api-sha) api_sha="${2:-}"; shift 2 ;;
    --protocol-sha) protocol_sha="${2:-}"; shift 2 ;;
    --backend-sha) backend_sha="${2:-}"; shift 2 ;;
    --kos-sha) kos_sha="${2:-}"; shift 2 ;;
    --release-tag) release_tag="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Stripe rehearsal ceiling management must run as root." >&2
  exit 1
fi
case "$action" in arm|disarm) ;; *) usage >&2; exit 2 ;; esac
for value in "$api_sha" "$protocol_sha" "$backend_sha" "$kos_sha"; do
  if ! [[ "$value" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Every release reference must be an exact lowercase 40-character SHA." >&2
    exit 1
  fi
done
if ! [[ "$release_tag" =~ ^solslot-v2-alpha-rc[0-9]+(\.[0-9]+)?-[0-9]{8}$ ]]; then
  echo "The release tag is not a coordinated RC tag." >&2
  exit 1
fi
if [ "$(hostname)" != "SolomonsLot" ]; then
  echo "Refusing to change the production ceiling on an unexpected host." >&2
  exit 1
fi

api_root=/opt/solslot/api-production
api_shared="$api_root/shared"
api_env="$api_shared/.env"
api_service=solslot-api-production.service
api_port=8791
backend_root=/opt/solslot/backend-production
backend_env="$backend_root/shared/.env"
backend_service=solslot-backend.service
backend_port=5099
telonium_service=telonium.service
telonium_port=5000
reconciler_service=solslot-stripe-reconciliation.service
reconciler_timer=solslot-stripe-reconciliation.timer
refund_timer=solslot-stripe-presale-refunds-production.timer
kos_root=/opt/solslot/key-of-solomon-production
kos_service=solslot-key-of-solomon.service
kos_port=8793
chia_tunnel_service=solslot-chia-rpc-tunnel.service
validator_credentials=/etc/solslot-api/validator-mtls

for path in \
  "$api_root/current/release.json" \
  "$backend_root/current/release.json" \
  "$kos_root/current/release.json" \
  "$api_env" \
  "$backend_env"; do
  test -f "$path" || { echo "Required production file is missing: $path" >&2; exit 1; }
done
for service in \
  "$api_service" "$backend_service" "$telonium_service" \
  "$reconciler_timer" "$refund_timer"; do
  systemctl is-active --quiet "$service" || {
    echo "Required production unit is not active: $service" >&2
    exit 1
  }
done
if [ "$action" = "arm" ]; then
  for service in "$kos_service" "$chia_tunnel_service"; do
    systemctl is-active --quiet "$service" || {
      echo "Required Stripe rehearsal unit is not active: $service" >&2
      exit 1
    }
  done
fi

tmp_dir="$(mktemp -d /run/solslot-stripe-ceiling.XXXXXX)"
chmod 0700 "$tmp_dir"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT

curl -fsS "http://127.0.0.1:$api_port/release" >"$tmp_dir/api-release.json"
curl -fsS "http://127.0.0.1:$telonium_port/healthz" >"$tmp_dir/backend-health.json"
if [ "$action" = "arm" ]; then
  curl -fsS "http://127.0.0.1:$kos_port/healthz" >"$tmp_dir/kos-health.json"
else
  printf '{}\n' >"$tmp_dir/kos-health.json"
fi
python3 - \
  "$api_root/current/release.json" \
  "$backend_root/current/release.json" \
  "$kos_root/current/release.json" \
  "$tmp_dir/api-release.json" \
  "$tmp_dir/backend-health.json" \
  "$tmp_dir/kos-health.json" \
  "$api_sha" "$protocol_sha" "$backend_sha" "$kos_sha" "$release_tag" \
  "$action" <<'PY'
import json
import sys

api_file, backend_file, kos_file, api_live, backend_live, kos_live = (
    json.load(open(path, encoding="utf-8")) for path in sys.argv[1:7]
)
api_sha, protocol_sha, backend_sha, kos_sha, tag, action = sys.argv[7:13]
assert api_file["api_commit"] == api_sha
assert api_file["protocol_commit"] == protocol_sha
assert api_file["release"] == tag
assert backend_file["commit"] == backend_sha
assert backend_file["release"] == tag
assert kos_file["commit"] == kos_sha
assert kos_file["release"] == tag
assert kos_file["network"] == "testnet11"
assert kos_file["executionMode"] == "exact-bundle-only"
assert kos_file["legacyInventoryWorkerEnabled"] is False
assert api_live["available"] is True
assert api_live["release"]["apiCommit"] == api_sha
assert api_live["release"]["protocolCommit"] == protocol_sha
assert backend_live["ok"] is True
assert backend_live["release"] == backend_sha
if action == "arm":
    assert kos_live == {
        "status": "ok",
        "releaseSha": kos_sha,
        "executionMode": "exact-bundle-only",
    }
PY

if [ "$action" = "arm" ]; then
  python3 - "$api_env" "$backend_env" <<'PY'
import pathlib
import sys

def parse(path):
    values = {}
    for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values

api = parse(sys.argv[1])
backend = parse(sys.argv[2])
required_backend = (
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_ACCOUNT_ID",
    "STRIPE_API_VERSION",
    "SOLSLOT_PROTOCOL_CALLBACK_TOKEN",
    "SOLSLOT_TELONIUM_INTERNAL_TOKEN",
)
missing = [name for name in required_backend if not backend.get(name)]
if missing:
    raise SystemExit("backend Stripe configuration is incomplete: " + ", ".join(missing))
if not backend["STRIPE_SECRET_KEY"].startswith("sk_test_"):
    raise SystemExit("RC27 rehearsal requires a Stripe test secret key")
if not backend["STRIPE_WEBHOOK_SECRET"].startswith("whsec_"):
    raise SystemExit("Stripe webhook signing secret is malformed")
if not backend["STRIPE_ACCOUNT_ID"].startswith("acct_"):
    raise SystemExit("Stripe account ID is malformed")
if backend["STRIPE_API_VERSION"] != "2026-02-25.clover":
    raise SystemExit("Stripe API version is not pinned to RC27")
for name in ("SOLSLOT_PROTOCOL_CALLBACK_TOKEN", "SOLSLOT_TELONIUM_INTERNAL_TOKEN"):
    if len(backend[name]) < 32:
        raise SystemExit(f"{name} must contain at least 32 characters")
for name in (
    "SOLSLOT_STRIPE_CREDIT_SURCHARGE_ENABLED",
    "SOLSLOT_STRIPE_CREDIT_SURCHARGE_BPS",
    "SOLSLOT_STRIPE_CREDIT_SURCHARGE_FIXED_MINOR",
):
    value = backend.get(name, "false" if name.endswith("ENABLED") else "0").lower()
    if value not in ({"", "0", "false", "no", "off"} if name.endswith("ENABLED") else {"", "0"}):
        raise SystemExit("credit surcharge must remain disabled for RC27 rehearsal")

required_api = (
    "SOLSLOT_STRIPE_ACCOUNT_ID",
    "SOLSLOT_PAYMENT_KOS_EXECUTOR_URL",
    "SOLSLOT_PAYMENT_KOS_EXECUTOR_PRIVATE_KEY_FILE",
    "SOLSLOT_PAYMENT_KOS_EXECUTOR_PUBLIC_KEY",
    "SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN",
)
missing = [name for name in required_api if not api.get(name)]
if missing:
    raise SystemExit("API Stripe configuration is incomplete: " + ", ".join(missing))
if api["SOLSLOT_STRIPE_ACCOUNT_ID"] != backend["STRIPE_ACCOUNT_ID"]:
    raise SystemExit("API and Telonium Stripe account IDs do not match")
if api.get("SOLSLOT_STRIPE_MODE", "test").lower() != "test":
    raise SystemExit("RC27 rehearsal cannot use Stripe live mode")
if len(api["SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN"]) < 32:
    raise SystemExit("protocol artifact service token is too short")
PY
fi

process_env_value() {
  local service="$1"
  local key="$2"
  local pid
  pid="$(systemctl show "$service" --property=MainPID --value)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  python3 - "$pid" "$key" <<'PY'
import pathlib
import sys

payload = pathlib.Path(f"/proc/{sys.argv[1]}/environ").read_bytes()
key = sys.argv[2].encode("ascii") + b"="
for item in payload.split(b"\0"):
    if item.startswith(key):
        print(item[len(key):].decode("utf-8"))
        raise SystemExit(0)
raise SystemExit(1)
PY
}

if [ "$(process_env_value "$api_service" SOLSLOT_LAUNCH_CONTROL_ENABLED)" != "true" ]; then
  echo "Guided launch control must be active before the Stripe ceiling can change." >&2
  exit 1
fi
genesis_db="$(process_env_value "$api_service" SOLSLOT_GENESIS_DB_PATH)"
delivery_db="$(process_env_value "$api_service" SOLSLOT_STRIPE_DELIVERY_DB_PATH)"
admin_db="$(process_env_value "$api_service" SOLSLOT_ADMIN_DB_PATH)"
checker="$api_root/current/scripts/check_stripe_rehearsal_ceiling.py"
test -x "$checker"
"$api_root/current/.venv/bin/python" "$checker" \
  --mode "$action" \
  --genesis-db "$genesis_db" \
  --delivery-db "$delivery_db" \
  --admin-db "$admin_db"

if [ "$action" = "arm" ]; then
  for credential in ca.crt coordinator.crt coordinator.key; do
    test -f "$validator_credentials/$credential" || {
      echo "Validator client credential is missing: $credential" >&2
      exit 1
    }
  done
  validator_urls="$(process_env_value "$api_service" SOLSLOT_ZKPASSPORT_VALIDATOR_URLS)"
  python3 - "$validator_urls" >"$tmp_dir/validator-urls" <<'PY'
import json
import sys
urls = json.loads(sys.argv[1])
if len(urls) != 3 or len(set(urls)) != 3:
    raise SystemExit("exactly three distinct validator URLs are required")
for url in urls:
    if not isinstance(url, str) or not url.startswith("https://"):
        raise SystemExit("validator URLs must use HTTPS")
    print(url)
PY
  index=0
  while IFS= read -r validator_url; do
    curl -fsS \
      --cacert "$validator_credentials/ca.crt" \
      --cert "$validator_credentials/coordinator.crt" \
      --key "$validator_credentials/coordinator.key" \
      "$validator_url/health" >"$tmp_dir/validator-$index.json"
    index=$((index + 1))
  done <"$tmp_dir/validator-urls"
  python3 - "$api_sha" "$protocol_sha" "$tmp_dir" <<'PY'
import json
import pathlib
import sys
api_sha, protocol_sha, directory = sys.argv[1:]
records = [
    json.load(open(path, encoding="utf-8"))
    for path in sorted(pathlib.Path(directory).glob("validator-*.json"))
]
if len(records) != 3:
    raise SystemExit("all three validator health records are required")
if {record["signerIndex"] for record in records} != {0, 1, 2}:
    raise SystemExit("validator signer slots do not match the 3-member roster")
if len({record["validatorPubkey"] for record in records}) != 3:
    raise SystemExit("validator public keys are not distinct")
for record in records:
    if record.get("status") != "healthy":
        raise SystemExit("a validator is unhealthy")
    if record.get("apiCommit") != api_sha or record.get("protocolCommit") != protocol_sha:
        raise SystemExit("validator release does not match RC27")
    if record.get("network") != "testnet11":
        raise SystemExit("validator is not on Testnet11")
    if record.get("stripeSettlementReady") is not True:
        raise SystemExit("a validator lacks a valid Stripe test read key")
PY
fi

api_dropin="/etc/systemd/system/$api_service.d/zz-stripe-test-rehearsal.conf"
backend_dropin="/etc/systemd/system/$backend_service.d/zz-stripe-test-rehearsal.conf"
telonium_dropin="/etc/systemd/system/$telonium_service.d/zz-stripe-test-rehearsal.conf"
reconciler_dropin="/etc/systemd/system/$reconciler_service.d/zz-stripe-test-rehearsal.conf"
dropins=("$api_dropin" "$backend_dropin" "$telonium_dropin" "$reconciler_dropin")

for path in "${dropins[@]}"; do
  mkdir -p "$(dirname "$path")"
  if [ -f "$path" ]; then
    cp -a "$path" "$tmp_dir/$(basename "$(dirname "$path")").$(basename "$path")"
  else
    touch "$tmp_dir/absent.$(basename "$(dirname "$path")").$(basename "$path")"
  fi
done

restore_dropins() {
  local path parent backup absent
  for path in "${dropins[@]}"; do
    parent="$(basename "$(dirname "$path")")"
    backup="$tmp_dir/$parent.$(basename "$path")"
    absent="$tmp_dir/absent.$parent.$(basename "$path")"
    if [ -f "$backup" ]; then
      cp -a "$backup" "$path"
    elif [ -f "$absent" ]; then
      rm -f "$path"
    fi
  done
  systemctl daemon-reload
  systemctl restart "$backend_service" "$telonium_service" || true
  systemctl restart "$api_service" || true
}

transition_started=false
rollback_on_error() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ "$transition_started" = true ]; then
    echo "Stripe ceiling transition failed; restoring prior service overrides." >&2
    restore_dropins
  fi
  cleanup
  exit "$status"
}
trap rollback_on_error EXIT
transition_started=true

if [ "$action" = "arm" ]; then
  cat >"$api_dropin" <<'EOF'
[Service]
Environment=SOLSLOT_ALPHA_WRITES_ENABLED=true
Environment=SOLSLOT_MINTING_ENABLED=true
Environment=SOLSLOT_COLLECTION_METADATA_ENABLED=true
Environment=SOLSLOT_COLLECTION_MINTING_ENABLED=true
Environment=SOLSLOT_PRESALE_ENABLED=true
Environment=SOLSLOT_VOUCHER_ISSUANCE_WORKER_ENABLED=true
Environment=SOLSLOT_PROTOCOL_FEE_FUNDING_ENABLED=true
Environment=SOLSLOT_STRIPE_SETTLEMENT_ENABLED=true
Environment=SOLSLOT_STRIPE_DELIVERY_WORKER_ENABLED=true
Environment=SOLSLOT_CEREMONY_MODE_ENABLED=false
EOF
  for path in "$backend_dropin" "$telonium_dropin" "$reconciler_dropin"; do
    cat >"$path" <<'EOF'
[Service]
Environment=SOLSLOT_PROTOCOL_PURCHASES_ENABLED=true
Environment=SOLSLOT_STRIPE_SMARTDEED_FULFILLMENT_ENABLED=true
EOF
  done
else
  rm -f "${dropins[@]}"
fi

systemctl daemon-reload
systemd-analyze verify \
  "$api_service" "$backend_service" "$telonium_service" \
  "$reconciler_service" >/dev/null
systemctl restart "$backend_service" "$telonium_service"
systemctl restart "$api_service"
systemctl enable --now "$reconciler_timer" >/dev/null

for attempt in $(seq 1 45); do
  if curl -fsS "http://127.0.0.1:$api_port/health" >/dev/null \
    && curl -fsS "http://127.0.0.1:$telonium_port/healthz" \
      >"$tmp_dir/backend-health-after.json"; then
    break
  fi
  if [ "$attempt" -eq 45 ]; then
    echo "Services did not recover after the Stripe ceiling transition." >&2
    exit 1
  fi
  sleep 1
done

expected=false
if [ "$action" = "arm" ]; then expected=true; fi
for key in \
  SOLSLOT_ALPHA_WRITES_ENABLED \
  SOLSLOT_MINTING_ENABLED \
  SOLSLOT_PRESALE_ENABLED \
  SOLSLOT_PROTOCOL_FEE_FUNDING_ENABLED \
  SOLSLOT_STRIPE_SETTLEMENT_ENABLED \
  SOLSLOT_STRIPE_DELIVERY_WORKER_ENABLED; do
  if [ "$(process_env_value "$api_service" "$key")" != "$expected" ]; then
    echo "API process did not apply $key=$expected." >&2
    exit 1
  fi
done
python3 - "$tmp_dir/backend-health-after.json" "$backend_sha" "$expected" <<'PY'
import json
import sys
health = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[3] == "true"
assert health["ok"] is True
assert health["release"] == sys.argv[2]
assert health["protocolPurchasesEnabled"] is expected
assert health["stripeSmartDeedFulfillmentEnabled"] is expected
PY

"$api_root/current/.venv/bin/python" "$checker" \
  --mode "$action" \
  --genesis-db "$genesis_db" \
  --delivery-db "$delivery_db" \
  --admin-db "$admin_db"
if [ "$action" = "arm" ]; then
  systemctl start "$reconciler_service"
  systemctl is-failed --quiet "$reconciler_service" && {
    echo "Stripe reconciliation worker failed its first armed run." >&2
    exit 1
  }
fi

transition_started=false
trap - EXIT
cleanup
echo "Stripe test rehearsal ceiling is $([ "$action" = arm ] && echo armed || echo disarmed)."
