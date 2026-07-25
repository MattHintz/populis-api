#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo scripts/configure_local_chia_provider.sh [options]

Options:
  --chia-root PATH      Existing Chia root (default: auto-detect)
  --shared-root PATH    API shared root (default: /opt/solslot/api-staging/shared)
  --env-file PATH       API environment file (default: <shared-root>/.env)
  --service NAME        API systemd service (default: solslot-api-staging.service)
  --service-user NAME   API service user (default: solslot-api)
  --network NAME        Required Chia network (default: testnet11)
  --rpc-port PORT       Local full-node RPC port (default: 8555)
  --no-restart          Configure and verify without restarting the API
EOF
}

CHIA_ROOT="${CHIA_ROOT:-}"
SHARED_ROOT="/opt/solslot/api-staging/shared"
ENV_FILE=""
SERVICE="solslot-api-staging.service"
SERVICE_USER="solslot-api"
NETWORK="testnet11"
RPC_PORT="8555"
RESTART=1

while (($#)); do
  case "$1" in
    --chia-root) CHIA_ROOT="${2:?missing path}"; shift 2 ;;
    --shared-root) SHARED_ROOT="${2:?missing path}"; shift 2 ;;
    --env-file) ENV_FILE="${2:?missing path}"; shift 2 ;;
    --service) SERVICE="${2:?missing service}"; shift 2 ;;
    --service-user) SERVICE_USER="${2:?missing user}"; shift 2 ;;
    --network) NETWORK="${2:?missing network}"; shift 2 ;;
    --rpc-port) RPC_PORT="${2:?missing port}"; shift 2 ;;
    --no-restart) RESTART=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi
if [[ -z "$ENV_FILE" ]]; then
  ENV_FILE="$SHARED_ROOT/.env"
fi
if [[ ! "$RPC_PORT" =~ ^[0-9]+$ ]] || ((RPC_PORT < 1 || RPC_PORT > 65535)); then
  echo "Invalid RPC port: $RPC_PORT" >&2
  exit 1
fi
id "$SERVICE_USER" >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null

if [[ -z "$CHIA_ROOT" ]]; then
  mapfile -t roots < <(
    find /home /root -maxdepth 6 -type f \
      -path '*/.chia/mainnet/config/config.yaml' -printf '%h\n' 2>/dev/null \
      | sort -u
  )
  if ((${#roots[@]} != 1)); then
    echo "Could not uniquely identify the Chia root; pass --chia-root PATH." >&2
    exit 1
  fi
  CHIA_ROOT="${roots[0]}"
fi

CA_DIR="$CHIA_ROOT/config/ssl/ca"
CA_CERT="$CA_DIR/private_ca.crt"
CA_KEY="$CA_DIR/private_ca.key"
for path in "$CHIA_ROOT/config/config.yaml" "$CA_CERT" "$CA_KEY"; do
  if [[ ! -r "$path" ]]; then
    echo "Required Chia file is unavailable: $path" >&2
    exit 1
  fi
done

TLS_DIR="$SHARED_ROOT/tls/chia"
CLIENT_KEY="$TLS_DIR/solslot_api.key"
CLIENT_CERT="$TLS_DIR/solslot_api.crt"
CLIENT_CA="$TLS_DIR/private_ca.crt"
install -d -m 0750 -o root -g "$SERVICE_USER" "$SHARED_ROOT" "$TLS_DIR"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
reuse_client=0
if [[ -r "$CLIENT_KEY" && -r "$CLIENT_CERT" && -r "$CLIENT_CA" ]] \
  && openssl verify -CAfile "$CA_CERT" "$CLIENT_CERT" >/dev/null 2>&1 \
  && openssl x509 -checkend 2592000 -noout -in "$CLIENT_CERT" >/dev/null 2>&1 \
  && cmp -s "$CA_CERT" "$CLIENT_CA"; then
  reuse_client=1
fi

if ((reuse_client == 0)); then
  openssl req -new -newkey rsa:2048 -nodes \
    -subj "/CN=solslot-api-local-chia" \
    -keyout "$tmp_dir/client.key" \
    -out "$tmp_dir/client.csr" >/dev/null 2>&1
  cat >"$tmp_dir/extensions.cnf" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
  openssl x509 -req -sha256 -days 825 \
    -in "$tmp_dir/client.csr" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAserial "$tmp_dir/private_ca.srl" \
    -CAcreateserial \
    -extfile "$tmp_dir/extensions.cnf" \
    -out "$tmp_dir/client.crt" >/dev/null 2>&1

  install -m 0640 -o root -g "$SERVICE_USER" "$tmp_dir/client.key" "$CLIENT_KEY"
  install -m 0644 -o root -g "$SERVICE_USER" "$tmp_dir/client.crt" "$CLIENT_CERT"
  install -m 0644 -o root -g "$SERVICE_USER" "$CA_CERT" "$CLIENT_CA"
fi

python3 - "$CLIENT_CA" "$CLIENT_CERT" "$CLIENT_KEY" "$RPC_PORT" "$NETWORK" <<'PY'
import json
import ssl
import sys
import urllib.request

ca, cert, key, port, expected_network = sys.argv[1:]
context = ssl.create_default_context(cafile=ca)
context.load_cert_chain(certfile=cert, keyfile=key)
context.check_hostname = False

def rpc(path):
    request = urllib.request.Request(
        f"https://127.0.0.1:{port}/{path}",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        payload = json.load(response)
    if payload.get("success") is False:
        raise SystemExit(f"Local Chia RPC rejected {path}")
    return payload

network = rpc("get_network_info").get("network_name")
if network != expected_network:
    raise SystemExit(
        f"Local Chia network mismatch: expected {expected_network}, got {network}"
    )
state = rpc("get_blockchain_state").get("blockchain_state") or {}
if not (state.get("sync") or {}).get("synced"):
    raise SystemExit("Local Chia full node is not synced")
if not state.get("peak"):
    raise SystemExit("Local Chia full node has no peak")
print(f"Verified local Chia provider on {network}; full node is synced.")
PY

touch "$ENV_FILE"
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
cp -a "$ENV_FILE" "$ENV_FILE.bak.$(date -u +%Y%m%dT%H%M%SZ)"

set_env() {
  local key="$1"
  local value="$2"
  local next="$tmp_dir/env"
  awk -v key="$key" -v value="$value" '
    BEGIN { found = 0 }
    index($0, key "=") == 1 {
      if (!found) print key "=" value
      found = 1
      next
    }
    { print }
    END { if (!found) print key "=" value }
  ' "$ENV_FILE" >"$next"
  install -m 0640 -o root -g "$SERVICE_USER" "$next" "$ENV_FILE"
}

set_env SOLSLOT_CHIA_PRIMARY_URL "https://127.0.0.1:$RPC_PORT"
set_env SOLSLOT_CHIA_FALLBACK_URL "https://testnet11.api.coinset.org"
set_env SOLSLOT_CHIA_PRIMARY_REQUIRED "true"
set_env SOLSLOT_CHIA_PRIMARY_RETRY_COUNT "1"
set_env SOLSLOT_CHIA_RECOVERY_PROBE_SECONDS "30"
set_env SOLSLOT_CHIA_PRIMARY_CA_CERT_PATH "$CLIENT_CA"
set_env SOLSLOT_CHIA_PRIMARY_CLIENT_CERT_PATH "$CLIENT_CERT"
set_env SOLSLOT_CHIA_PRIMARY_CLIENT_KEY_PATH "$CLIENT_KEY"

if ((RESTART)); then
  systemctl restart "$SERVICE"
  systemctl is-active --quiet "$SERVICE"
fi

echo "Local Chia provider configuration installed in $ENV_FILE."
