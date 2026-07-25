#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo scripts/configure_testnet11_full_node.sh [options]

Options:
  --chia-root PATH      Dedicated Testnet11 root
  --chia-bin PATH       Chia CLI executable
  --service-user USER   Unprivileged node owner
  --service NAME        systemd unit name (default: solslot-chia-testnet11.service)
  --rpc-port PORT       Loopback RPC port (default: 8555)
EOF
}

CHIA_ROOT="/opt/solslot/chia-testnet11"
CHIA_BIN="/home/hiram/.local/bin/chia"
SERVICE_USER="hiram"
SERVICE="solslot-chia-testnet11.service"
RPC_PORT="8555"

while (($#)); do
  case "$1" in
    --chia-root) CHIA_ROOT="${2:?missing path}"; shift 2 ;;
    --chia-bin) CHIA_BIN="${2:?missing path}"; shift 2 ;;
    --service-user) SERVICE_USER="${2:?missing user}"; shift 2 ;;
    --service) SERVICE="${2:?missing service}"; shift 2 ;;
    --rpc-port) RPC_PORT="${2:?missing port}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi
id "$SERVICE_USER" >/dev/null
if [[ ! -x "$CHIA_BIN" ]]; then
  echo "Chia executable is unavailable: $CHIA_BIN" >&2
  exit 1
fi
if [[ ! "$RPC_PORT" =~ ^[0-9]+$ ]] || ((RPC_PORT < 1 || RPC_PORT > 65535)); then
  echo "Invalid RPC port: $RPC_PORT" >&2
  exit 1
fi

install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$CHIA_ROOT"
available_kib="$(df -Pk "$CHIA_ROOT" | awk 'NR == 2 {print $4}')"
if [[ ! "$available_kib" =~ ^[0-9]+$ ]] || ((available_kib < 20 * 1024 * 1024)); then
  echo "At least 20 GiB of free disk is required for the Testnet11 node." >&2
  exit 1
fi

run_chia() {
  sudo -H -u "$SERVICE_USER" env CHIA_ROOT="$CHIA_ROOT" "$CHIA_BIN" "$@"
}

if [[ ! -f "$CHIA_ROOT/config/config.yaml" ]]; then
  run_chia init
fi
run_chia configure --testnet true --enable-upnp false

read_config() {
  local field="$1"
  awk -v field="$field" '
    /^full_node:/ { section = 1; next }
    section && /^[^[:space:]]/ { section = 0 }
    section && $1 == field ":" { print $2; exit }
  ' "$CHIA_ROOT/config/config.yaml"
}

network="$(read_config selected_network)"
configured_rpc_port="$(read_config rpc_port)"
if [[ "$network" != "testnet11" ]]; then
  echo "Dedicated Chia root did not configure Testnet11 (got $network)." >&2
  exit 1
fi
if [[ "$configured_rpc_port" != "$RPC_PORT" ]]; then
  echo "Dedicated Chia RPC port is $configured_rpc_port, expected $RPC_PORT." >&2
  exit 1
fi

cat >/etc/systemd/system/"$SERVICE" <<EOF
[Unit]
Description=Solslot Chia Testnet11 Full Node
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$SERVICE_USER
Group=$SERVICE_USER
Environment=CHIA_ROOT=$CHIA_ROOT
ExecStart=$CHIA_BIN start full_node -r
ExecStop=$CHIA_BIN stop full_node
RemainAfterExit=yes
TimeoutStartSec=120
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
for _ in $(seq 1 60); do
  if ss -ltn | grep -Eq "127\\.0\\.0\\.1:$RPC_PORT[[:space:]]"; then
    echo "Dedicated Testnet11 full node is listening on 127.0.0.1:$RPC_PORT."
    exit 0
  fi
  sleep 1
done

systemctl status "$SERVICE" --no-pager || true
echo "Testnet11 full-node RPC did not start on loopback." >&2
exit 1
