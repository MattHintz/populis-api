#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo scripts/configure_chia_rpc_tunnel.sh [options]

Installs a persistent loopback-only SSH tunnel to an existing Chia full node.
The remote authorized key must be restricted to the requested RPC destination.

Options:
  --remote-host HOST       Pinned Chia node hostname
  --remote-user USER       SSH account (default: ec2-user)
  --identity-file PATH     Restricted forwarding-only private key
  --known-hosts PATH       Pinned SSH host-key file
  --local-port PORT        Coordinator loopback port (default: 18555)
  --remote-port PORT       Chia node loopback RPC port (default: 18555)
  --service-user USER      Local tunnel user (default: solslot-api)
  --service NAME           systemd unit (default: solslot-chia-rpc-tunnel.service)
EOF
}

REMOTE_HOST=""
REMOTE_USER="ec2-user"
IDENTITY_FILE="/etc/solslot-chia-tunnel/id_ed25519"
KNOWN_HOSTS="/etc/solslot-chia-tunnel/known_hosts"
LOCAL_PORT="18555"
REMOTE_PORT="18555"
SERVICE_USER="solslot-api"
SERVICE="solslot-chia-rpc-tunnel.service"

while (($#)); do
  case "$1" in
    --remote-host) REMOTE_HOST="${2:?missing host}"; shift 2 ;;
    --remote-user) REMOTE_USER="${2:?missing user}"; shift 2 ;;
    --identity-file) IDENTITY_FILE="${2:?missing path}"; shift 2 ;;
    --known-hosts) KNOWN_HOSTS="${2:?missing path}"; shift 2 ;;
    --local-port) LOCAL_PORT="${2:?missing port}"; shift 2 ;;
    --remote-port) REMOTE_PORT="${2:?missing port}"; shift 2 ;;
    --service-user) SERVICE_USER="${2:?missing user}"; shift 2 ;;
    --service) SERVICE="${2:?missing service}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi
if [[ ! "$REMOTE_HOST" =~ ^[A-Za-z0-9.-]+$ ]] \
  || [[ ! "$REMOTE_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]]; then
  echo "A valid remote host and user are required." >&2
  exit 1
fi
if [[ ! "$SERVICE" =~ ^[A-Za-z0-9@_.-]+\.service$ ]] \
  || [[ ! "$IDENTITY_FILE" =~ ^/[A-Za-z0-9._/-]+$ ]] \
  || [[ ! "$KNOWN_HOSTS" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
  echo "Service and tunnel file paths contain unsupported characters." >&2
  exit 1
fi
for port in "$LOCAL_PORT" "$REMOTE_PORT"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    echo "Invalid TCP port: $port" >&2
    exit 1
  fi
done
id "$SERVICE_USER" >/dev/null
for path in "$IDENTITY_FILE" "$KNOWN_HOSTS"; do
  if ! runuser -u "$SERVICE_USER" -- test -r "$path"; then
    echo "Tunnel user cannot read required file: $path" >&2
    exit 1
  fi
done
if ! grep -Eq "^${REMOTE_HOST//./\\.}[[:space:]]+(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa)[[:space:]]" "$KNOWN_HOSTS"; then
  echo "Known-hosts file has no explicit pin for $REMOTE_HOST." >&2
  exit 1
fi

unit="/etc/systemd/system/$SERVICE"
cat >"$unit" <<EOF
[Unit]
Description=Solslot Testnet11 Chia RPC Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=/usr/bin/ssh -NT -i $IDENTITY_FILE -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L 127.0.0.1:$LOCAL_PORT:127.0.0.1:$REMOTE_PORT $REMOTE_USER@$REMOTE_HOST
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
for _ in $(seq 1 20); do
  if systemctl is-active --quiet "$SERVICE" \
    && ss -ltn | grep -Eq "127\\.0\\.0\\.1:$LOCAL_PORT[[:space:]]"; then
    echo "Chia RPC tunnel is listening on 127.0.0.1:$LOCAL_PORT."
    exit 0
  fi
  sleep 1
done

systemctl status "$SERVICE" --no-pager || true
echo "Chia RPC tunnel did not become ready." >&2
exit 1
