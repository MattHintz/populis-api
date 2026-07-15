#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 1 ] || { echo "usage: $0 SIGNER_INDEX" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
case "$1" in
  0) signer_ip="10.77.0.10" ;;
  1) signer_ip="10.77.0.11" ;;
  2) signer_ip="10.77.0.12" ;;
  *) echo "SIGNER_INDEX must be 0, 1, or 2" >&2; exit 2 ;;
esac
command -v nft >/dev/null
ip -brief address show wg0 | grep -q "$signer_ip/" || {
  echo "wg0 is not configured with the expected signer address" >&2
  exit 1
}
nft delete table inet solslot_validator 2>/dev/null || true
nft -f - <<'EOF'
table inet solslot_validator {
  chain input {
    type filter hook input priority -5; policy accept;
    iifname "wg0" ip saddr 10.77.0.1 tcp dport 9443 accept
    tcp dport 9443 drop
  }
}
EOF
nft list table inet solslot_validator
