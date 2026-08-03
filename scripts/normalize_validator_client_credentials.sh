#!/usr/bin/env bash
set -euo pipefail

service=""
credential_root=""
drop_in=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --service)
      service="${2:-}"
      shift 2
      ;;
    --credential-root)
      credential_root="${2:-}"
      shift 2
      ;;
    --drop-in)
      drop_in="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! "$service" =~ ^[A-Za-z0-9_.@-]+\.service$ ]]; then
  echo "--service must be a systemd .service unit name." >&2
  exit 2
fi
if [[ "$credential_root" != /* ]]; then
  echo "--credential-root must be absolute." >&2
  exit 2
fi
drop_in="${drop_in:-/etc/systemd/system/$service.d/20-validator-fleet.conf}"
test -f "$drop_in"
test -f "$credential_root/ca.crt"
test -f "$credential_root/coordinator.crt"
test -f "$credential_root/coordinator.key"

python3 - "$drop_in" "$service" "$credential_root" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
service = sys.argv[2]
root = sys.argv[3]
keys = (
    "SOLSLOT_ZKPASSPORT_VALIDATOR_MTLS_CA_PATH",
    "SOLSLOT_ZKPASSPORT_VALIDATOR_MTLS_CERT_PATH",
    "SOLSLOT_ZKPASSPORT_VALIDATOR_MTLS_KEY_PATH",
)
credential_names = ("validator-ca", "validator-client-cert", "validator-client-key")
lines = path.read_text(encoding="utf-8").splitlines()
lines = [
    line
    for line in lines
    if not any(line.startswith(f"Environment={key}=") for key in keys)
    and not any(line.startswith(f"LoadCredential={name}:") for name in credential_names)
]
try:
    service_index = lines.index("[Service]")
except ValueError as exc:
    raise SystemExit("validator drop-in has no [Service] section") from exc

insert = [
    f"LoadCredential=validator-ca:{root}/ca.crt",
    f"LoadCredential=validator-client-cert:{root}/coordinator.crt",
    f"LoadCredential=validator-client-key:{root}/coordinator.key",
    f"Environment={keys[0]}=/run/credentials/{service}/validator-ca",
    f"Environment={keys[1]}=/run/credentials/{service}/validator-client-cert",
    f"Environment={keys[2]}=/run/credentials/{service}/validator-client-key",
]
lines[service_index + 1:service_index + 1] = insert
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

chmod 0644 "$credential_root/ca.crt" "$credential_root/coordinator.crt"
chmod 0600 "$credential_root/coordinator.key" "$drop_in"
echo "Normalized validator client credentials for $service."
