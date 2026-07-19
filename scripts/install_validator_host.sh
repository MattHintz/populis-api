#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  echo "usage: sudo $0 INDEX WG_IP RELEASE_TGZ VALIDATOR_ENV SEED_FILE CA_CERT SERVER_CERT SERVER_KEY" >&2
  exit 2
}
[ "$#" -eq 8 ] || usage
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

index="$1"
wg_ip="$2"
archive="$(readlink -f "$3")"
env_file="$(readlink -f "$4")"
seed_file="$(readlink -f "$5")"
ca_cert="$(readlink -f "$6")"
server_cert="$(readlink -f "$7")"
server_key="$(readlink -f "$8")"
case "$index:$wg_ip" in
  0:10.77.0.10|1:10.77.0.11|2:10.77.0.12) ;;
  *) echo "signer index and WireGuard IP do not match the fixed topology" >&2; exit 1 ;;
esac
for path in "$archive" "$env_file" "$seed_file" "$ca_cert" "$server_cert" "$server_key"; do
  [ -f "$path" ] || { echo "missing input file" >&2; exit 1; }
done
python3 - "$archive" <<'PY'
import pathlib
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    for member in archive.getmembers():
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe release archive path: {member.name}")
        if member.isdev() or member.isfifo():
            raise SystemExit(f"unsupported special file in release archive: {member.name}")
        if member.issym() or member.islnk():
            target = pathlib.PurePosixPath(member.linkname)
            if target.is_absolute() or ".." in target.parts:
                raise SystemExit(f"unsafe release archive link: {member.name}")
PY
command -v openssl >/dev/null
openssl verify -CAfile "$ca_cert" "$server_cert" >/dev/null
cert_public_key="$(openssl x509 -in "$server_cert" -pubkey -noout \
  | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
private_public_key="$(openssl pkey -in "$server_key" -pubout -outform DER 2>/dev/null \
  | sha256sum | awk '{print $1}')"
[ "$cert_public_key" = "$private_public_key" ] || {
  echo "validator certificate and private key do not match" >&2
  exit 1
}
openssl x509 -in "$server_cert" -noout -ext subjectAltName \
  | grep -q "IP Address:$wg_ip" || {
    echo "validator certificate is not bound to $wg_ip" >&2
    exit 1
  }
ip -brief address show wg0 | grep -q "$wg_ip/" || {
  echo "wg0 is not configured with $wg_ip" >&2
  exit 1
}

id solslot-validator >/dev/null 2>&1 || \
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin solslot-validator
install -d -m 0755 /opt/solslot/validator/releases /etc/solslot-validator/tls
install -d -m 0700 -o solslot-validator -g solslot-validator /var/lib/solslot-validator
install -d -m 0700 /etc/solslot-validator/private
release_id="$(sha256sum "$archive" | awk '{print substr($1,1,24)}')"
release_dir="/opt/solslot/validator/releases/$release_id"
current_link=/opt/solslot/validator/current
previous=""
if [ -L "$current_link" ]; then
  previous="$(readlink -f "$current_link" || true)"
fi
if [ -e "$current_link" ] && [ ! -L "$current_link" ]; then
  echo "validator current path exists and is not a symlink" >&2
  exit 1
fi
if [ ! -f "$release_dir/.release-ready" ]; then
  rm -rf "$release_dir"
  mkdir -p "$release_dir"
  tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$release_dir"
  python_bin="$(command -v python3.12 || command -v python3.11)"
  "$python_bin" -m venv "$release_dir/.venv"
  "$release_dir/.venv/bin/python" -m pip install --upgrade pip wheel
  # Chia 2.7.x requires the yanked zstd 1.5.7.3 wheel exactly.
  "$release_dir/.venv/bin/python" -m pip install \
    -c "$release_dir/constraints.lock" \
    zstd==1.5.7.3
  "$release_dir/.venv/bin/python" -m pip install \
    -c "$release_dir/constraints.lock" \
    -e "$release_dir/protocol" \
    "$release_dir"
  "$release_dir/.venv/bin/python" -m pip check
  "$release_dir/.venv/bin/python" -m py_compile \
    "$release_dir/solslot_api/validator_app.py" \
    "$release_dir/solslot_api/validator_service.py"
  touch "$release_dir/.release-ready"
fi
# The installer runs with a restrictive umask, but the isolated service account
# still needs to traverse and import the immutable release tree.
chown -R root:solslot-validator "$release_dir"
chmod -R u=rwX,g=rX,o= "$release_dir"

"$release_dir/.venv/bin/python" - "$env_file" "$index" "$seed_file" <<'PY'
import os
import pathlib
import sys

from solslot_api.validator_service import load_validator_private_key
from solslot_api.validator_settings import ValidatorSettings

for raw_line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        raise SystemExit("validator environment contains a malformed line")
    key, value = line.split("=", 1)
    if not key.startswith("SOLSLOT_VALIDATOR_"):
        raise SystemExit(f"validator environment contains unexpected key: {key}")
    os.environ[key] = value
os.environ["SOLSLOT_VALIDATOR_SIGNER_INDEX"] = sys.argv[2]
os.environ["SOLSLOT_VALIDATOR_SEED_FILE"] = sys.argv[3]
load_validator_private_key(ValidatorSettings())
PY

install -m 0600 "$seed_file" /etc/solslot-validator/private/validator.seed
install -m 0600 "$server_key" /etc/solslot-validator/private/server.key
install -m 0644 "$ca_cert" /etc/solslot-validator/tls/ca.crt
install -m 0644 "$server_cert" /etc/solslot-validator/tls/server.crt
install -m 0640 -o root -g solslot-validator "$env_file" /etc/solslot-validator/validator.env

unit_template="$release_dir/ops/validator/solslot-validator.service.in"
[ -f "$unit_template" ] || { echo "release lacks validator unit template" >&2; exit 1; }
ln -sfn "$release_dir" "$current_link"
sed -e "s/@SIGNER_INDEX@/$index/g" -e "s/@WIREGUARD_IP@/$wg_ip/g" \
  "$unit_template" > /etc/systemd/system/solslot-validator.service
systemctl daemon-reload
systemctl enable solslot-validator.service

rollback_release() {
  if [ -n "$previous" ] && [ "$previous" != "$current_link" ] && [ -d "$previous" ]; then
    ln -sfn "$previous" "$current_link"
    systemctl restart solslot-validator.service || true
  else
    rm -f "$current_link"
    systemctl stop solslot-validator.service || true
  fi
}

if ! systemctl restart solslot-validator.service; then
  rollback_release
  journalctl -u solslot-validator.service -n 100 --no-pager >&2
  exit 1
fi
validator_ready=false
for _ in $(seq 1 30); do
  if systemctl is-active --quiet solslot-validator.service \
    && ss -ltn | grep -Eq "$wg_ip:9443[[:space:]]"; then
    validator_ready=true
    break
  fi
  sleep 1
done
[ "$validator_ready" = true ] || {
  rollback_release
  echo "validator is not bound to the WireGuard address" >&2
  journalctl -u solslot-validator.service -n 100 --no-pager >&2
  exit 1
}
! ss -ltn | grep -Eq "(0.0.0.0|\[::\]):9443[[:space:]]" || {
  rollback_release
  echo "validator port is publicly bound" >&2
  exit 1
}
find /opt/solslot/validator/releases -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
  | sort -rn | awk 'NR>5 {print $2}' | xargs -r rm -rf
echo "$release_id"
