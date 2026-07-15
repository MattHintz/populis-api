#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 1 ] || { echo "usage: sudo $0 SIGNED_ARTIFACT_JSON" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

artifact="$(readlink -f "$1")"
[ -f "$artifact" ] || { echo "signed artifact is missing" >&2; exit 1; }
release_dir="$(readlink -f /opt/solslot/validator/current)"
[ -d "$release_dir" ] || { echo "validator release is not installed" >&2; exit 1; }

artifact_hash="$(
  "$release_dir/.venv/bin/python" - "$artifact" "$release_dir/release.json" <<'PY'
import json
import sys

from solslot_api.public_artifact import verify_signed_public_artifact_file

artifact = verify_signed_public_artifact_file(sys.argv[1])
with open(sys.argv[2], encoding="utf-8") as stream:
    release = json.load(stream)
sources = artifact.get("sourceShas", {})
if sources.get("api") != release.get("api_commit"):
    raise SystemExit("artifact API commit does not match the installed validator release")
if sources.get("protocol") != release.get("protocol_commit"):
    raise SystemExit("artifact protocol commit does not match the installed validator release")
print(artifact["artifactHash"])
PY
)"

target=/var/lib/solslot-validator/public_artifact_v2.json
temporary="$(mktemp /var/lib/solslot-validator/.public-artifact.XXXXXX)"
trap 'rm -f "$temporary"' EXIT
install -m 0640 -o solslot-validator -g solslot-validator "$artifact" "$temporary"
mv -f "$temporary" "$target"
trap - EXIT
systemctl restart solslot-validator.service
systemctl is-active --quiet solslot-validator.service
printf '%s\n' "$artifact_hash"
