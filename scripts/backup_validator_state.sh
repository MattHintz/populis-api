#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$#" -eq 1 ] || { echo "usage: $0 BACKUP_ROOT" >&2; exit 2; }
command -v sqlite3 >/dev/null
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
source_dir="/var/lib/solslot-validator"
target="$1/$timestamp"
mkdir -p "$target"
chmod 0700 "$target"
for name in signatures_v2.db; do
  if [ -f "$source_dir/$name" ]; then
    sqlite3 "$source_dir/$name" ".backup '$target/$name'"
  fi
done
for name in public_artifact_v2.json; do
  [ ! -f "$source_dir/$name" ] || cp --preserve=mode,timestamps "$source_dir/$name" "$target/$name"
done
sha256sum "$target"/* > "$target/SHA256SUMS"
printf '%s\n' "$target"
