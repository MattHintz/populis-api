#!/usr/bin/env bash
set -euo pipefail
umask 077

confirmation="GENERATE-SOLSLOT-VALIDATOR-NETWORK-MATERIAL"
if [ "$#" -ne 2 ] || [ "$2" != "$confirmation" ]; then
  echo "usage: $0 OUTPUT_DIR $confirmation" >&2
  exit 2
fi
output_dir="$1"
if [ -d "$output_dir" ] && find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  echo "output directory must be absent or empty" >&2
  exit 1
fi
command -v openssl >/dev/null
command -v wg >/dev/null
mkdir -p "$output_dir/private/mtls" "$output_dir/private/wireguard" "$output_dir/public/mtls" "$output_dir/public/wireguard"
chmod 0700 "$output_dir" "$output_dir/private" "$output_dir/private/mtls" "$output_dir/private/wireguard" "$output_dir/public"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$output_dir/private/mtls/ca.key"
openssl req -x509 -new -sha256 -days 825 \
  -key "$output_dir/private/mtls/ca.key" \
  -subj "/CN=Solslot Validator V2 Private CA" \
  -out "$output_dir/public/mtls/ca.crt"

issue_certificate() {
  local name="$1"
  local usage="$2"
  local san="$3"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$output_dir/private/mtls/$name.key"
  openssl req -new -sha256 \
    -key "$output_dir/private/mtls/$name.key" \
    -subj "/CN=$name" \
    -addext "subjectAltName=$san" \
    -out "$output_dir/private/mtls/$name.csr"
  printf 'extendedKeyUsage=%s\nsubjectAltName=%s\n' "$usage" "$san" \
    > "$output_dir/private/mtls/$name.ext"
  openssl x509 -req -sha256 -days 397 \
    -in "$output_dir/private/mtls/$name.csr" \
    -CA "$output_dir/public/mtls/ca.crt" \
    -CAkey "$output_dir/private/mtls/ca.key" \
    -CAcreateserial \
    -extfile "$output_dir/private/mtls/$name.ext" \
    -out "$output_dir/public/mtls/$name.crt"
  rm -f "$output_dir/private/mtls/$name.csr" "$output_dir/private/mtls/$name.ext"
}

issue_certificate coordinator clientAuth 'IP:10.77.0.1'
issue_certificate signer-0 serverAuth 'IP:10.77.0.10'
issue_certificate signer-1 serverAuth 'IP:10.77.0.11'
issue_certificate signer-2 serverAuth 'IP:10.77.0.12'

for peer in coordinator signer-0 signer-1 signer-2; do
  wg genkey > "$output_dir/private/wireguard/$peer.key"
  wg pubkey < "$output_dir/private/wireguard/$peer.key" \
    > "$output_dir/public/wireguard/$peer.pub"
done
find "$output_dir/private" -type f -exec chmod 0600 {} +
find "$output_dir/public" -type f -exec chmod 0600 {} +
sha256sum "$output_dir"/public/mtls/*.crt "$output_dir"/public/wireguard/*.pub \
  > "$output_dir/public/SHA256SUMS"
printf '%s\n' "$output_dir/public/SHA256SUMS"
