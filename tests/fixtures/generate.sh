#!/usr/bin/env bash
# Regenerates the TLS test fixtures. Needs OpenSSL 3.0, as shipped in
# rust:1-bookworm: LibreSSL writes v1 where v3 is required, and OpenSSL 3.2+
# writes v3 where client-v1.pem must be v1. The checks at the end catch both.
#   docker run --rm -v "$PWD:/w" -w /w rust:1-bookworm tests/fixtures/generate.sh
#
# The CA key is thrown away on purpose: CI installs test-ca.pem into the OS
# trust store, so nobody should be able to sign further certificates with it.
set -euo pipefail
cd "$(dirname "$0")"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

EC=(-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes)
DAYS=36500

openssl req -x509 "${EC[@]}" -keyout "$work/ca.key" -out test-ca.pem -days "$DAYS" \
    -subj "/CN=htp-agent test CA" 2>/dev/null

# sign <name> <subject> [extensions]: a CA-signed certificate plus its key in <name>.pem.
# Without extensions, OpenSSL writes an X.509 v1 certificate.
sign() {
    local ext=()

    openssl req "${EC[@]}" -keyout "$work/$1.key" -out "$work/$1.csr" -subj "$2" 2>/dev/null

    if [[ -n "${3:-}" ]]; then
        printf '%b' "$3" > "$work/$1.ext"
        ext=(-extfile "$work/$1.ext")
    fi

    openssl x509 -req -in "$work/$1.csr" -CA test-ca.pem -CAkey "$work/ca.key" \
        -CAcreateserial -CAserial "$work/ca.srl" -days "$DAYS" ${ext[@]+"${ext[@]}"} \
        -out "$work/$1.crt" 2>/dev/null
    cat "$work/$1.crt" "$work/$1.key" > "$1.pem"
}

sign localhost "/CN=localhost" \
    "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
sign client-identity "/CN=htp-agent test client" \
    "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n"
sign client-v1 "/CN=htp-agent test client v1"

# expect_version <file> <n>: fail loudly when an OpenSSL build wrote the wrong version.
expect_version() {
    local version
    version=$(openssl x509 -in "$1" -noout -text | grep -m1 'Version:' | xargs)
    printf '%-20s %s\n' "$1" "$version"

    if [[ "$version" != "Version: $2 "* ]]; then
        echo "$1 must be X.509 v$2; regenerate with OpenSSL 3.0 (see the header)" >&2
        exit 1
    fi
}

expect_version test-ca.pem 3
expect_version localhost.pem 3
expect_version client-identity.pem 3
expect_version client-v1.pem 1
