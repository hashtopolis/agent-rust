#!/bin/sh
# Launcher for the rust-agent bundle: detect this platform, then exec the
# matching binary, forwarding all arguments. Lets a user run the bundle without
# knowing which per-target subfolder to reach into.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"

os="$(uname -s)"
arch="$(uname -m)"

case "$os/$arch" in
  Darwin/arm64)              bin="aarch64-apple-darwin/htp-agent" ;;
  Linux/x86_64)              bin="x86_64-unknown-linux-musl/htp-agent" ;;
  Linux/aarch64 | Linux/arm64) bin="aarch64-unknown-linux-musl/htp-agent" ;;
  *)
    echo "rust-agent: no bundled binary for $os/$arch" >&2
    exit 1
    ;;
esac

target="$here/$bin"

if [ ! -f "$target" ]; then
  echo "rust-agent: missing $bin in the bundle" >&2
  exit 1
fi

# Extraction does not always preserve the executable bit.
[ -x "$target" ] || chmod +x "$target" 2>/dev/null || true

exec "$target" "$@"
