#!/usr/bin/env bash
#
# Cross-compile the agent for every supported platform and bundle the binaries
# into dist/rust-agent.zip, the artifact the backend serves as the "rust" agent
# type.
#
# Linux (musl) and Windows (gnu) are built with cargo-zigbuild (zig as the
# cross-linker) so they need no per-target C toolchain and build from any host.
# macOS is built natively: zig's linker duplicates the IOKit framework that
# pci-info/sysinfo pull in, which macOS 15+ dyld rejects, so the apple target
# must go through the system linker -- which means the bundle's macOS binary can
# only be produced on a macOS host.
#
# Requires: rustup, cargo-zigbuild, zig (all provided via mise.toml).
# Run with:  mise run bundle    (or ./scripts/bundle.sh)

set -euo pipefail

cd "$(dirname "$0")/.."

BIN_NAME="htp-agent"
DIST_DIR="dist"
STAGE_DIR="$DIST_DIR/rust-agent"
ZIP_PATH="$DIST_DIR/rust-agent.zip"

VERSION="$(cargo metadata --format-version 1 --no-deps \
    | jq -r '.packages[] | select(.name=="htp-agent-rust") | .version')"

# Each entry: <builder>|<rust-target>|<staged-dir>|<binary-filename>|<os>|<arch>|<equivalent-triples-csv>
# builder: "zig" -> cargo zigbuild; "native" -> cargo build (system linker).
# equivalent-triples lets a running agent match its own compiled-in triple even
# when the bundle ships a compatible build (musl serving gnu hosts; windows-gnu
# serving msvc hosts).
TARGETS=(
    "zig|x86_64-unknown-linux-musl|x86_64-unknown-linux-musl|$BIN_NAME|linux|x86_64|x86_64-unknown-linux-musl,x86_64-unknown-linux-gnu"
    "zig|aarch64-unknown-linux-musl|aarch64-unknown-linux-musl|$BIN_NAME|linux|aarch64|aarch64-unknown-linux-musl,aarch64-unknown-linux-gnu"
    "zig|x86_64-pc-windows-gnu|x86_64-pc-windows-gnu|$BIN_NAME.exe|windows|x86_64|x86_64-pc-windows-gnu,x86_64-pc-windows-msvc"
    "native|aarch64-apple-darwin|aarch64-apple-darwin|$BIN_NAME|macos|aarch64|aarch64-apple-darwin"
)

echo ">> building rust-agent v$VERSION"

echo ">> ensuring rustup targets are installed"
rustup target add \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-musl \
    x86_64-pc-windows-gnu \
    aarch64-apple-darwin

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

manifest_targets="[]"

for entry in "${TARGETS[@]}"; do
    IFS='|' read -r builder target dir binfile os arch triples <<<"$entry"

    if [[ "$builder" == "native" && "$os" == "macos" && "$(uname -s)" != "Darwin" ]]; then
        echo "!! skipping $target: macOS binaries must be built on a macOS host" >&2
        continue
    fi

    echo ">> building $target ($builder)"
    if [[ "$builder" == "zig" ]]; then
        cargo zigbuild --release --locked --target "$target"
    else
        cargo build --release --locked --target "$target"
    fi

    src="target/$target/release/$binfile"
    if [[ ! -f "$src" ]]; then
        echo "!! expected binary not found: $src" >&2
        exit 1
    fi

    mkdir -p "$STAGE_DIR/$dir"
    cp "$src" "$STAGE_DIR/$dir/$binfile"
    chmod +x "$STAGE_DIR/$dir/$binfile"

    triples_json="$(jq -cn --arg t "$triples" '$t | split(",")')"
    manifest_targets="$(jq -c \
        --arg path "$dir/$binfile" \
        --arg os "$os" \
        --arg arch "$arch" \
        --argjson triples "$triples_json" \
        '. += [{path: $path, os: $os, arch: $arch, triples: $triples}]' \
        <<<"$manifest_targets")"
done

jq -n \
    --arg agent_type "rust" \
    --arg version "$VERSION" \
    --arg built_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson binaries "$manifest_targets" \
    '{agent_type: $agent_type, version: $version, built_at: $built_at, binaries: $binaries}' \
    >"$STAGE_DIR/manifest.json"

# Platform-detecting launchers so a user can run the bundle without reaching into
# a per-target subfolder.
cp scripts/launcher/run.sh "$STAGE_DIR/run.sh"
cp scripts/launcher/run.bat "$STAGE_DIR/run.bat"
chmod +x "$STAGE_DIR/run.sh"

echo ">> writing $ZIP_PATH"
rm -f "$ZIP_PATH"
( cd "$DIST_DIR" && zip -r -q "rust-agent.zip" "rust-agent" )

echo ">> done"
unzip -l "$ZIP_PATH"
