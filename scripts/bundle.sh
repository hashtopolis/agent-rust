#!/usr/bin/env bash
#
# Build the agent per platform and bundle the binaries into
# dist/rust-agent.zip, the artifact the backend serves as the "rust" agent type.
#
# Every target is built natively on its own OS (no cross-compilation), so the
# work is split into two steps that the release workflow runs on different
# runners:
#
#   ./scripts/bundle.sh build <rust-target> [cargo-subcommand]
#       build one target and stage it under dist/rust-agent/. The subcommand
#       defaults to `build` (native host, system linker); pass e.g. `zigbuild`
#       to cross-build instead.
#   ./scripts/bundle.sh package
#       write the manifest and launchers for the staged binaries and zip them
#
# `package` requires a staged binary for every target below, so a full bundle
# is only produced by CI (or by collecting the binaries from each OS).
#
# Requires: rustup, cargo; `package` also needs jq and zip.

set -euo pipefail

cd "$(dirname "$0")/.."

BIN_NAME="htp-agent"
DIST_DIR="dist"
STAGE_DIR="$DIST_DIR/rust-agent"
ZIP_PATH="$DIST_DIR/rust-agent.zip"

# Each entry: <rust-target>|<binary-filename>|<os>|<arch>|<equivalent-triples-csv>
# The binary is staged as <rust-target>/<binary-filename>. equivalent-triples
# lets a running agent match its own compiled-in triple even when the bundle
# ships a compatible build (musl serving gnu hosts; windows-gnu serving msvc
# hosts).
TARGETS=(
    "x86_64-unknown-linux-musl|$BIN_NAME|linux|x86_64|x86_64-unknown-linux-musl,x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu|$BIN_NAME.exe|windows|x86_64|x86_64-pc-windows-gnu,x86_64-pc-windows-msvc"
    "aarch64-apple-darwin|$BIN_NAME|macos|aarch64|aarch64-apple-darwin"
)

die() {
    echo "!! $*" >&2
    exit 1
}

usage() {
    die "usage: $0 build <rust-target> [cargo-subcommand] | package"
}

lookup() {
    local wanted="$1" entry

    for entry in "${TARGETS[@]}"; do
        if [[ "${entry%%|*}" == "$wanted" ]]; then
            echo "$entry"
            return 0
        fi
    done

    return 1
}

build() {
    local target="$1" cargo_cmd="${2:-build}" entry binfile src

    entry="$(lookup "$target")" || die "unknown target: $target"
    IFS='|' read -r _ binfile _ _ _ <<<"$entry"

    echo ">> building $target (cargo $cargo_cmd)"
    rustup target add "$target"
    cargo "$cargo_cmd" --release --locked --target "$target"

    src="target/$target/release/$binfile"
    [[ -f "$src" ]] || die "expected binary not found: $src"

    mkdir -p "$STAGE_DIR/$target"
    cp "$src" "$STAGE_DIR/$target/$binfile"
    echo ">> staged $STAGE_DIR/$target/$binfile"
}

package() {
    local version entry target binfile os arch triples staged triples_json
    local manifest_targets="[]"

    version="$(cargo metadata --format-version 1 --no-deps \
        | jq -r '.packages[] | select(.name=="htp-agent-rust") | .version')"
    echo ">> packaging rust-agent v$version"

    for entry in "${TARGETS[@]}"; do
        IFS='|' read -r target binfile os arch triples <<<"$entry"

        staged="$STAGE_DIR/$target/$binfile"
        [[ -f "$staged" ]] || die "missing staged binary: $staged (run '$0 build $target' on its host)"

        # Artifact transfers between CI jobs drop the executable bit.
        chmod +x "$staged"

        triples_json="$(jq -cn --arg t "$triples" '$t | split(",")')"
        manifest_targets="$(jq -c \
            --arg path "$target/$binfile" \
            --arg os "$os" \
            --arg arch "$arch" \
            --argjson triples "$triples_json" \
            '. += [{path: $path, os: $os, arch: $arch, triples: $triples}]' \
            <<<"$manifest_targets")"
    done

    jq -n \
        --arg agent_type "rust" \
        --arg version "$version" \
        --arg built_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson binaries "$manifest_targets" \
        '{agent_type: $agent_type, version: $version, built_at: $built_at, binaries: $binaries}' \
        >"$STAGE_DIR/manifest.json"

    # Platform-detecting launchers so a user can run the bundle without reaching
    # into a per-target subfolder.
    cp scripts/launcher/run.sh "$STAGE_DIR/run.sh"
    cp scripts/launcher/run.bat "$STAGE_DIR/run.bat"
    chmod +x "$STAGE_DIR/run.sh"

    echo ">> writing $ZIP_PATH"
    rm -f "$ZIP_PATH"
    ( cd "$DIST_DIR" && zip -r -q "rust-agent.zip" "rust-agent" )

    echo ">> done"
    unzip -l "$ZIP_PATH"
}

case "${1:-}" in
    build)
        [[ $# -eq 2 || $# -eq 3 ]] || usage
        build "$2" "${3:-build}"
        ;;
    package)
        [[ $# -eq 1 ]] || usage
        package
        ;;
    *)
        usage
        ;;
esac
