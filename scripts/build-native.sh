#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)/rust"
cd "$ROOT_DIR"

echo "Building Rust crate (release)..."
cargo build --release

# Find compiled library in target/release
TARGET_DIR="$ROOT_DIR/target/release"
LIB_FILE=""
for ext in so dylib dll; do
    found=$(ls "$TARGET_DIR"/*.$ext 2>/dev/null | head -n 1 || true)
    if [ -n "$found" ]; then
        LIB_FILE="$found"
        break
    fi
done

if [ -z "$LIB_FILE" ]; then
    echo "Could not find compiled native library in $TARGET_DIR" >&2
    exit 1
fi

echo "Found native library: $LIB_FILE"

# Copy it to package root as index.node
cp "$LIB_FILE" "$ROOT_DIR/../index.node"
chmod 755 "$ROOT_DIR/../index.node"

echo "Copied native library to index.node"
