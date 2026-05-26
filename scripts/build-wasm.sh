#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WASM_DIR="$ROOT/wasm-engine"
OUT_DIR="$ROOT/public/wasm"

echo "==> Building Rust WASM engine..."
cd "$WASM_DIR"
wasm-pack build --target bundler --out-dir pkg --release

echo "==> Copying WASM artifact to public/wasm/..."
mkdir -p "$OUT_DIR"
cp pkg/firewall_engine_bg.wasm "$OUT_DIR/firewall_engine_bg.wasm"

echo "==> Done. Artifact: public/wasm/firewall_engine_bg.wasm"
