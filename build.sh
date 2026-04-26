#!/usr/bin/env bash
set -euo pipefail

# Build repx with nix, injecting the bpf-linker from the dev environment.
#
# Usage:
#   nix develop -c ./build.sh
#   # or if bpf-linker is already installed:
#   ./build.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure bpf-linker is available.
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v bpf-linker &>/dev/null; then
    echo "bpf-linker not found. Installing..."
    cargo install bpf-linker --version 0.10.2
fi

echo "=== Building repx-ebpf ==="
cd "$SCRIPT_DIR/repx-ebpf"
cargo build --release -Z build-std=core --target bpfel-unknown-none

echo "=== Building repx ==="
cd "$SCRIPT_DIR"
REPX_EBPF_BIN="$SCRIPT_DIR/repx-ebpf/target/bpfel-unknown-none/release/repx-ebpf" \
    cargo build --release

echo ""
echo "Build complete!"
echo "  Binary: $SCRIPT_DIR/target/release/repx"
echo "  eBPF:   $SCRIPT_DIR/repx-ebpf/target/bpfel-unknown-none/release/repx-ebpf"
echo ""
echo "Run with: sudo ./target/release/repx trace -o attestation.json -- <command>"
