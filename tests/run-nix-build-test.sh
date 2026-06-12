#!/usr/bin/env bash
set -euo pipefail

# Integration test: trace a nix-style build pipeline with repx.
#
# This test traces a multi-step C build that mimics what nix does internally:
#   1. Create a source file and build script
#   2. Trace the full build (preprocess -> compile -> link) under repx
#   3. Run the built binary to verify it works
#   4. Verify the attestation by re-running the exact same build
#
# This exercises: fork/exec chains, mmap (linker), many file open/close
# operations, and multi-process tracking.
#
# Usage:
#   sudo nix run .#test-nix-build
#   sudo ./tests/run-nix-build-test.sh

# Check for root (eBPF requires CAP_BPF / CAP_SYS_ADMIN).
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: eBPF requires root. Run with: sudo $0"
    exit 1
fi

# Find repx binary.
REPX="${REPX:-}"
if [ -z "$REPX" ]; then
    if command -v repx &>/dev/null; then
        REPX="$(command -v repx)"
    else
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || true
        if [ -n "${SCRIPT_DIR:-}" ]; then
            PROJECT_DIR="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)" || true
            if [ -n "${PROJECT_DIR:-}" ]; then
                if [ -x "$PROJECT_DIR/result/bin/repx" ]; then
                    REPX="$PROJECT_DIR/result/bin/repx"
                elif [ -x "$PROJECT_DIR/target/release/repx" ]; then
                    REPX="$PROJECT_DIR/target/release/repx"
                fi
            fi
        fi
    fi
fi
if [ -z "$REPX" ] || [ ! -x "$REPX" ]; then
    echo "ERROR: repx binary not found."
    exit 1
fi

echo "Using repx: $REPX"

DETERMINISM_RUNS="${DETERMINISM_RUNS:-2}"
if ! [[ "$DETERMINISM_RUNS" =~ ^[0-9]+$ ]] || [ "$DETERMINISM_RUNS" -lt 2 ]; then
    echo "ERROR: DETERMINISM_RUNS must be an integer of at least 2."
    exit 1
fi

TMPDIR=$(mktemp -d)
cleanup_tmpdir() {
    local status=$?
    if [ "${KEEP_TMPDIR:-0}" = "1" ] || [ "$status" -ne 0 ]; then
        echo "Keeping temp workspace: $TMPDIR"
    else
        rm -rf "$TMPDIR"
    fi
}
trap cleanup_tmpdir EXIT

echo "=== Setting up multi-file C project ==="

# Create a small multi-file C project to build.
mkdir -p "$TMPDIR/src" "$TMPDIR/build"

cat > "$TMPDIR/src/math.h" << 'EOF'
#ifndef MATH_H
#define MATH_H
int add(int a, int b);
int multiply(int a, int b);
#endif
EOF

cat > "$TMPDIR/src/math.c" << 'EOF'
#include "math.h"
int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }
EOF

cat > "$TMPDIR/src/main.c" << 'EOF'
#include <stdio.h>
#include "math.h"
int main(void) {
    int sum = add(3, 4);
    int product = multiply(5, 6);
    printf("add(3,4) = %d\n", sum);
    printf("multiply(5,6) = %d\n", product);
    printf("combined = %d\n", add(sum, product));
    return 0;
}
EOF

# Create a build script that mimics a nix builder.
# This does separate compilation + linking like a real build system.
cat > "$TMPDIR/build.sh" << 'BUILDEOF'
#!/usr/bin/env bash
set -euo pipefail

SRC="$1"
OUT="$2"

echo "Building from $SRC -> $OUT"

# Step 1: Compile each .c file to .o (separate compilation units).
gcc -c -I"$SRC" -o "$OUT/math.o" "$SRC/math.c"
gcc -c -I"$SRC" -o "$OUT/main.o" "$SRC/main.c"

# Step 2: Link the object files into the final binary.
gcc -o "$OUT/calculator" "$OUT/math.o" "$OUT/main.o"

# Step 3: Run the binary and capture output as a build artifact.
"$OUT/calculator" > "$OUT/output.txt"

echo "Build complete. Output:"
cat "$OUT/output.txt"
BUILDEOF
chmod +x "$TMPDIR/build.sh"

echo "Created multi-file C project in $TMPDIR/src/"
echo "Files: math.h, math.c, main.c, build.sh"
cd "$TMPDIR"

echo ""
echo "=== Trace: building project under repx ==="
"$REPX" trace --output-root "$TMPDIR/build" \
    --dump-ops "$TMPDIR/trace-ops.json" -o "$TMPDIR/attestation.json" -- \
    "$TMPDIR/build.sh" "$TMPDIR/src" "$TMPDIR/build"

echo ""
echo "=== Build output ==="
cat "$TMPDIR/build/output.txt"

echo ""
echo "=== Attestation root hash ==="
# Extract just the root hash for display.
head -5 "$TMPDIR/attestation.json"

echo ""
echo "=== Determinism: repeating the exact same build ==="
attestations=("$TMPDIR/attestation.json")
for ((run = 2; run <= DETERMINISM_RUNS; run++)); do
    rm -rf "$TMPDIR/build"
    mkdir -p "$TMPDIR/build"

    run_attestation="$TMPDIR/run-$run-attestation.json"
    attestations+=("$run_attestation")
    if ! "$REPX" trace --output-root "$TMPDIR/build" \
        --dump-ops "$TMPDIR/run-$run-ops.json" \
        -o "$run_attestation" -- \
        "$TMPDIR/build.sh" "$TMPDIR/src" "$TMPDIR/build"; then
        echo "ERROR: trace run $run failed"
        exit 1
    fi
done

"$REPX" stability --json "${attestations[@]}" > "$TMPDIR/stability.json"
if ! "$REPX" stability --strict "${attestations[@]}"; then
    for candidate in "${attestations[@]:1}"; do
        "$REPX" diff "$TMPDIR/attestation.json" "$candidate" || true
    done
    echo "ERROR: clean traces were not deterministic"
    exit 1
fi

rm -rf "$TMPDIR/build"
mkdir -p "$TMPDIR/build"

"$REPX" verify --output-root "$TMPDIR/build" \
    -a "$TMPDIR/attestation.json" -- \
    "$TMPDIR/build.sh" "$TMPDIR/src" "$TMPDIR/build"

echo ""
echo "=== Verify output still correct ==="
cat "$TMPDIR/build/output.txt"

echo ""
echo "=== Nix Build Test PASSED ==="
echo ""
echo "This traced a multi-step build pipeline:"
echo "  bash build.sh -> gcc -c math.c -> gcc -c main.c -> gcc -o calculator -> ./calculator"
echo "All process forks, file I/O, and mmap operations were captured and verified."
