#!/usr/bin/env bash
set -euo pipefail

# Integration test: compile a C program, then trace and verify it with repx.
#
# Usage (must run as root for eBPF):
#   sudo ./tests/run-test.sh
#   sudo nix run .#test

# Check for root (eBPF requires CAP_BPF / CAP_SYS_ADMIN).
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: eBPF requires root. Run with: sudo $0"
    exit 1
fi

# Find repx binary: check REPX env, PATH, then common locations.
REPX="${REPX:-}"
if [ -z "$REPX" ]; then
    if command -v repx &>/dev/null; then
        REPX="$(command -v repx)"
    else
        # Try relative paths from the script location.
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
    echo "Build with one of:"
    echo "  nix build                  # pure nix build (recommended)"
    echo "  nix develop -c ./build.sh  # dev build"
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

echo "=== Setting up test ==="

# Write the test C program inline so this script works from any location.
cat > "$TMPDIR/hello.c" << 'HELLOC'
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#define MAX_SIZE 4096
int main(int argc, char *argv[]) {
    if (argc != 3) { fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]); return 1; }
    FILE *in = fopen(argv[1], "r");
    if (!in) { perror("fopen input"); return 1; }
    char buf[MAX_SIZE];
    size_t n = fread(buf, 1, sizeof(buf) - 1, in);
    buf[n] = '\0';
    fclose(in);
    for (size_t i = 0; i < n; i++) buf[i] = toupper((unsigned char)buf[i]);
    FILE *out = fopen(argv[2], "w");
    if (!out) { perror("fopen output"); return 1; }
    fwrite(buf, 1, n, out);
    fclose(out);
    printf("Transformed %zu bytes: %s -> %s\n", n, argv[1], argv[2]);
    return 0;
}
HELLOC

echo "Hello, repx!" > "$TMPDIR/input.txt"

# Compile the C program.
gcc -o "$TMPDIR/hello" "$TMPDIR/hello.c"
echo "Compiled test program: $TMPDIR/hello"

echo ""
echo "=== Trace: running hello under repx ==="
"$REPX" trace -o "$TMPDIR/attestation.json" -- "$TMPDIR/hello" "$TMPDIR/input.txt" "$TMPDIR/output.txt"

echo ""
echo "=== Output check ==="
echo "Input:  $(cat "$TMPDIR/input.txt")"
echo "Output: $(cat "$TMPDIR/output.txt")"

echo ""
echo "=== Attestation ==="
head -20 "$TMPDIR/attestation.json"
echo "..."

echo ""
echo "=== Determinism: repeating the same command ==="
attestations=("$TMPDIR/attestation.json")
for ((run = 2; run <= DETERMINISM_RUNS; run++)); do
    rm -f "$TMPDIR/output.txt"
    run_attestation="$TMPDIR/run-$run-attestation.json"
    attestations+=("$run_attestation")
    "$REPX" trace -o "$run_attestation" -- \
        "$TMPDIR/hello" "$TMPDIR/input.txt" "$TMPDIR/output.txt"
done
"$REPX" stability --json "${attestations[@]}" > "$TMPDIR/stability.json"
"$REPX" stability --strict "${attestations[@]}"

echo ""
echo "=== Verify: re-running hello and comparing attestation ==="
# Reset the output file so the verify run produces the same result.
rm -f "$TMPDIR/output.txt"
"$REPX" verify -a "$TMPDIR/attestation.json" -- "$TMPDIR/hello" "$TMPDIR/input.txt" "$TMPDIR/output.txt"

echo ""
echo "=== Test PASSED ==="
