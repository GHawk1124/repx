#!/usr/bin/env bash
# Demo: repx file-centric tracking catches rogue processes that a traditional
# fork-tree tracer would miss.
#
# Narrative:
#   "Your build is clean. But a rogue process on your CI server is silently
#   modifying artifacts."
#
# Usage:
#   sudo bash tests/demo-nix-build.sh
#   sudo nix run .#demo-nix-build
set -euo pipefail

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

root_hash() {
    grep -o '"root_hash": "[^"]*"' "$1" | head -1 | cut -d'"' -f4
}

external_write_count() {
    # Matches serde's default enum variant spelling in `repx trace --dump-ops`.
    grep -c '"op_type": "ExternalFileWrite"' "$1" || true
}

ATTACKER_PID=""
TMPDIR=$(mktemp -d)
COORDDIR=$(mktemp -d)

cleanup_attacker() {
    if [ -n "$ATTACKER_PID" ]; then
        kill "$ATTACKER_PID" 2>/dev/null || true
        wait "$ATTACKER_PID" 2>/dev/null || true
        ATTACKER_PID=""
    fi
}

cleanup_tmpdir() {
    cleanup_attacker
    if [ "${KEEP_TMPDIR:-0}" = "1" ]; then
        echo "Keeping temp workspace: $TMPDIR"
    else
        rm -rf "$TMPDIR"
    fi
    rm -rf "$COORDDIR"
}

trap cleanup_tmpdir EXIT

prepare_coordination() {
    COORD_SIGNAL_FIFO="$COORDDIR/build-complete.fifo"
    COORD_ACK_FIFO="$COORDDIR/attacker-ack.fifo"
    rm -f "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"
    mkfifo "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"
}

cleanup_coordination() {
    rm -f "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"
}

start_coord_ack() {
    local signal_fifo="$1"
    local ack_fifo="$2"

    (
        IFS= read -r _ < "$signal_fifo"
        printf 'ack\n' > "$ack_fifo"
    ) &

    ATTACKER_PID="$!"
}

start_object_tamper() {
    local signal_fifo="$1"
    local ack_fifo="$2"

    (
        IFS= read -r _ < "$signal_fifo"
        printf '\nBACKDOOR\n' >> "$TMPDIR/build/crypto.o"
        printf 'ack\n' > "$ack_fifo"
    ) &

    ATTACKER_PID="$!"
}

run_tampered_trace() {
    local output="$1"

    rm -rf "$TMPDIR/build"
    mkdir -p "$TMPDIR/build"
    prepare_coordination
    start_object_tamper "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"

    DEMO_SIGNAL_FIFO="$COORD_SIGNAL_FIFO" \
    DEMO_ACK_FIFO="$COORD_ACK_FIFO" \
    "$REPX" trace --watch "$TMPDIR/" \
        --dump-ops "${output%.json}-ops.json" \
        -o "$output" \
        -- bash "$TMPDIR/build.sh" "$TMPDIR"

    wait "$ATTACKER_PID" 2>/dev/null || true
    ATTACKER_PID=""
    cleanup_coordination
}

echo "========================================================"
echo "  repx: file-centric supply chain attestation demo"
echo "========================================================"
echo ""
echo "Temp workspace: $TMPDIR"
echo ""

# ---------------------------------------------------------------------------
# Set up a minimal C project
# ---------------------------------------------------------------------------
mkdir -p "$TMPDIR/src" "$TMPDIR/build"

cat > "$TMPDIR/src/crypto.c" << 'EOF'
#include <stdio.h>
// Simulates a crypto module in a larger build
int crypto_verify(const char *data) {
    return 42; // trusted implementation
}
int main() {
    printf("Build OK: crypto_verify=%d\n", crypto_verify("test"));
    return 0;
}
EOF

cat > "$TMPDIR/build.sh" << 'BUILDEOF'
#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$1"

gcc -o "$WORKDIR/build/crypto.o" -c "$WORKDIR/src/crypto.c"
gcc -o "$WORKDIR/build/app" "$WORKDIR/build/crypto.o"

if [ -n "${DEMO_SIGNAL_FIFO:-}" ] && [ -p "$DEMO_SIGNAL_FIFO" ]; then
    printf 'linked\n' > "$DEMO_SIGNAL_FIFO"
fi

if [ -n "${DEMO_ACK_FIFO:-}" ] && [ -p "$DEMO_ACK_FIFO" ]; then
    IFS= read -r _ < "$DEMO_ACK_FIFO"
fi
BUILDEOF
chmod +x "$TMPDIR/build.sh"

# ---------------------------------------------------------------------------
# Step 1: Trace the clean build with --watch
# ---------------------------------------------------------------------------
echo "--- Step 1: Trace clean build (create baseline attestation) ---"
prepare_coordination
start_coord_ack "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"

DEMO_SIGNAL_FIFO="$COORD_SIGNAL_FIFO" \
DEMO_ACK_FIFO="$COORD_ACK_FIFO" \
"$REPX" trace --watch "$TMPDIR/" \
    -o "$TMPDIR/attestation.json" \
    -- bash "$TMPDIR/build.sh" "$TMPDIR"

wait "$ATTACKER_PID" 2>/dev/null || true
ATTACKER_PID=""
cleanup_coordination

CLEAN_HASH=$(root_hash "$TMPDIR/attestation.json")
echo "Clean attestation root hash: $CLEAN_HASH"
echo "Attestation written to: $TMPDIR/attestation.json"
echo ""

# ---------------------------------------------------------------------------
# Step 2: Clean rebuild — should PASS verification
# ---------------------------------------------------------------------------
echo "--- Step 2: Clean re-build — verify should PASS ---"
rm -rf "$TMPDIR/build"
mkdir -p "$TMPDIR/build"

prepare_coordination
start_coord_ack "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"

DEMO_SIGNAL_FIFO="$COORD_SIGNAL_FIFO" \
DEMO_ACK_FIFO="$COORD_ACK_FIFO" \
"$REPX" verify --watch "$TMPDIR/" \
    --attestation "$TMPDIR/attestation.json" \
    -- bash "$TMPDIR/build.sh" "$TMPDIR"

wait "$ATTACKER_PID" 2>/dev/null || true
ATTACKER_PID=""
cleanup_coordination

echo ""

# ---------------------------------------------------------------------------
# Step 3: Re-verify while a rogue background process tampers with the output
# ---------------------------------------------------------------------------
echo "--- Step 3: Re-verify with rogue background process — should FAIL ---"
echo "  Rogue process: appends 'BACKDOOR' to crypto.o after the app is linked."
echo "  This process is NOT in the build's process tree."
echo "  A traditional fork-tree tracer would miss it entirely."
echo ""

rm -rf "$TMPDIR/build"
mkdir -p "$TMPDIR/build"
prepare_coordination
start_object_tamper "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"

if DEMO_SIGNAL_FIFO="$COORD_SIGNAL_FIFO" \
    DEMO_ACK_FIFO="$COORD_ACK_FIFO" \
    "$REPX" verify --watch "$TMPDIR/" \
    --attestation "$TMPDIR/attestation.json" \
    -- bash "$TMPDIR/build.sh" "$TMPDIR" 2>&1; then
    wait "$ATTACKER_PID" 2>/dev/null || true
    ATTACKER_PID=""
    cleanup_coordination
    echo ""
    echo "FAIL: repx did not detect the rogue modification."
    exit 1
fi

wait "$ATTACKER_PID" 2>/dev/null || true
ATTACKER_PID=""
cleanup_coordination

echo ""
echo "--- Step 4: Confirm the failure was an external watched write ---"
run_tampered_trace "$TMPDIR/tampered-attestation.json"
TAMPERED_OPS="$TMPDIR/tampered-attestation-ops.json"

TAMPERED_HASH=$(root_hash "$TMPDIR/tampered-attestation.json")
EXTERNAL_WRITES=$(external_write_count "$TAMPERED_OPS")

if [ "$EXTERNAL_WRITES" -eq 0 ]; then
    echo "FAIL: --watch did not capture the external write."
    echo "Tampered attestation kept at: $TMPDIR/tampered-attestation.json"
    echo "Tampered ops kept at: $TAMPERED_OPS"
    exit 1
fi

echo "Tampered attestation root hash: $TAMPERED_HASH"
echo "external_file_write nodes: $EXTERNAL_WRITES"
echo ""
echo "========================================================"
echo "  SUCCESS: repx detected the rogue modification!"
echo ""
echo "  The attacker was NOT in the build's process tree."
echo "  A traditional tracer would have missed it."
echo "  repx's --watch flag caught it system-wide."
echo "========================================================"
