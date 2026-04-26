#!/usr/bin/env bash
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

if ! pgrep -x nix-daemon >/dev/null 2>&1; then
    echo "SKIP: nix-daemon is not running; cannot exercise the multi-user nix build path."
    exit 77
fi

NIXPKGS_PATH="$(nix-instantiate --find-file nixpkgs 2>/dev/null || true)"
if [ -z "$NIXPKGS_PATH" ]; then
    echo "ERROR: could not resolve <nixpkgs> for the inline demo derivation"
    exit 1
fi

root_hash() {
    grep -o '"root_hash": "[^"]*"' "$1" | head -1 | cut -d'"' -f4
}

external_write_count() {
    # Matches serde's default enum variant spelling in `repx trace --dump-ops`.
    grep -c '"op_type": "ExternalFileWrite"' "$1" || true
}

skip_test() {
    echo "SKIP: $1"
    exit 77
}

ATTACKER_PID=""
TMPDIR=$(mktemp -d)
COORDDIR=$(mktemp -d)
RESULT_LINK="$TMPDIR/result"
TAMPER_FILE="$TMPDIR/result-tamper"
BUILD_STAMP=$(date +%s)

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

delete_result_store_path() {
    local result_path

    result_path="$(readlink -f "$RESULT_LINK" 2>/dev/null || true)"
    if [ -z "$result_path" ] || [ ! -e "$result_path" ]; then
        skip_test "could not resolve the nix-build output behind $RESULT_LINK"
    fi

    rm -f "$RESULT_LINK"

    if ! nix store delete "$result_path" >/dev/null 2>&1; then
        skip_test "could not delete $result_path; rerun as root or a trusted user"
    fi
}

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

start_result_tamper() {
    local signal_fifo="$1"
    local ack_fifo="$2"

    (
        IFS= read -r _ < "$signal_fifo"
        printf 'tampered\n' > "$TAMPER_FILE"
        printf 'ack\n' > "$ack_fifo"
    ) &

    ATTACKER_PID="$!"
}

run_tampered_trace() {
    local output="$1"

    rm -f "$RESULT_LINK" "$TAMPER_FILE"
    prepare_coordination
    start_result_tamper "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"

    DEMO_BUILD_STAMP="$BUILD_STAMP" \
    DEMO_NIXPKGS_PATH="$NIXPKGS_PATH" \
    DEMO_SIGNAL_FIFO="$COORD_SIGNAL_FIFO" \
    DEMO_ACK_FIFO="$COORD_ACK_FIFO" \
    "$REPX" trace --watch "$TMPDIR/" \
        --dump-ops "${output%.json}-ops.json" \
        -o "$output" \
        -- bash "$TMPDIR/run-nix-build.sh" "$TMPDIR/demo.nix" "$RESULT_LINK"

    wait "$ATTACKER_PID" 2>/dev/null || true
    ATTACKER_PID=""
    cleanup_coordination
}

echo "========================================================"
echo "  repx: real nix-build + --watch demo"
echo "========================================================"
echo ""
echo "Temp workspace: $TMPDIR"
echo ""

cat > "$TMPDIR/demo.nix" << 'NIXEOF'
{ buildStamp }:
let
  pkgs = import <nixpkgs> {};
in pkgs.runCommand "repx-demo-real-nix-build-${buildStamp}" {
  preferLocalBuild = true;
  allowSubstitutes = false;
} ''
  printf '%s\n' '${buildStamp}' > "$out"
''
NIXEOF

cat > "$TMPDIR/run-nix-build.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

DEMO_NIX="$1"
OUT_LINK="$2"

if [ -z "${DEMO_BUILD_STAMP:-}" ] || [ -z "${DEMO_NIXPKGS_PATH:-}" ]; then
    echo "ERROR: missing nix build parameters" >&2
    exit 1
fi

nix-build "$DEMO_NIX" \
    -I "nixpkgs=$DEMO_NIXPKGS_PATH" \
    --argstr buildStamp "$DEMO_BUILD_STAMP" \
    --option substitute false \
    --out-link "$OUT_LINK"

if [ -n "${DEMO_SIGNAL_FIFO:-}" ] && [ -p "$DEMO_SIGNAL_FIFO" ]; then
    printf 'built\n' > "$DEMO_SIGNAL_FIFO"
fi

if [ -n "${DEMO_ACK_FIFO:-}" ] && [ -p "$DEMO_ACK_FIFO" ]; then
    IFS= read -r _ < "$DEMO_ACK_FIFO"
fi
EOF
chmod +x "$TMPDIR/run-nix-build.sh"

echo "--- Step 1: Trace a real nix-build under repx --watch ---"
prepare_coordination
start_coord_ack "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"

DEMO_BUILD_STAMP="$BUILD_STAMP" \
DEMO_NIXPKGS_PATH="$NIXPKGS_PATH" \
DEMO_SIGNAL_FIFO="$COORD_SIGNAL_FIFO" \
DEMO_ACK_FIFO="$COORD_ACK_FIFO" \
"$REPX" trace --watch "$TMPDIR/" \
    -o "$TMPDIR/attestation.json" \
    -- bash "$TMPDIR/run-nix-build.sh" "$TMPDIR/demo.nix" "$RESULT_LINK"

wait "$ATTACKER_PID" 2>/dev/null || true
ATTACKER_PID=""
cleanup_coordination

CLEAN_HASH=$(root_hash "$TMPDIR/attestation.json")
echo "Clean attestation root hash: $CLEAN_HASH"
echo "nix-build output link: $RESULT_LINK -> $(readlink -f "$RESULT_LINK")"
echo ""

echo "--- Step 2: Clean re-build — verify should PASS ---"
delete_result_store_path
rm -f "$TAMPER_FILE"

prepare_coordination
start_coord_ack "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"

DEMO_BUILD_STAMP="$BUILD_STAMP" \
DEMO_NIXPKGS_PATH="$NIXPKGS_PATH" \
DEMO_SIGNAL_FIFO="$COORD_SIGNAL_FIFO" \
DEMO_ACK_FIFO="$COORD_ACK_FIFO" \
"$REPX" verify --watch "$TMPDIR/" \
    -a "$TMPDIR/attestation.json" \
    -- bash "$TMPDIR/run-nix-build.sh" "$TMPDIR/demo.nix" "$RESULT_LINK"

wait "$ATTACKER_PID" 2>/dev/null || true
ATTACKER_PID=""
cleanup_coordination

echo ""

echo "--- Step 3: Re-verify with a watched rogue write — should FAIL ---"
delete_result_store_path

rm -f "$RESULT_LINK" "$TAMPER_FILE"
prepare_coordination
start_result_tamper "$COORD_SIGNAL_FIFO" "$COORD_ACK_FIFO"

if DEMO_BUILD_STAMP="$BUILD_STAMP" \
    DEMO_NIXPKGS_PATH="$NIXPKGS_PATH" \
    DEMO_SIGNAL_FIFO="$COORD_SIGNAL_FIFO" \
    DEMO_ACK_FIFO="$COORD_ACK_FIFO" \
    "$REPX" verify --watch "$TMPDIR/" \
        -a "$TMPDIR/attestation.json" \
        -- bash "$TMPDIR/run-nix-build.sh" "$TMPDIR/demo.nix" "$RESULT_LINK" 2>&1; then
    wait "$ATTACKER_PID" 2>/dev/null || true
    ATTACKER_PID=""
    cleanup_coordination
    echo "FAIL: repx did not detect the rogue watched write."
    exit 1
fi

wait "$ATTACKER_PID" 2>/dev/null || true
ATTACKER_PID=""
cleanup_coordination

echo ""
echo "--- Step 4: Confirm the failure was an external watched write ---"
delete_result_store_path
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
echo "The nix-daemon that built the derivation is a systemd service, not a child of the nix CLI we traced."
echo "--watch still catches writes under the watched prefix because the feature is file-centric, not lineage-centric."
