#!/usr/bin/env bash
set -euo pipefail

# Integration test: trace a small Bazel C/C++ build with repx.
#
# Usage:
#   sudo ./tests/run-bazel-test.sh
#   sudo nix run .#test-bazel

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

BAZEL="${BAZEL:-}"
if [ -z "$BAZEL" ]; then
    if command -v bazel &>/dev/null; then
        BAZEL="$(command -v bazel)"
    elif command -v bazelisk &>/dev/null; then
        BAZEL="$(command -v bazelisk)"
    fi
fi
if [ -z "$BAZEL" ] || [ ! -x "$BAZEL" ]; then
    echo "ERROR: bazel or bazelisk binary not found."
    exit 1
fi

echo "Using repx: $REPX"
echo "Using Bazel: $BAZEL"

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

WORKSPACE_DIR="$TMPDIR/workspace"
OUTPUT_BASE="$TMPDIR/bazel-output-base"
OUTPUT_USER_ROOT="$TMPDIR/bazel-user-root"
TRACE_ATT="$TMPDIR/trace-attestation.json"
TRACE_OPS="$TMPDIR/trace-ops.json"
VERIFY_ATT="$TMPDIR/verify-attestation.json"
VERIFY_OPS="$TMPDIR/verify-ops.json"

echo "=== Setting up Bazel C project ==="
mkdir -p "$WORKSPACE_DIR"

cat > "$WORKSPACE_DIR/WORKSPACE" << 'EOF'
workspace(name = "repx_bazel_test")
EOF

cat > "$WORKSPACE_DIR/BUILD.bazel" << 'EOF'
cc_library(
    name = "math",
    srcs = ["math.c"],
    hdrs = ["math.h"],
)

cc_binary(
    name = "hello",
    srcs = ["main.c"],
    deps = [":math"],
)

cc_test(
    name = "math_test",
    srcs = ["math_test.c"],
    deps = [":math"],
)
EOF

cat > "$WORKSPACE_DIR/math.h" << 'EOF'
#ifndef REPX_BAZEL_TEST_MATH_H
#define REPX_BAZEL_TEST_MATH_H
int add(int a, int b);
int multiply(int a, int b);
#endif
EOF

cat > "$WORKSPACE_DIR/math.c" << 'EOF'
#include "math.h"
int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }
EOF

cat > "$WORKSPACE_DIR/main.c" << 'EOF'
#include <stdio.h>
#include "math.h"
int main(void) {
    printf("bazel add=%d multiply=%d\n", add(8, 5), multiply(6, 7));
    return 0;
}
EOF

cat > "$WORKSPACE_DIR/math_test.c" << 'EOF'
#include "math.h"
int main(void) {
    return add(2, 3) == 5 && multiply(4, 7) == 28 ? 0 : 1;
}
EOF

cat > "$WORKSPACE_DIR/build-and-export.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

BAZEL_DETERMINISTIC_FLAGS=(
    --noenable_bzlmod
    --noshow_progress
    --jobs=1
    --spawn_strategy=local
    --genrule_strategy=local
    --strategy=CppCompile=local
    --strategy=CppLink=local
)

"$BAZEL" --batch --output_user_root="$OUTPUT_USER_ROOT" --output_base="$OUTPUT_BASE" \
    build "${BAZEL_DETERMINISTIC_FLAGS[@]}" //:hello //:math_test

mkdir -p dist
dd if=bazel-bin/hello of=dist/hello bs=1M status=none
dd if=bazel-bin/math_test of=dist/math_test bs=1M status=none
chmod +x dist/hello dist/math_test
EOF
chmod +x "$WORKSPACE_DIR/build-and-export.sh"

bazel_cmd() {
    "$BAZEL" --batch --output_user_root="$OUTPUT_USER_ROOT" --output_base="$OUTPUT_BASE" "$@"
}

BAZEL_DETERMINISTIC_FLAGS=(
    --noenable_bzlmod
    --noshow_progress
    --jobs=1
    --spawn_strategy=local
    --genrule_strategy=local
    --strategy=CppCompile=local
    --strategy=CppLink=local
)
export BAZEL OUTPUT_USER_ROOT OUTPUT_BASE

reset_bazel_state() {
    rm -rf "$OUTPUT_BASE"
    rm -rf "$WORKSPACE_DIR/dist"
    rm -f \
        "$WORKSPACE_DIR/bazel-bin" \
        "$WORKSPACE_DIR/bazel-out" \
        "$WORKSPACE_DIR/bazel-testlogs" \
        "$WORKSPACE_DIR/bazel-repx_bazel_test"
}

root_hash() {
    grep -o '"root_hash": "[^"]*"' "$1" | head -1 | cut -d'"' -f4
}

summarize_trace() {
    python3 - "$1" << 'PYEOF'
import json
import sys

ops = json.load(open(sys.argv[1]))
counts = {}
for op in ops:
    counts[op["op_type"]] = counts.get(op["op_type"], 0) + 1

tool_hashes = {op.get("tool_hash") for op in ops if op.get("tool_hash")}
blank_file_ops = sum(
    1
    for op in ops
    if op["op_type"] in ("FileRead", "FileWrite") and not op.get("tool_hash")
)

print(f"Canonical ops: {len(ops)}")
for key in sorted(counts):
    print(f"  {key}: {counts[key]}")
print(f"Unique tool hashes: {len(tool_hashes)}")
print(f"File ops without tool hash: {blank_file_ops}")

if counts.get("FileWrite", 0) < 2:
    raise SystemExit("expected output-sliced Bazel trace to include exported outputs")
if counts.get("Exit", 0) != 1:
    raise SystemExit("expected output-sliced Bazel trace to include root exit")
PYEOF
}

compare_traces() {
    python3 - "$TRACE_OPS" "$VERIFY_OPS" << 'PYEOF'
import collections
import hashlib
import json
import sys

def op_hash(op):
    h = hashlib.sha256()
    tag = {
        "Exec": "exec",
        "FileRead": "file_read",
        "FileWrite": "file_write",
        "SystemStateRead": "system_state_read",
        "Exit": "exit",
        "ExternalFileRead": "external_file_read",
        "ExternalFileWrite": "external_file_write",
    }[op["op_type"]]
    h.update(tag.encode())
    if op.get("tool_hash"):
        h.update(op["tool_hash"].encode())
    for arg in sorted(op.get("args", [])):
        h.update(arg.encode())
        h.update(b"\0")
    for item in sorted(op.get("input_hashes", [])):
        h.update(item.encode())
    for item in sorted(op.get("output_hashes", [])):
        h.update(item.encode())
    return h.hexdigest()[:12]

def row(op):
    return (
        f"{op['op_type']:14s} pi={op.get('process_index')} "
        f"tool={(op.get('tool_hash') or '')[:16]} op={op_hash(op)} "
        f"args={' '.join(op.get('args', []))!r} "
        f"in={','.join(h[:12] for h in op.get('input_hashes', []))} "
        f"out={','.join(h[:12] for h in op.get('output_hashes', []))}"
    )

a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
ca = collections.Counter(op_hash(op) for op in a)
cb = collections.Counter(op_hash(op) for op in b)
missing = ca - cb
extra = cb - ca
print(f"Semantic delta: missing={sum(missing.values())} extra={sum(extra.values())}")

if missing:
    print("Missing ops:")
    shown = 0
    for op in a:
        marker = op_hash(op)
        if missing[marker] > 0:
            print(f"  - {row(op)}")
            missing[marker] -= 1
            shown += 1
            if shown >= 30:
                break
if extra:
    print("Extra ops:")
    shown = 0
    for op in b:
        marker = op_hash(op)
        if extra[marker] > 0:
            print(f"  + {row(op)}")
            extra[marker] -= 1
            shown += 1
            if shown >= 30:
                break
PYEOF
}

echo "Created Bazel workspace in $WORKSPACE_DIR"

echo ""
echo "=== Warm Bazel install outside repx ==="
(
    cd "$WORKSPACE_DIR"
    "$BAZEL" --batch \
        --output_user_root="$OUTPUT_USER_ROOT" \
        --output_base="$TMPDIR/bazel-warm-output-base" \
        info release >/dev/null
)
rm -rf "$TMPDIR/bazel-warm-output-base"
reset_bazel_state

echo ""
echo "=== Trace: bazel build under repx ==="
reset_bazel_state
(
    cd "$WORKSPACE_DIR"
    "$REPX" trace --output-root dist --dump-ops "$TRACE_OPS" -o "$TRACE_ATT" -- \
        bash "$WORKSPACE_DIR/build-and-export.sh"
)

echo ""
echo "=== Run Bazel-built binary ==="
"$WORKSPACE_DIR/dist/hello"

echo ""
echo "=== Run Bazel test outside repx ==="
(
    cd "$WORKSPACE_DIR"
    bazel_cmd test "${BAZEL_DETERMINISTIC_FLAGS[@]}" //:math_test
)

echo ""
echo "=== Determinism: repeating the same Bazel build ==="
attestations=("$TRACE_ATT")
for ((run = 2; run <= DETERMINISM_RUNS; run++)); do
    run_attestation="$TMPDIR/run-$run-attestation.json"
    run_ops="$TMPDIR/run-$run-ops.json"
    if [ "$run" -eq 2 ]; then
        run_attestation="$VERIFY_ATT"
        run_ops="$VERIFY_OPS"
    fi
    attestations+=("$run_attestation")

    reset_bazel_state
    (
        cd "$WORKSPACE_DIR"
        "$REPX" trace --output-root dist --dump-ops "$run_ops" -o "$run_attestation" -- \
            bash "$WORKSPACE_DIR/build-and-export.sh"
    )
done

TRACE_ROOT=$(root_hash "$TRACE_ATT")
"$REPX" stability --json "${attestations[@]}" > "$TMPDIR/stability.json"
if ! "$REPX" stability --strict "${attestations[@]}"; then
    echo ""
    echo "MISMATCH: Bazel output-sliced trace is not deterministic."
    for candidate in "${attestations[@]:1}"; do
        "$REPX" diff "$TRACE_ATT" "$candidate" || true
    done
    echo ""
    echo "Trace summary:"
    summarize_trace "$TRACE_OPS"
    echo ""
    echo "Verify summary:"
    summarize_trace "$VERIFY_OPS"
    echo ""
    compare_traces
    echo ""
    echo "Artifacts:"
    echo "  Trace attestation:  $TRACE_ATT"
    echo "  Verify attestation: $VERIFY_ATT"
    echo "  Trace ops:          $TRACE_OPS"
    echo "  Verify ops:         $VERIFY_OPS"
    echo "Rerun with KEEP_TMPDIR=1 to preserve these files."
    exit 1
fi

"$REPX" explain -a "$TRACE_ATT" >/dev/null
"$REPX" diff "$TRACE_ATT" "$VERIFY_ATT" >/dev/null

echo "STABLE: $DETERMINISM_RUNS Bazel attestations match."
echo "Root hash: $TRACE_ROOT"

echo ""
echo "=== Verify: re-running with explicit output selection ==="
reset_bazel_state
(
    cd "$WORKSPACE_DIR"
    "$REPX" verify --output-root dist -a "$TRACE_ATT" -- \
        bash "$WORKSPACE_DIR/build-and-export.sh"
)

echo ""
echo "=== Trace summary ==="
summarize_trace "$TRACE_OPS"

echo ""
echo "=== Bazel Build Test PASSED ==="
