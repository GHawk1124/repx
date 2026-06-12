#!/usr/bin/env bash
set -euo pipefail

# Integration matrix: trace and verify representative build systems with repx.
#
# Usage:
#   sudo nix run .#test-build-systems
#   sudo nix run .#test-build-systems -- make cargo
#   sudo ./tests/run-build-system-tests.sh cmake-ninja go

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: eBPF requires root. Run with: sudo $0"
    exit 1
fi

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

if counts.get("FileWrite", 0) < 1:
    raise SystemExit("expected at least one exported output")
if counts.get("Exit", 0) != 1:
    raise SystemExit("expected exactly one root exit")
PYEOF
}

run_repx_case() {
    local name="$1"
    local workspace="$2"
    local command="$3"
    local check_command="$4"
    local reset_command="$5"

    local trace_att="$TMPDIR/$name-run-1-attestation.json"
    local trace_ops="$TMPDIR/$name-run-1-ops.json"
    local verify_log="$TMPDIR/$name-verify.log"
    local -a attestations=()

    echo ""
    echo "========================================================"
    echo "  $name"
    echo "========================================================"

    for ((run = 1; run <= DETERMINISM_RUNS; run++)); do
        local run_att="$TMPDIR/$name-run-$run-attestation.json"
        local run_ops="$TMPDIR/$name-run-$run-ops.json"
        local run_log="$TMPDIR/$name-run-$run.log"
        attestations+=("$run_att")

        (
            cd "$workspace"
            bash -c "$reset_command"
            "$REPX" trace --output-root dist --dump-ops "$run_ops" -o "$run_att" -- bash -c "$command" >"$run_log" 2>&1
            cat "$run_log"
            if grep -q "events dropped" "$run_log"; then
                echo "ERROR: $name run $run dropped events; attestation is incomplete."
                exit 1
            fi
            bash -c "$check_command"
        )
    done

    echo ""
    echo "Determinism report ($DETERMINISM_RUNS runs):"
    "$REPX" stability --json "${attestations[@]}" > "$TMPDIR/$name-stability.json"
    "$REPX" stability --strict "${attestations[@]}"

    (
        cd "$workspace"
        bash -c "$reset_command"
        "$REPX" verify --output-root dist -a "$trace_att" -- bash -c "$command" >"$verify_log" 2>&1
        cat "$verify_log"
        if grep -q "events dropped" "$verify_log"; then
            echo "ERROR: $name verify trace dropped events; attestation is incomplete."
            exit 1
        fi
    )

    "$REPX" explain -a "$trace_att" >/dev/null
    "$REPX" diff "$trace_att" "$trace_att" >/dev/null

    echo ""
    echo "Trace summary:"
    summarize_trace "$trace_ops"
}

setup_make() {
    local workspace="$TMPDIR/make"
    mkdir -p "$workspace/src"

    cat > "$workspace/src/math.h" << 'EOF'
#ifndef REPX_MATRIX_MATH_H
#define REPX_MATRIX_MATH_H
int add(int a, int b);
int multiply(int a, int b);
#endif
EOF

    cat > "$workspace/src/math.c" << 'EOF'
#include "math.h"
int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }
EOF

    cat > "$workspace/src/main.c" << 'EOF'
#include <stdio.h>
#include "math.h"
int main(void) {
    printf("make add=%d multiply=%d\n", add(4, 9), multiply(6, 7));
    return 0;
}
EOF

    cat > "$workspace/Makefile" << 'EOF'
BUILD_DIR ?= /tmp/repx-make-build
.PHONY: all clean
all: dist/hello
dist/hello: $(BUILD_DIR)/hello
	mkdir -p dist
	dd if=$< of=$@ bs=1M status=none
	chmod +x $@
$(BUILD_DIR)/hello: $(BUILD_DIR)/main.o $(BUILD_DIR)/math.o
	gcc -o $@ $^
$(BUILD_DIR)/main.o: src/main.c src/math.h
	mkdir -p $(BUILD_DIR)
	gcc -c -Isrc -o $@ src/main.c
$(BUILD_DIR)/math.o: src/math.c src/math.h
	mkdir -p $(BUILD_DIR)
	gcc -c -Isrc -o $@ src/math.c
clean:
	rm -rf dist $(BUILD_DIR)
EOF

    run_repx_case \
        "make" \
        "$workspace" \
        "make BUILD_DIR='$TMPDIR/make-build' all" \
        "test \"\$(./dist/hello)\" = 'make add=13 multiply=42'" \
        "make BUILD_DIR='$TMPDIR/make-build' clean >/dev/null 2>&1 || true"
}

setup_cmake_ninja() {
    local workspace="$TMPDIR/cmake-ninja"
    local build_dir="$TMPDIR/cmake-ninja-build"
    mkdir -p "$workspace/src"

    cat > "$workspace/CMakeLists.txt" << 'EOF'
cmake_minimum_required(VERSION 3.20)
project(repx_cmake_ninja_test C)
add_library(math src/math.c)
target_include_directories(math PUBLIC src)
add_executable(hello src/main.c)
target_link_libraries(hello PRIVATE math)
EOF

    cat > "$workspace/src/math.h" << 'EOF'
#ifndef REPX_CMAKE_NINJA_MATH_H
#define REPX_CMAKE_NINJA_MATH_H
int add(int a, int b);
int multiply(int a, int b);
#endif
EOF

    cat > "$workspace/src/math.c" << 'EOF'
#include "math.h"
int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }
EOF

    cat > "$workspace/src/main.c" << 'EOF'
#include <stdio.h>
#include "math.h"
int main(void) {
    printf("cmake-ninja add=%d multiply=%d\n", add(5, 8), multiply(7, 6));
    return 0;
}
EOF

    cmake -S "$workspace" -B "$build_dir" -G Ninja >/dev/null

    run_repx_case \
        "cmake-ninja" \
        "$workspace" \
        "cmake --build '$build_dir' --target hello && mkdir -p dist && dd if='$build_dir/hello' of=dist/hello bs=1M status=none && chmod +x dist/hello" \
        "test \"\$(./dist/hello)\" = 'cmake-ninja add=13 multiply=42'" \
        "rm -rf dist && cmake --build '$build_dir' --target clean >/dev/null 2>&1 || true"
}

setup_cargo() {
    local workspace="$TMPDIR/cargo"
    local target_dir="$TMPDIR/cargo-target"
    local cargo_home="$TMPDIR/cargo-home"
    mkdir -p "$workspace/src" "$cargo_home"

    cat > "$workspace/Cargo.toml" << 'EOF'
[package]
name = "repx-cargo-test"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "hello"
path = "src/main.rs"
EOF

    cat > "$workspace/src/main.rs" << 'EOF'
fn add(a: i32, b: i32) -> i32 { a + b }
fn multiply(a: i32, b: i32) -> i32 { a * b }
fn main() {
    println!("cargo add={} multiply={}", add(6, 7), multiply(6, 7));
}
EOF

    (
        cd "$workspace"
        CARGO_HOME="$cargo_home" cargo generate-lockfile --offline
    )

    run_repx_case \
        "cargo" \
        "$workspace" \
        "CARGO_HOME='$cargo_home' CARGO_TARGET_DIR='$target_dir' cargo build --release --offline --locked && mkdir -p dist && dd if='$target_dir/release/hello' of=dist/hello bs=1M status=none && chmod +x dist/hello" \
        "test \"\$(./dist/hello)\" = 'cargo add=13 multiply=42'" \
        "rm -rf dist '$target_dir'"
}

setup_go() {
    local workspace="$TMPDIR/go"
    local gocache="$TMPDIR/go-cache"
    local gomodcache="$TMPDIR/go-mod-cache"
    mkdir -p "$workspace" "$gocache" "$gomodcache"

    cat > "$workspace/go.mod" << 'EOF'
module example.com/repx-go-test

go 1.22
EOF

    cat > "$workspace/main.go" << 'EOF'
package main

import "fmt"

func add(a, b int) int { return a + b }
func multiply(a, b int) int { return a * b }

func main() {
	fmt.Printf("go add=%d multiply=%d\n", add(8, 5), multiply(6, 7))
}
EOF

    (
        cd "$workspace"
        GOCACHE="$gocache" GOMODCACHE="$gomodcache" \
            go build -trimpath -buildvcs=false -ldflags='-buildid=' \
            -o "$TMPDIR/go-warm" .
    )

    run_repx_case \
        "go" \
        "$workspace" \
        "GOCACHE='$gocache' GOMODCACHE='$gomodcache' go build -trimpath -buildvcs=false -ldflags='-buildid=' -o dist/hello ." \
        "test \"\$(./dist/hello)\" = 'go add=13 multiply=42'" \
        "rm -rf dist"
}

if [ "$#" -eq 0 ]; then
    SYSTEMS=(make cmake-ninja cargo go)
else
    SYSTEMS=("$@")
fi

for system in "${SYSTEMS[@]}"; do
    case "$system" in
        make) setup_make ;;
        cmake-ninja|cmake|ninja) setup_cmake_ninja ;;
        cargo|rust) setup_cargo ;;
        go|golang) setup_go ;;
        *)
            echo "ERROR: unknown build system '$system'"
            echo "Known systems: make cmake-ninja cargo go"
            exit 1
            ;;
    esac
done

echo ""
echo "========================================================"
echo "  Build system matrix PASSED"
echo "========================================================"
