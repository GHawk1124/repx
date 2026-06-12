#!/usr/bin/env bash
set -euo pipefail

# Repeated-trace determinism harness over the integration workload matrix.
#
# Usage:
#   sudo nix run .#test-determinism
#   sudo nix run .#test-determinism -- bazel build-systems
#   sudo DETERMINISM_RUNS=50 nix run .#test-determinism

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: eBPF requires root. Run with: sudo $0"
    exit 1
fi

DETERMINISM_RUNS="${DETERMINISM_RUNS:-20}"
if ! [[ "$DETERMINISM_RUNS" =~ ^[0-9]+$ ]] || [ "$DETERMINISM_RUNS" -lt 2 ]; then
    echo "ERROR: DETERMINISM_RUNS must be an integer of at least 2."
    exit 1
fi
export DETERMINISM_RUNS

workloads=("$@")
if [ "${#workloads[@]}" -eq 0 ]; then
    workloads=(smoke nix-build bazel build-systems)
fi

echo "repx determinism harness"
echo "Repeated traces per workload: $DETERMINISM_RUNS"

for workload in "${workloads[@]}"; do
    echo ""
    echo "========================================================"
    echo "  determinism: $workload"
    echo "========================================================"
    case "$workload" in
        smoke)
            repx-test
            ;;
        nix-build)
            repx-test-nix-build
            ;;
        bazel)
            repx-test-bazel
            ;;
        build-systems)
            repx-test-build-systems
            ;;
        *)
            echo "ERROR: unknown workload '$workload'."
            echo "Valid workloads: smoke nix-build bazel build-systems"
            exit 1
            ;;
    esac
done

echo ""
echo "========================================================"
echo "  Determinism harness PASSED"
echo "========================================================"
