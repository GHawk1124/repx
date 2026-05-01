#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

echo "========================================================"
echo "  repx runtime verification"
echo "========================================================"
echo ""

# ---------------------------------------------------------------------------
# 1. Sanity: trace /bin/true, count canonical ops
# ---------------------------------------------------------------------------
echo "--- [1/4] Clean trace of /bin/true ---"
./target/release/repx trace --dump-ops /tmp/repx-ops-true.json \
    -o /tmp/repx-att-true.json -- "$(command -v true)"
OP_COUNT=$(grep -c '"op_type"' /tmp/repx-ops-true.json || true)
echo "Canonical ops produced: $OP_COUNT (expect ~22)"
echo ""

# ---------------------------------------------------------------------------
# 2. Demo: full nix-build scenario
# ---------------------------------------------------------------------------
echo "--- [2/4] demo-nix-build.sh ---"
bash tests/demo-nix-build.sh
echo ""

# ---------------------------------------------------------------------------
# 3. nix run #test (unit + integration)
# ---------------------------------------------------------------------------
echo "--- [3/4] nix run .#test ---"
nix run "path:$REPO#test"
echo ""

# ---------------------------------------------------------------------------
# 4. nix run #test-nix-build
# ---------------------------------------------------------------------------
echo "--- [4/4] nix run .#test-nix-build ---"
nix run "path:$REPO#test-nix-build"
echo ""

echo "========================================================"
echo "  All checks passed."
echo "========================================================"
