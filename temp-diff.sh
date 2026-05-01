#!/usr/bin/env bash
# Runs two identical clean traces and diffs the ops JSON to expose
# exactly which ops differ between runs (non-determinism diagnosis).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPX="$REPO/target/release/repx"

WDIR=$(mktemp -d)
mkdir -p "$WDIR/src" "$WDIR/build1" "$WDIR/build2"

cat > "$WDIR/src/crypto.c" << 'EOF'
#include <stdio.h>
int crypto_verify(const char *data) { return 42; }
int main() { printf("ok\n"); return 0; }
EOF

echo "Workdir: $WDIR"
echo ""

run_trace() {
    local outdir="$1" tag="$2"
    rm -rf "$outdir" && mkdir -p "$outdir"
    "$REPX" trace \
        --watch "$WDIR/" \
        --dump-ops "$WDIR/ops-${tag}.json" \
        -o "$WDIR/att-${tag}.json" \
        -- bash -c "gcc -o '$outdir/crypto.o' -c '$WDIR/src/crypto.c' && gcc -o '$outdir/app' '$outdir/crypto.o'"
    echo "Root ($tag): $(grep -o '"root_hash":"[^"]*"' "$WDIR/att-${tag}.json" | cut -d'"' -f4)"
}

run_trace "$WDIR/build1" "A"
run_trace "$WDIR/build2" "B"

echo ""
echo "=== Op count A=$(grep -c '"op_type"' "$WDIR/ops-A.json") B=$(grep -c '"op_type"' "$WDIR/ops-B.json") ==="
echo ""

# Extract per-op lines and compare
python3 - "$WDIR/ops-A.json" "$WDIR/ops-B.json" << 'PYEOF'
import json, sys, difflib

def summarise(ops):
    rows = []
    for op in ops:
        t   = op.get("op_type","?")
        pi  = op.get("process_index","?")
        th  = (op.get("tool_hash") or "")[:16]
        args = " ".join(op.get("args", []))[:80]
        inh  = ",".join(h[:12] for h in op.get("input_hashes",[]))[:40]
        outh = ",".join(h[:12] for h in op.get("output_hashes",[]))[:40]
        rows.append(f"{t:25s} pi={pi:>6} tool={th}  args={args!r}  in={inh}  out={outh}")
    return rows

a_ops = json.load(open(sys.argv[1]))
b_ops = json.load(open(sys.argv[2]))

a_rows = summarise(a_ops)
b_rows = summarise(b_ops)

diff = list(difflib.unified_diff(a_rows, b_rows, lineterm="", fromfile="run-A", tofile="run-B", n=1))
if not diff:
    print("IDENTICAL — no non-determinism found.")
else:
    print(f"DIFF ({len(diff)} lines):")
    for line in diff:
        print(line)
PYEOF

echo ""
echo "Artifacts kept in: $WDIR"
