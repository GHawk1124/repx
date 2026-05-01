#!/usr/bin/env bash
# Diagnoses whether BPF captures an external write under --watch.
#
# The traced command signals an attacker, waits for it to write, then exits.
# If ExternalFileWrite appears in the ops, BPF+userspace are working.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPX="$REPO/target/release/repx"

WDIR=$(mktemp -d)
mkdir -p "$WDIR/watched"
echo "initial" > "$WDIR/watched/target.txt"

echo "Workdir:   $WDIR"
echo "Watching:  $WDIR/watched/"
echo ""

# Attacker: waits for signal file, appends to target, marks done
(
    while [ ! -f "$WDIR/go" ]; do sleep 0.05; done
    echo "ATTACKER: writing..." >&2
    printf '\nTAMPERED\n' >> "$WDIR/watched/target.txt"
    echo "ATTACKER: done" >&2
    touch "$WDIR/done"
) &
ATTACKER_PID=$!

# Traced command: sleep, signal attacker, wait for write, exit
TRACED_SCRIPT="$(cat <<EOF
sleep 0.4
touch "$WDIR/go"
DEADLINE=\$((SECONDS + 5))
while [ ! -f "$WDIR/done" ]; do
    [ \$SECONDS -ge \$DEADLINE ] && { echo "TIMEOUT waiting for attacker"; exit 1; }
    sleep 0.05
done
echo "traced: attacker finished, exiting"
EOF
)"

RUST_LOG=warn "$REPX" trace \
    --watch "$WDIR/watched/" \
    --dump-ops "$WDIR/ops.json" \
    -o "$WDIR/att.json" \
    -- bash -c "$TRACED_SCRIPT"

wait $ATTACKER_PID 2>/dev/null || true

echo ""
echo "=== All op_type entries in ops.json ==="
grep '"op_type"' "$WDIR/ops.json" || echo "(none)"

echo ""
EW=$(grep -c '"op_type": "ExternalFileWrite"' "$WDIR/ops.json" 2>/dev/null || true)
echo "ExternalFileWrite count: ${EW:-0}"

if [ "${EW:-0}" -ge 1 ]; then
    echo "PASS: BPF+userspace captured the external write."
else
    echo "FAIL: external write not captured — digging deeper..."
    echo ""

    # Re-run with debug logging to see what events are processed
    echo "=== Re-running with RUST_LOG=debug ==="
    echo "initial" > "$WDIR/watched/target.txt"
    rm -f "$WDIR/go" "$WDIR/done"

    (
        while [ ! -f "$WDIR/go2" ]; do sleep 0.05; done
        printf '\nTAMPERED\n' >> "$WDIR/watched/target.txt"
        touch "$WDIR/done2"
    ) &
    ATTACKER2_PID=$!

    TRACED_SCRIPT2="$(cat <<EOF
sleep 0.4
touch "$WDIR/go2"
DEADLINE=\$((SECONDS + 5))
while [ ! -f "$WDIR/done2" ]; do
    [ \$SECONDS -ge \$DEADLINE ] && { echo "TIMEOUT"; exit 1; }
    sleep 0.05
done
echo "traced: done"
EOF
)"

    RUST_LOG=debug "$REPX" trace \
        --watch "$WDIR/watched/" \
        --dump-ops "$WDIR/ops-debug.json" \
        -o "$WDIR/att-debug.json" \
        -- bash -c "$TRACED_SCRIPT2" 2>"$WDIR/debug.log"

    wait $ATTACKER2_PID 2>/dev/null || true

    echo "--- FileOpen/FileClose/FileMmap events from debug log ---"
    grep -E 'FileOpen|FileClose|FileMmap' "$WDIR/debug.log" | grep -i 'external=true\|target\.txt' || echo "(none matching)"
    echo ""
    echo "--- All external=true events ---"
    grep 'external=true' "$WDIR/debug.log" | head -20 || echo "(none)"
    echo ""
    echo "--- dropped_events line ---"
    grep -i 'drop' "$WDIR/debug.log" | head -5 || echo "(none)"
fi

echo ""
echo "Artifacts kept in: $WDIR"
echo "(remove manually when done)"
