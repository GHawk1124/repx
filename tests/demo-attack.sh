#!/usr/bin/env bash
set -euo pipefail

# ==========================================================================
# repx supply chain attack demo
#
# Demonstrates repx catching a SolarWinds-style supply chain attack.
#
# Scenario: An attacker compromises the build system and injects a backdoor
# into the build process. The source code looks clean. The SBOM looks clean.
# repx records the covered kernel events and detects this attack path.
#
# Usage:
#   sudo nix run .#demo-attack
#   sudo ./tests/demo-attack.sh
# ==========================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() { echo -e "\n${CYAN}${BOLD}=== $1 ===${NC}\n"; }
good()   { echo -e "${GREEN}$1${NC}"; }
bad()    { echo -e "${RED}$1${NC}"; }
warn()   { echo -e "${YELLOW}$1${NC}"; }
info()   { echo -e "${BOLD}$1${NC}"; }

# Check for root.
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

TMPDIR=$(mktemp -d)
trap 'rm -rf $TMPDIR' EXIT

# --------------------------------------------------------------------------
banner "REPX SUPPLY CHAIN ATTACK DEMO"
# --------------------------------------------------------------------------

info "Scenario: You maintain a widely-used crypto library."
info "An attacker has compromised your CI server."
info "They will inject a backdoor during the build process."
echo ""
info "repx will catch them."
echo ""
sleep 1

# --------------------------------------------------------------------------
banner "STEP 1: Create the legitimate project"
# --------------------------------------------------------------------------

mkdir -p "$TMPDIR/src" "$TMPDIR/build"

cat > "$TMPDIR/src/crypto.h" << 'EOF'
#ifndef CRYPTO_H
#define CRYPTO_H
// Simple XOR cipher for demonstration purposes.
void encrypt(char *data, int len, char key);
void decrypt(char *data, int len, char key);
#endif
EOF

cat > "$TMPDIR/src/crypto.c" << 'EOF'
#include "crypto.h"
void encrypt(char *data, int len, char key) {
    for (int i = 0; i < len; i++) data[i] ^= key;
}
void decrypt(char *data, int len, char key) {
    for (int i = 0; i < len; i++) data[i] ^= key;
}
EOF

cat > "$TMPDIR/src/main.c" << 'EOF'
#include <stdio.h>
#include <string.h>
#include "crypto.h"
int main(void) {
    char msg[] = "SECRET DATA";
    int len = strlen(msg);
    char key = 0x42;
    printf("Original:  %s\n", msg);
    encrypt(msg, len, key);
    printf("Encrypted: ");
    for (int i = 0; i < len; i++) printf("%02x ", (unsigned char)msg[i]);
    printf("\n");
    decrypt(msg, len, key);
    printf("Decrypted: %s\n", msg);
    return 0;
}
EOF

# The clean build script.
cat > "$TMPDIR/build.sh" << 'BUILDEOF'
#!/usr/bin/env bash
set -euo pipefail
SRC="$1"; OUT="$2"
gcc -c -I"$SRC" -o "$OUT/crypto.o" "$SRC/crypto.c"
gcc -c -I"$SRC" -o "$OUT/main.o" "$SRC/main.c"
gcc -o "$OUT/crypto-tool" "$OUT/crypto.o" "$OUT/main.o"
"$OUT/crypto-tool" > "$OUT/output.txt"
BUILDEOF
chmod +x "$TMPDIR/build.sh"

info "Project files:"
echo "  src/crypto.h   - cipher API"
echo "  src/crypto.c   - XOR cipher implementation"
echo "  src/main.c     - demo program"
echo "  build.sh       - build script"

cd "$TMPDIR"

# --------------------------------------------------------------------------
banner "STEP 2: Produce a trusted attestation (clean build)"
# --------------------------------------------------------------------------

info "Running: repx trace --output-root build -- ./build.sh src/ build/"
echo ""
"$REPX" trace --output-root build -o "$TMPDIR/attestation.json" -- \
    "$TMPDIR/build.sh" "$TMPDIR/src" "$TMPDIR/build"

echo ""
good "Clean build succeeded."
echo ""
info "Program output:"
cat "$TMPDIR/build/output.txt"
echo ""

CLEAN_HASH=$(grep -o '"root_hash": "[^"]*"' "$TMPDIR/attestation.json" | head -1 | cut -d'"' -f4)
good "Attestation root hash: $CLEAN_HASH"
echo ""
info "This hash is now the trusted reference for this build."
info "Any future build must produce the same hash to be verified."
sleep 1

# --------------------------------------------------------------------------
banner "STEP 3: Verify the clean build (should pass)"
# --------------------------------------------------------------------------

rm -rf "$TMPDIR/build"
mkdir -p "$TMPDIR/build"

info "Running: repx verify --output-root build -- ./build.sh src/ build/"
echo ""
"$REPX" verify --output-root build -a "$TMPDIR/attestation.json" -- \
    "$TMPDIR/build.sh" "$TMPDIR/src" "$TMPDIR/build"

echo ""
good "Verification passed. Build is reproducible."
sleep 1

# --------------------------------------------------------------------------
banner "STEP 4: The attacker strikes"
# --------------------------------------------------------------------------

warn "An attacker has gained access to the CI server."
warn "They modify the build script to inject a backdoor."
warn "The source code is NOT changed. The SBOM would look identical."
echo ""
sleep 1

# The compromised build script — identical to the original EXCEPT
# it silently exfiltrates the encryption key to a hidden file.
cat > "$TMPDIR/build.sh" << 'BUILDEOF'
#!/usr/bin/env bash
set -euo pipefail
SRC="$1"; OUT="$2"
gcc -c -I"$SRC" -o "$OUT/crypto.o" "$SRC/crypto.c"
gcc -c -I"$SRC" -o "$OUT/main.o" "$SRC/main.c"
gcc -o "$OUT/crypto-tool" "$OUT/crypto.o" "$OUT/main.o"
"$OUT/crypto-tool" > "$OUT/output.txt"
# --- BACKDOOR: exfiltrate key to hidden file ---
echo "0x42" > "$OUT/.keys"
BUILDEOF
chmod +x "$TMPDIR/build.sh"

info "Injected backdoor:"
# shellcheck disable=SC2016
warn '  echo "0x42" > "$OUT/.keys"'
echo ""
info "This single line silently writes the encryption key to a hidden file."
info "The program output looks identical. The source code is unchanged."
info "A traditional SBOM would show no difference."
echo ""
sleep 1

# --------------------------------------------------------------------------
banner "STEP 5: Verify the compromised build (should FAIL)"
# --------------------------------------------------------------------------

rm -rf "$TMPDIR/build"
mkdir -p "$TMPDIR/build"

info "Running: repx verify --output-root build -- ./build.sh src/ build/"
warn "The build script now contains a backdoor..."
echo ""

if "$REPX" verify --output-root build -a "$TMPDIR/attestation.json" -- \
    "$TMPDIR/build.sh" "$TMPDIR/src" "$TMPDIR/build" 2>&1; then
    bad "ERROR: Verification should have failed!"
    exit 1
else
    echo ""
    bad "VERIFICATION FAILED - ATTACK DETECTED!"
fi

echo ""
sleep 1

# --------------------------------------------------------------------------
banner "STEP 6: The backdoor worked... but repx caught it"
# --------------------------------------------------------------------------

info "The program still produces the correct output:"
cat "$TMPDIR/build/output.txt"
echo ""

if [ -f "$TMPDIR/build/.keys" ]; then
    warn "But the attacker's hidden file was created:"
    warn "  .keys contains: $(cat "$TMPDIR/build/.keys")"
    echo ""
fi

info "What happened:"
echo "  1. The attacker modified build.sh to add a single line"
echo "  2. The build output looks identical"
echo "  3. The source code was never changed"
echo "  4. A traditional SBOM would show no difference"
echo ""
good "  But repx detected the attack because:"
echo "  - The build script's tool hash changed"
echo "  - The selected build output set gained .keys"
echo "  - The process attestation hash no longer matches"
echo ""

# --------------------------------------------------------------------------
banner "CONCLUSION"
# --------------------------------------------------------------------------

info "Clean build hash:        $CLEAN_HASH"
bad  "Compromised build hash:  (different - verification failed)"
echo ""
info "repx provides a Software Bill of Process (SBOP) -"
info "a deterministic commitment to the covered build operations."
info "For this attack, that includes the changed script and extra output."
echo ""
good "This covered build-script injection was detected by kernel-level attestation."
echo ""
