## repx testing progression (run in order, stop at first failure)

Run every command from the repository root.

### 0. Build

```bash
nix develop -c ./build.sh
```

Expect both the eBPF object and the userspace binary to compile.

### 1. Smoke: two-terminal external write

Terminal 1:

```bash
sudo ./target/release/repx trace --watch /tmp/repx-smoke/ \
    --dump-ops /tmp/ops.json -o /tmp/att.json -- bash -c "sleep 3; echo hi"
```

Terminal 2, while Terminal 1 is sleeping:

```bash
mkdir -p /tmp/repx-smoke && echo tamper > /tmp/repx-smoke/x
```

Expect `/tmp/att.json` to contain `external_file_write`.

```bash
python3 -c 'import json; d=json.load(open("/tmp/ops.json")); print([op for op in d if "External" in op["op_type"]])'
```

### 2. Simulated-build demo (hardened)

```bash
sudo nix run .#demo-nix-build
```

Expect the clean verify to pass and the tampered verify to fail with `external_file_write` in the follow-up tampered attestation.

### 3. Real nix-build demo

```bash
sudo nix run .#demo-real-nix-build
```

Expect a real `nix-build` invocation under `repx trace --watch`.
The clean rebuild should pass.
The tampered rebuild should fail and report `external_file_write` in the follow-up tampered attestation.
Exit code `77` means the test was skipped because the daemon path was unavailable or the store output could not be deleted.

### 4. Pre-existing regression tests

```bash
sudo nix run .#test
sudo nix run .#test-nix-build
sudo nix run .#test-bazel
sudo nix run .#test-build-systems
sudo nix run .#test-determinism
sudo nix run .#demo-attack
```

Expect all six to pass. The first four use two repeated traces by default;
`test-determinism` raises that count for stability measurement.
`test-bazel` traces a real Bazel build, verifies a second clean run against the
output-sliced attestation root, and asserts that repx captured the Bazel process
tree and file operations.
`test-build-systems` runs the same trace/verify pattern across Make,
CMake/Ninja, Cargo, and Go exported artifacts.

`test-determinism` repeats the smoke, multi-process C, Bazel, and build-system
matrix traces 20 times in fixed workspaces. It fails unless every attestation
root matches and reports process-root stability plus minimum and mean leaf-set
Jaccard similarity. Set `DETERMINISM_RUNS=50` for a longer experiment, or pass
workload names such as `bazel build-systems` after `--`.

For explicit output selection in manual tests, prefer:

```bash
sudo ./target/release/repx trace --output-root dist -o repx-attestation.json -- make release
sudo ./target/release/repx verify --output-root dist -a repx-attestation.json -- make release
```

Use `--artifact path/to/file` for individual files. Verification requires the
same explicit artifact and output-root flags; it does not trust policy copied
from the attestation file.

To inspect attestations without re-running a build:

```bash
./target/release/repx explain -a repx-attestation.json
./target/release/repx diff baseline-attestation.json candidate-attestation.json
./target/release/repx stability --strict run-*.json
```

`explain` prints the command, output-selection policy, recorded output hashes,
and operation-set size. `diff` compares output paths and hashes first, then
reports added and missing operation hashes if roots differ.

## Notes

`--watch` uses directory-boundary matching in userspace before opening or
hashing external files. External relative-path reads can still be missed by the
eBPF raw-path prefix filter.

If you need to inspect the generated attestation files after a demo, rerun with `KEEP_TMPDIR=1`.
