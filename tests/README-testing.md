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
    -o /tmp/att.json -- bash -c "sleep 3; echo hi"
```

Terminal 2, while Terminal 1 is sleeping:

```bash
mkdir -p /tmp/repx-smoke && echo tamper > /tmp/repx-smoke/x
```

Expect `/tmp/att.json` to contain `external_file_write`.

```bash
python3 -c 'import json; d=json.load(open("/tmp/att.json")); print([n for n in d["tree"]["nodes"] if "external" in str(n)])'
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
sudo nix run .#demo-attack
```

Expect all three to behave exactly as before.

## Notes

`--watch` matches prefixes literally, so avoid collisions like `/tmp/foo` and `/tmp/foobar`.

If you need to inspect the generated attestation files after a demo, rerun with `KEEP_TMPDIR=1`.
