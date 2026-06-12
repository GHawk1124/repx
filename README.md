# repx

`repx` is a Linux/eBPF prototype for reproducible build-process attestations. It traces a selected set of process and file events, captures file identities while events are arriving, canonicalizes the observations into a deterministic set of distinct operations, and commits that set with a Merkle root.

The attestation answers a narrow question: did this command reproduce the same set of **covered** operations and selected outputs as a trusted baseline? It is not a complete record of every kernel action.

## Build

```bash
nix develop -c ./build.sh
```

The resulting binary is `target/release/repx`. Loading the eBPF programs requires root or equivalent BPF capabilities.

## Use

```bash
sudo ./target/release/repx trace \
  --output-root dist \
  -o repx-attestation.json \
  -- make release

sudo ./target/release/repx verify \
  --output-root dist \
  -a repx-attestation.json \
  -- make release
```

Verification requires the exact command and explicit output-selection flags used during tracing. This prevents command and artifact policy from being silently inherited from an untrusted JSON file.

When a trusted root is distributed separately, pin it with `--expected-root sha256:...` to detect replacement of the attestation file.

Use `--artifact PATH` for individual outputs, `--dump-ops PATH` to inspect canonical operations, `explain` for a summary, and `diff` for added/missing operation hashes and output changes.

Use `repx stability --strict run-*.json` to measure attestation-root stability,
process-root stability, and leaf-set Jaccard similarity across repeated traces.
The privileged `nix run .#test-determinism` harness applies this analysis to the
project's integration workload matrix.

## Security Semantics

- File reads, tool binaries, mmap inputs, and close-time outputs are hashed when their events reach userspace. Only regular files are opened, using nonblocking handles; retained handles allow deleted temporary files to remain hashable.
- `O_RDWR` contributes both a read and a write. Writable private mappings are reads; only writable `MAP_SHARED` mappings are classified as file writes.
- Canonicalization produces a sorted set of distinct covered operations. Counts, ordering, timestamps, and process indices are diagnostic data, not part of the process-set root.
- Output-rooted attestations commit selected outputs and content-resolved dependencies. Unavailable transient intermediates remain visible in full-trace mode but are omitted from the output dependency walk. Missing, unreadable, and non-regular identities bind stable paths while normalizing recognized session and compiler temporary names.
- The top-level root binds the process-set root, command, output selection, and output hashes.
- Event loss fails closed by default. `trace --allow-dropped-events` is an explicit escape hatch for incomplete diagnostic attestations.
- The eBPF ring uses compact fixed-size events and a 32 MiB capacity to absorb bursty build-system workloads such as Bazel.
- Attestations are currently unsigned. They must be distributed through a trusted channel or checked with `--expected-root`; DSSE/Sigstore signing remains future work.

## Coverage Boundary

| Behavior | Status |
| --- | --- |
| `openat`, `close`, file-backed `mmap`, `exec`, fork, exit | Covered |
| `open`, `openat2` | Not covered |
| `rename`, `unlink`, temp-file replacement | Not modeled as operations |
| `dup*`, inherited descriptors | Descriptor attribution incomplete |
| `sendfile`, `copy_file_range`, `io_uring` | Not covered |
| Network I/O and remote inputs | Not covered |
| External relative-path reads in `--watch` mode | May be missed by kernel prefix filtering |
| External writes in `--watch` mode | Resolved and prefix-checked in userspace before file observation |
| Paths longer than the event buffer | Descriptor resolution usually recovers them; otherwise coverage is incomplete |

An attacker who controls the build can deliberately choose an uncovered path. Treat the current prototype as a deterministic commitment over observed covered behavior, not proof that no malicious activity occurred.

## Tests

```bash
cargo test --workspace
```

Privileged integration scenarios are documented in [tests/README-testing.md](tests/README-testing.md).

## License

MIT. See [LICENSE](LICENSE).
