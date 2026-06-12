//! Event canonicalization.
//!
//! Transforms raw eBPF events into system-independent canonical operations.
//! This is where we:
//! - Replace file paths with content hashes
//! - Filter/normalize system state reads (/proc, /sys, etc.)
//! - Replace PIDs with logical process indices
//! - Strip timestamps (they're only used for ordering)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::file_identity::{is_path_within, is_system_state, SYSTEM_STATE_SENTINEL};
use crate::tracer::TracedEvent;

/// A canonicalized build operation, independent of any specific system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalOp {
    /// What kind of operation this is.
    pub op_type: OpType,
    /// Logical process index (0 = root process, 1 = first child, etc.)
    pub process_index: u32,
    /// Content hash of the executable that performed this operation.
    pub tool_hash: Option<String>,
    /// Non-path arguments (flags, options).
    pub args: Vec<String>,
    /// Content hashes of input files read.
    pub input_hashes: Vec<String>,
    /// Content hashes of output files written.
    pub output_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpType {
    /// Process executed a binary.
    Exec,
    /// File was read (input).
    FileRead,
    /// File was written (output).
    FileWrite,
    /// System state was accessed (normalized).
    SystemStateRead,
    /// Process exited.
    Exit,
    /// File was read by an external (non-fork-tree) process touching a watched path.
    ExternalFileRead,
    /// File was written by an external (non-fork-tree) process touching a watched path.
    ExternalFileWrite,
}

impl CanonicalOp {
    fn op_tag(&self) -> &'static str {
        match self.op_type {
            OpType::Exec => "exec",
            OpType::FileRead => "file_read",
            OpType::FileWrite => "file_write",
            OpType::SystemStateRead => "system_state_read",
            OpType::Exit => "exit",
            OpType::ExternalFileRead => "external_file_read",
            OpType::ExternalFileWrite => "external_file_write",
        }
    }

    /// Produce a deterministic hash of this operation for the merkle tree.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.op_tag().as_bytes());

        // Logical process indices depend on scheduler/event arrival order in
        // concurrent build tools. Keep them in dump-ops for diagnostics, but
        // exclude them from the semantic attestation hash.
        if let Some(ref th) = self.tool_hash {
            hasher.update(th.as_bytes());
        }

        for arg in &self.args {
            hasher.update(arg.as_bytes());
            hasher.update(b"\x00");
        }

        for h in &self.input_hashes {
            hasher.update(h.as_bytes());
        }

        for h in &self.output_hashes {
            hasher.update(h.as_bytes());
        }

        format!("sha256:{:x}", hasher.finalize())
    }
}

pub(crate) fn finalize_ops(mut ops: Vec<CanonicalOp>) -> Vec<CanonicalOp> {
    // Canonical roots are file/content-centric. Low-level open/read/mmap
    // counts and independent process interleavings can vary across otherwise
    // identical runs, especially under JVM-based build systems like Bazel.
    for op in &mut ops {
        op.args.sort();
        op.input_hashes.sort();
        op.output_hashes.sort();
    }

    ops.sort_by_key(|op| op.hash());
    ops.dedup_by(|a, b| a.hash() == b.hash());
    ops
}

fn is_watched_path(path: &str, watch_prefixes: &[String]) -> bool {
    watch_prefixes
        .iter()
        .any(|prefix| is_path_within(path, prefix))
}

/// Canonicalize raw traced events into system-independent operations.
///
/// `root_pid` is the PID of the root traced process (from the tracer).
/// This is used to determine which process gets its exit code included
/// in the canonical hash (only the root, since BPF can't capture exit
/// codes for child processes).
pub fn canonicalize_events(
    events: Vec<TracedEvent>,
    root_pid: u32,
    watch_prefixes: &[String],
) -> Result<Vec<CanonicalOp>> {
    let mut ops = Vec::new();

    // Map real PIDs to logical process indices.
    // The root process is always assigned index 0 explicitly.
    let mut pid_to_index: HashMap<u32, u32> = HashMap::new();
    pid_to_index.insert(root_pid, 0);
    let mut next_index: u32 = 1;

    // Track pending write ops by (pid, fd) -> index into ops vec.
    // When a file is closed, we look up the matching write op by fd
    // instead of scanning backwards for "most recent write by process".
    let mut pending_writes: HashMap<(u32, i32), usize> = HashMap::new();

    // External events (from watched paths, non-fork-tree processes).
    // Collected separately and sorted by hash for deterministic ordering,
    // since external event arrival order is non-deterministic.
    let mut external_ops: Vec<CanonicalOp> = Vec::new();
    let mut external_pending_writes: HashMap<(u32, i32), usize> = HashMap::new();
    let mut fallback_external_pids: HashSet<u32> = HashSet::new();

    let mut pid_to_tool_hash: HashMap<u32, String> = HashMap::new();

    for event in &events {
        match event {
            TracedEvent::Exec {
                pid, observation, ..
            } => {
                // Assign logical index if new.
                if !pid_to_index.contains_key(pid) {
                    pid_to_index.insert(*pid, next_index);
                    next_index += 1;
                }
                let proc_idx = pid_to_index[pid];

                let tool_hash = observation.identity();
                pid_to_tool_hash.insert(*pid, tool_hash.clone());

                // Argv is intentionally empty: BPF kernel-stack captures are
                // racy (the same exec yields different argv across runs) and
                // gcc emits random temp paths (/tmp/ccXXXXXX.s) into argv,
                // both breaking determinism. Build identity is captured via
                // tool_hash plus FileOpen/Close content hashes.
                ops.push(CanonicalOp {
                    op_type: OpType::Exec,
                    process_index: proc_idx,
                    tool_hash: Some(tool_hash),
                    args: vec![],
                    input_hashes: vec![],
                    output_hashes: vec![],
                });
            }

            TracedEvent::FileOpen {
                pid,
                path,
                flags,
                fd,
                external,
                observation,
                ..
            } => {
                if *external && !is_watched_path(path, watch_prefixes) {
                    continue;
                }

                // Linux O_ACCMODE: O_RDONLY=0, O_WRONLY=1, O_RDWR=2.
                let access_mode = flags & 0x3;
                let can_read = access_mode != 1;
                let can_write = access_mode != 0;

                let fallback_external = !*external
                    && *pid != root_pid
                    && is_watched_path(path, watch_prefixes)
                    && (fallback_external_pids.contains(pid)
                        || !pid_to_tool_hash.contains_key(pid));

                if *external || fallback_external {
                    fallback_external_pids.insert(*pid);
                    // External process touching a watched path.
                    if can_read {
                        external_ops.push(CanonicalOp {
                            op_type: OpType::ExternalFileRead,
                            process_index: u32::MAX,
                            tool_hash: None,
                            args: vec![],
                            input_hashes: vec![observation.identity()],
                            output_hashes: vec![],
                        });
                    }
                    if can_write {
                        let op_idx = external_ops.len();
                        external_ops.push(CanonicalOp {
                            op_type: OpType::ExternalFileWrite,
                            process_index: u32::MAX,
                            tool_hash: None,
                            args: vec![],
                            input_hashes: vec![],
                            output_hashes: vec![],
                        });
                        external_pending_writes.insert((*pid, *fd), op_idx);
                    }
                    continue;
                }

                if !pid_to_index.contains_key(pid) {
                    pid_to_index.insert(*pid, next_index);
                    next_index += 1;
                }
                let proc_idx = pid_to_index[pid];

                if is_system_state(path) {
                    ops.push(CanonicalOp {
                        op_type: OpType::SystemStateRead,
                        process_index: proc_idx,
                        tool_hash: pid_to_tool_hash.get(pid).cloned(),
                        args: vec![],
                        input_hashes: vec![SYSTEM_STATE_SENTINEL.to_string()],
                        output_hashes: vec![],
                    });
                } else {
                    if can_read {
                        ops.push(CanonicalOp {
                            op_type: OpType::FileRead,
                            process_index: proc_idx,
                            tool_hash: pid_to_tool_hash.get(pid).cloned(),
                            args: vec![],
                            input_hashes: vec![observation.identity()],
                            output_hashes: vec![],
                        });
                    }

                    if can_write {
                        // Output file: its close event carries the final identity.
                        let op_idx = ops.len();
                        ops.push(CanonicalOp {
                            op_type: OpType::FileWrite,
                            process_index: proc_idx,
                            tool_hash: pid_to_tool_hash.get(pid).cloned(),
                            args: vec![],
                            input_hashes: vec![],
                            output_hashes: vec![], // filled when we see the close
                        });
                        pending_writes.insert((*pid, *fd), op_idx);
                    }
                }
            }

            TracedEvent::FileMmap {
                pid,
                fd,
                prot,
                flags,
                path,
                external,
                observation,
                ..
            } => {
                if *external {
                    let Some(path) = path.as_deref() else {
                        continue;
                    };
                    if !is_watched_path(path, watch_prefixes) {
                        continue;
                    }
                }

                if let (Some(path), Some(observation)) = (path, observation) {
                    // A private writable mapping does not write back to the file.
                    // MAP_SHARED and MAP_SHARED_VALIDATE both have bit 0 set.
                    let is_write = (prot & 0x2) != 0 && (flags & 0x1) != 0;

                    let fallback_external = !*external
                        && (*pid != root_pid)
                        && is_watched_path(path, watch_prefixes)
                        && (fallback_external_pids.contains(pid)
                            || !pid_to_tool_hash.contains_key(pid));

                    if *external || fallback_external {
                        fallback_external_pids.insert(*pid);
                        external_ops.push(CanonicalOp {
                            op_type: OpType::ExternalFileRead,
                            process_index: u32::MAX,
                            tool_hash: None,
                            args: vec!["mmap".to_string()],
                            input_hashes: vec![observation.identity()],
                            output_hashes: vec![],
                        });
                        if is_write {
                            external_pending_writes
                                .entry((*pid, *fd))
                                .or_insert_with(|| {
                                    let op_idx = external_ops.len();
                                    external_ops.push(CanonicalOp {
                                        op_type: OpType::ExternalFileWrite,
                                        process_index: u32::MAX,
                                        tool_hash: None,
                                        args: vec![],
                                        input_hashes: vec![],
                                        output_hashes: vec![],
                                    });
                                    op_idx
                                });
                        }
                        continue;
                    }

                    if !pid_to_index.contains_key(pid) {
                        pid_to_index.insert(*pid, next_index);
                        next_index += 1;
                    }
                    let proc_idx = pid_to_index[pid];

                    if is_system_state(path) {
                        ops.push(CanonicalOp {
                            op_type: OpType::SystemStateRead,
                            process_index: proc_idx,
                            tool_hash: pid_to_tool_hash.get(pid).cloned(),
                            args: vec![],
                            input_hashes: vec![SYSTEM_STATE_SENTINEL.to_string()],
                            output_hashes: vec![],
                        });
                    } else {
                        ops.push(CanonicalOp {
                            op_type: OpType::FileRead,
                            process_index: proc_idx,
                            tool_hash: pid_to_tool_hash.get(pid).cloned(),
                            args: vec!["mmap".to_string()],
                            input_hashes: vec![observation.identity()],
                            output_hashes: vec![],
                        });

                        if is_write {
                            pending_writes.entry((*pid, *fd)).or_insert_with(|| {
                                let op_idx = ops.len();
                                ops.push(CanonicalOp {
                                    op_type: OpType::FileWrite,
                                    process_index: proc_idx,
                                    tool_hash: pid_to_tool_hash.get(pid).cloned(),
                                    args: vec![],
                                    input_hashes: vec![],
                                    output_hashes: vec![],
                                });
                                op_idx
                            });
                        }
                    }
                }
            }

            TracedEvent::FileClose {
                pid,
                fd,
                path,
                external,
                observation,
                ..
            } => {
                if let Some(path) = path {
                    let fallback_external = !*external
                        && (*pid != root_pid)
                        && fallback_external_pids.contains(pid)
                        && is_watched_path(path, watch_prefixes);

                    if *external || fallback_external {
                        // Resolve pending external write if any.
                        if let Some(op_idx) = external_pending_writes.remove(&(*pid, *fd)) {
                            if let (Some(op), Some(observation)) =
                                (external_ops.get_mut(op_idx), observation)
                            {
                                op.output_hashes.push(observation.identity());
                            }
                        }
                    } else if let Some(op_idx) = pending_writes.remove(&(*pid, *fd)) {
                        // Fork-tree pending write.
                        if let (Some(op), Some(observation)) = (ops.get_mut(op_idx), observation) {
                            op.output_hashes.push(observation.identity());
                        }
                    }
                }
            }

            TracedEvent::Exit { pid, exit_code, .. } => {
                if let Some(&proc_idx) = pid_to_index.get(pid) {
                    // Only include exit code for the root process, which
                    // gets the real exit code from waitpid(). Child processes
                    // always report 0 from BPF (task_struct is opaque), so
                    // we exclude their exit code to avoid false confidence.
                    let args = if *pid == root_pid {
                        vec![format!("exit:{}", exit_code)]
                    } else {
                        vec![]
                    };
                    ops.push(CanonicalOp {
                        op_type: OpType::Exit,
                        process_index: proc_idx,
                        tool_hash: pid_to_tool_hash.get(pid).cloned(),
                        args,
                        input_hashes: vec![],
                        output_hashes: vec![],
                    });
                }
            }
        }
    }

    ops.extend(external_ops);

    Ok(finalize_ops(ops))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_identity::observe_path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "repx-canonicalize-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn drops_external_opens_outside_watched_prefixes() {
        let ops = canonicalize_events(
            vec![TracedEvent::FileOpen {
                pid: 2,
                path: "/tmp/not-watched".to_string(),
                flags: 1,
                fd: 3,
                external: true,
                observation: observe_path("/tmp/not-watched"),
            }],
            1,
            &["/watched".to_string()],
        )
        .unwrap();

        assert!(ops.is_empty());
    }

    #[test]
    fn drops_external_mmaps_outside_watched_prefixes() {
        let ops = canonicalize_events(
            vec![TracedEvent::FileMmap {
                pid: 2,
                fd: 3,
                prot: 0,
                flags: 0x2,
                path: Some("/tmp/not-watched".to_string()),
                external: true,
                observation: Some(observe_path("/tmp/not-watched")),
            }],
            1,
            &["/watched".to_string()],
        )
        .unwrap();

        assert!(ops.is_empty());
    }

    #[test]
    fn fallback_external_pid_stays_external_after_exec() {
        let dir = unique_test_dir("fallback-external");
        std::fs::create_dir_all(&dir).unwrap();

        let write_path = dir.join("artifact.txt");
        let mmap_path = dir.join("input.txt");
        std::fs::write(&write_path, b"artifact").unwrap();
        std::fs::write(&mmap_path, b"input").unwrap();

        let ops = canonicalize_events(
            vec![
                TracedEvent::FileOpen {
                    pid: 2,
                    path: write_path.to_string_lossy().to_string(),
                    flags: 1,
                    fd: 3,
                    external: false,
                    observation: observe_path(&write_path.to_string_lossy()),
                },
                TracedEvent::Exec {
                    pid: 2,
                    observation: observe_path("/bin/true"),
                },
                TracedEvent::FileMmap {
                    pid: 2,
                    fd: 4,
                    prot: 0,
                    flags: 0x2,
                    path: Some(mmap_path.to_string_lossy().to_string()),
                    external: false,
                    observation: Some(observe_path(&mmap_path.to_string_lossy())),
                },
                TracedEvent::FileClose {
                    pid: 2,
                    fd: 3,
                    path: Some(write_path.to_string_lossy().to_string()),
                    external: false,
                    observation: Some(observe_path(&write_path.to_string_lossy())),
                },
            ],
            1,
            &[dir.to_string_lossy().to_string()],
        )
        .unwrap();

        assert_eq!(
            ops.iter().filter(|op| op.op_type == OpType::Exec).count(),
            1
        );
        assert!(ops
            .iter()
            .any(|op| op.op_type == OpType::ExternalFileRead && op.process_index == u32::MAX));
        assert!(ops.iter().any(|op| {
            op.op_type == OpType::ExternalFileWrite
                && op.process_index == u32::MAX
                && !op.output_hashes.is_empty()
        }));
        assert_eq!(
            ops.iter()
                .filter(|op| matches!(op.op_type, OpType::FileRead | OpType::FileWrite))
                .count(),
            0
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_write_open_records_both_input_and_output() {
        let dir = unique_test_dir("rdwr");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("archive.a");
        std::fs::write(&path, b"archive").unwrap();
        let observation = observe_path(&path.to_string_lossy());

        let ops = canonicalize_events(
            vec![
                TracedEvent::FileOpen {
                    pid: 1,
                    path: path.to_string_lossy().into_owned(),
                    flags: 2,
                    fd: 3,
                    external: false,
                    observation: observation.clone(),
                },
                TracedEvent::FileClose {
                    pid: 1,
                    fd: 3,
                    path: Some(path.to_string_lossy().into_owned()),
                    external: false,
                    observation: Some(observation),
                },
            ],
            1,
            &[],
        )
        .unwrap();

        assert!(ops.iter().any(|op| op.op_type == OpType::FileRead));
        assert!(ops.iter().any(|op| op.op_type == OpType::FileWrite));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_writable_mmap_is_a_read_not_a_write() {
        let dir = unique_test_dir("private-mmap");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("library.so");
        std::fs::write(&path, b"library").unwrap();

        let ops = canonicalize_events(
            vec![TracedEvent::FileMmap {
                pid: 1,
                fd: 3,
                prot: 0x3,
                flags: 0x2,
                path: Some(path.to_string_lossy().into_owned()),
                external: false,
                observation: Some(observe_path(&path.to_string_lossy())),
            }],
            1,
            &[],
        )
        .unwrap();

        assert!(ops.iter().any(|op| op.op_type == OpType::FileRead));
        assert!(!ops.iter().any(|op| op.op_type == OpType::FileWrite));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
