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
use std::fs;

use crate::tracer::TracedEvent;

/// Sentinel hash used for system state reads that should be normalized.
pub const SYSTEM_STATE_SENTINEL: &str =
    "SYSTEM_STATE:0000000000000000000000000000000000000000000000000000000000000000";

/// Paths that represent system state rather than build inputs.
const SYSTEM_STATE_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/etc/hostname",
    "/etc/os-release",
    "/etc/machine-id",
    "/dev/urandom",
    "/dev/random",
    "/dev/null",
    "/dev/zero",
];

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
    /// Produce a deterministic hash of this operation for the merkle tree.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        // Use a stable string representation instead of Debug format,
        // which could change between compiler versions.
        let op_tag = match self.op_type {
            OpType::Exec => "exec",
            OpType::FileRead => "file_read",
            OpType::FileWrite => "file_write",
            OpType::SystemStateRead => "system_state_read",
            OpType::Exit => "exit",
            OpType::ExternalFileRead => "external_file_read",
            OpType::ExternalFileWrite => "external_file_write",
        };
        hasher.update(op_tag.as_bytes());
        hasher.update(self.process_index.to_le_bytes());

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

/// Check if a path represents system state that should be normalized.
fn is_system_state(path: &str) -> bool {
    SYSTEM_STATE_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Hash the contents of a file. Returns None if the file can't be read.
fn hash_file_contents(path: &str) -> Option<String> {
    let data = fs::read(path).ok()?;
    let hash = Sha256::digest(&data);
    Some(format!("sha256:{:x}", hash))
}

/// Hash a byte slice.
fn hash_bytes(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("sha256:{:x}", hash)
}

fn is_watched_path(path: &str, watch_prefixes: &[String]) -> bool {
    watch_prefixes.iter().any(|prefix| path.starts_with(prefix))
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
                pid,
                filename,
                argv,
                ..
            } => {
                // Assign logical index if new.
                if !pid_to_index.contains_key(pid) {
                    pid_to_index.insert(*pid, next_index);
                    next_index += 1;
                }
                let proc_idx = pid_to_index[pid];

                // Hash the executable binary.
                let tool_hash = hash_file_contents(filename);
                if let Some(ref th) = tool_hash {
                    pid_to_tool_hash.insert(*pid, th.clone());
                }

                // Keep argv literally. File content is captured via
                // FileOpen/FileClose events, so hashing argv paths here
                // would be redundant and would cause non-determinism when
                // the compiler produces output files (which are hashed at
                // canonicalization time, after the build completes).
                let args: Vec<String> = argv.iter().skip(1).cloned().collect();

                ops.push(CanonicalOp {
                    op_type: OpType::Exec,
                    process_index: proc_idx,
                    tool_hash,
                    args,
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
                ..
            } => {
                if *external && !is_watched_path(path, watch_prefixes) {
                    continue;
                }

                // O_WRONLY = 1, O_RDWR = 2 on Linux
                let is_write = (flags & 0x3) != 0;

                let fallback_external = !*external
                    && *pid != root_pid
                    && is_watched_path(path, watch_prefixes)
                    && (fallback_external_pids.contains(pid)
                        || !pid_to_tool_hash.contains_key(pid));

                if *external || fallback_external {
                    fallback_external_pids.insert(*pid);
                    // External process touching a watched path.
                    if is_write {
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
                    } else {
                        let input_hash =
                            hash_file_contents(path).unwrap_or_else(|| hash_bytes(b"<unreadable>"));
                        external_ops.push(CanonicalOp {
                            op_type: OpType::ExternalFileRead,
                            process_index: u32::MAX,
                            tool_hash: None,
                            args: vec![],
                            input_hashes: vec![input_hash],
                            output_hashes: vec![],
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
                } else if is_write {
                    // Output file: we'll hash on close.
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
                } else {
                    // Input file: hash contents now.
                    let input_hash =
                        hash_file_contents(path).unwrap_or_else(|| hash_bytes(b"<unreadable>"));
                    ops.push(CanonicalOp {
                        op_type: OpType::FileRead,
                        process_index: proc_idx,
                        tool_hash: pid_to_tool_hash.get(pid).cloned(),
                        args: vec![],
                        input_hashes: vec![input_hash],
                        output_hashes: vec![],
                    });
                }
            }

            TracedEvent::FileMmap {
                pid,
                fd,
                prot,
                path,
                external,
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

                if let Some(path) = path {
                    // PROT_WRITE = 0x2
                    let is_write = (prot & 0x2) != 0;

                    let fallback_external = !*external
                        && (*pid != root_pid)
                        && is_watched_path(path, watch_prefixes)
                        && (fallback_external_pids.contains(pid)
                            || !pid_to_tool_hash.contains_key(pid));

                    if *external || fallback_external {
                        fallback_external_pids.insert(*pid);
                        if is_write {
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
                        } else {
                            let input_hash = hash_file_contents(path)
                                .unwrap_or_else(|| hash_bytes(b"<unreadable>"));
                            external_ops.push(CanonicalOp {
                                op_type: OpType::ExternalFileRead,
                                process_index: u32::MAX,
                                tool_hash: None,
                                args: vec![],
                                input_hashes: vec![input_hash],
                                output_hashes: vec![],
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
                    } else if is_write {
                        let op_idx = ops.len();
                        ops.push(CanonicalOp {
                            op_type: OpType::FileWrite,
                            process_index: proc_idx,
                            tool_hash: pid_to_tool_hash.get(pid).cloned(),
                            args: vec![],
                            input_hashes: vec![],
                            output_hashes: vec![],
                        });
                        pending_writes.insert((*pid, *fd), op_idx);
                    } else {
                        let input_hash =
                            hash_file_contents(path).unwrap_or_else(|| hash_bytes(b"<unreadable>"));
                        ops.push(CanonicalOp {
                            op_type: OpType::FileRead,
                            process_index: proc_idx,
                            tool_hash: pid_to_tool_hash.get(pid).cloned(),
                            args: vec![],
                            input_hashes: vec![input_hash],
                            output_hashes: vec![],
                        });
                    }
                }
            }

            TracedEvent::FileClose {
                pid,
                fd,
                path,
                external,
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
                            let output_hash = hash_file_contents(path)
                                .unwrap_or_else(|| hash_bytes(b"<unreadable>"));
                            if let Some(op) = external_ops.get_mut(op_idx) {
                                op.output_hashes.push(output_hash);
                            }
                        }
                    } else if let Some(op_idx) = pending_writes.remove(&(*pid, *fd)) {
                        // Fork-tree pending write.
                        let output_hash =
                            hash_file_contents(path).unwrap_or_else(|| hash_bytes(b"<unreadable>"));
                        if let Some(op) = ops.get_mut(op_idx) {
                            op.output_hashes.push(output_hash);
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

    // Sort external ops by their content hash for deterministic ordering.
    // External events arrive in non-deterministic order (any process, any time),
    // so we sort to produce a stable attestation across runs.
    external_ops.sort_by(|a, b| a.hash().cmp(&b.hash()));
    ops.extend(external_ops);

    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;
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
                dfd: 0,
                external: true,
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
                path: Some("/tmp/not-watched".to_string()),
                external: true,
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
                    dfd: 0,
                    external: false,
                },
                TracedEvent::Exec {
                    pid: 2,
                    ppid: 1,
                    filename: "/bin/true".to_string(),
                    argv: vec!["/bin/true".to_string()],
                },
                TracedEvent::FileMmap {
                    pid: 2,
                    fd: 4,
                    prot: 0,
                    path: Some(mmap_path.to_string_lossy().to_string()),
                    external: false,
                },
                TracedEvent::FileClose {
                    pid: 2,
                    fd: 3,
                    path: Some(write_path.to_string_lossy().to_string()),
                    external: false,
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
}
