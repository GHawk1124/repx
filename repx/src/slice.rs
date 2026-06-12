use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::canonicalize::{finalize_ops, CanonicalOp, OpType};
use crate::file_identity::{is_system_state, SYSTEM_STATE_SENTINEL};
use crate::tracer::TracedEvent;
use crate::workspace::OutputFile;

#[derive(Default)]
struct ProcessFlow {
    tool_hash: Option<String>,
    reads: HashSet<String>,
    writes: HashSet<String>,
}

pub fn canonicalize_output_slice(
    events: Vec<TracedEvent>,
    root_pid: u32,
    outputs: &[OutputFile],
) -> Result<Vec<CanonicalOp>> {
    let mut flows: HashMap<u32, ProcessFlow> = HashMap::new();
    let mut pending_writes: HashMap<(u32, i32), String> = HashMap::new();
    let mut writers_by_hash: HashMap<String, HashSet<u32>> = HashMap::new();
    let mut writers_by_path: HashMap<String, HashSet<u32>> = HashMap::new();
    let mut output_hashes: HashSet<String> = outputs.iter().map(|out| out.hash.clone()).collect();
    let mut root_exit_code = None;

    for event in events {
        match event {
            TracedEvent::Exec {
                pid, observation, ..
            } => {
                flows.entry(pid).or_default().tool_hash = Some(observation.identity());
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
                if external {
                    continue;
                }

                let access_mode = flags & 0x3;
                let can_read = access_mode != 1;
                let can_write = access_mode != 0;
                if can_read {
                    let hash = if is_system_state(&path) {
                        Some(SYSTEM_STATE_SENTINEL.to_string())
                    } else {
                        observation.content_hash().map(ToOwned::to_owned)
                    };
                    if let Some(hash) = hash {
                        flows.entry(pid).or_default().reads.insert(hash);
                    }
                }
                if can_write {
                    pending_writes.insert((pid, fd), path);
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
                if external {
                    continue;
                }

                let is_write = (prot & 0x2) != 0 && (flags & 0x1) != 0;
                if let (Some(path), Some(observation)) = (path, observation) {
                    let hash = if is_system_state(&path) {
                        Some(SYSTEM_STATE_SENTINEL.to_string())
                    } else {
                        observation.content_hash().map(ToOwned::to_owned)
                    };
                    if let Some(hash) = hash {
                        flows.entry(pid).or_default().reads.insert(hash);
                    }
                    if is_write {
                        pending_writes.insert((pid, fd), path);
                    }
                }
            }
            TracedEvent::FileClose {
                pid,
                fd,
                external,
                observation,
                ..
            } => {
                if external {
                    continue;
                }

                let write_path = pending_writes.remove(&(pid, fd));
                if let (Some(path), Some(observation)) = (write_path, observation) {
                    writers_by_path.entry(path).or_default().insert(pid);
                    if let Some(hash) = observation.content_hash() {
                        let hash = hash.to_string();
                        flows.entry(pid).or_default().writes.insert(hash.clone());
                        writers_by_hash.entry(hash).or_default().insert(pid);
                    }
                }
            }
            TracedEvent::Exit { pid, exit_code } => {
                if pid == root_pid {
                    root_exit_code = Some(exit_code);
                }
            }
        }
    }

    if output_hashes.is_empty() {
        return Ok(Vec::new());
    }

    let mut included_pids = HashSet::new();
    let mut relevant_hashes = output_hashes.clone();
    let mut queue = VecDeque::new();

    for output in outputs {
        if let Some(writers) = writers_by_path.get(&output.path) {
            for pid in writers {
                if included_pids.insert(*pid) {
                    queue.push_back(*pid);
                }
            }
        }
    }

    while let Some(pid) = queue.pop_front() {
        let Some(flow) = flows.get(&pid) else {
            continue;
        };

        for read_hash in &flow.reads {
            if relevant_hashes.insert(read_hash.clone()) {
                if let Some(writers) = writers_by_hash.get(read_hash) {
                    for writer_pid in writers {
                        if included_pids.insert(*writer_pid) {
                            queue.push_back(*writer_pid);
                        }
                    }
                }
            }
        }
    }

    let mut ops = Vec::new();
    let mut pids: Vec<u32> = included_pids.into_iter().collect();
    pids.sort_unstable();

    for pid in pids {
        let Some(flow) = flows.get(&pid) else {
            continue;
        };

        if let Some(tool_hash) = &flow.tool_hash {
            ops.push(CanonicalOp {
                op_type: OpType::Exec,
                process_index: pid,
                tool_hash: Some(tool_hash.clone()),
                args: vec![],
                input_hashes: vec![],
                output_hashes: vec![],
            });
        }

        for read_hash in sorted_hashes(&flow.reads) {
            if relevant_hashes.contains(&read_hash) {
                ops.push(CanonicalOp {
                    op_type: OpType::FileRead,
                    process_index: pid,
                    tool_hash: flow.tool_hash.clone(),
                    args: vec![],
                    input_hashes: vec![read_hash],
                    output_hashes: vec![],
                });
            }
        }

        for write_hash in sorted_hashes(&flow.writes) {
            if relevant_hashes.contains(&write_hash) || output_hashes.contains(&write_hash) {
                output_hashes.remove(&write_hash);
                ops.push(CanonicalOp {
                    op_type: OpType::FileWrite,
                    process_index: pid,
                    tool_hash: flow.tool_hash.clone(),
                    args: vec![],
                    input_hashes: vec![],
                    output_hashes: vec![write_hash],
                });
            }
        }
    }

    for orphan_hash in sorted_hashes(&output_hashes) {
        ops.push(CanonicalOp {
            op_type: OpType::FileWrite,
            process_index: u32::MAX,
            tool_hash: None,
            args: vec!["output".to_string()],
            input_hashes: vec![],
            output_hashes: vec![orphan_hash],
        });
    }

    if let Some(exit_code) = root_exit_code {
        ops.push(CanonicalOp {
            op_type: OpType::Exit,
            process_index: root_pid,
            tool_hash: flows.get(&root_pid).and_then(|flow| flow.tool_hash.clone()),
            args: vec![format!("exit:{}", exit_code)],
            input_hashes: vec![],
            output_hashes: vec![],
        });
    }

    Ok(finalize_ops(ops))
}

fn sorted_hashes(hashes: &HashSet<String>) -> Vec<String> {
    let mut values: Vec<String> = hashes.iter().cloned().collect();
    values.sort();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_identity::{hash_file_contents, observe_path, FileObservation};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("repx-slice-{name}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn slices_to_process_that_wrote_changed_output() {
        let dir = unique_dir("basic");
        fs::create_dir_all(&dir).unwrap();

        let tool = dir.join("tool");
        let input = dir.join("input.txt");
        let output = dir.join("output.txt");
        let unrelated = dir.join("unrelated.txt");
        fs::write(&tool, b"tool").unwrap();
        fs::write(&input, b"input").unwrap();
        fs::write(&output, b"output").unwrap();
        fs::write(&unrelated, b"unrelated").unwrap();

        let output_hash = hash_file_contents(&output).unwrap();
        let events = vec![
            TracedEvent::Exec {
                pid: 10,
                observation: observe_path(&tool.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                pid: 10,
                path: input.to_string_lossy().to_string(),
                flags: 0,
                fd: 3,
                external: false,
                observation: observe_path(&input.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                pid: 10,
                path: output.to_string_lossy().to_string(),
                flags: 1,
                fd: 4,
                external: false,
                observation: observe_path(&output.to_string_lossy()),
            },
            TracedEvent::FileClose {
                pid: 10,
                fd: 4,
                path: Some(output.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&output.to_string_lossy())),
            },
            TracedEvent::FileOpen {
                pid: 11,
                path: unrelated.to_string_lossy().to_string(),
                flags: 1,
                fd: 5,
                external: false,
                observation: observe_path(&unrelated.to_string_lossy()),
            },
            TracedEvent::FileClose {
                pid: 11,
                fd: 5,
                path: Some(unrelated.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&unrelated.to_string_lossy())),
            },
            TracedEvent::Exit {
                pid: 10,
                exit_code: 0,
            },
        ];

        let ops = canonicalize_output_slice(
            events,
            10,
            &[OutputFile {
                path: output.to_string_lossy().to_string(),
                hash: output_hash,
            }],
        )
        .unwrap();

        assert!(ops.iter().any(|op| op.op_type == OpType::Exec));
        assert!(ops.iter().any(|op| op.op_type == OpType::FileRead));
        assert!(ops.iter().any(|op| op.op_type == OpType::FileWrite));
        assert!(!ops.iter().any(|op| {
            op.output_hashes
                .iter()
                .any(|hash| hash == &hash_file_contents(&unrelated).unwrap())
        }));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prefers_output_path_writer_over_same_hash_writer() {
        let dir = unique_dir("path-writer");
        fs::create_dir_all(&dir).unwrap();

        let tool = dir.join("tool");
        let input = dir.join("input.txt");
        let output = dir.join("output.txt");
        let cache = dir.join("cache.txt");
        let volatile = dir.join("volatile.txt");
        fs::write(&tool, b"tool").unwrap();
        fs::write(&input, b"input").unwrap();
        fs::write(&output, b"same").unwrap();
        fs::write(&cache, b"same").unwrap();
        fs::write(&volatile, b"volatile").unwrap();

        let output_hash = hash_file_contents(&output).unwrap();
        let volatile_hash = hash_file_contents(&volatile).unwrap();

        let events = vec![
            TracedEvent::Exec {
                pid: 10,
                observation: observe_path(&tool.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                pid: 10,
                path: input.to_string_lossy().to_string(),
                flags: 0,
                fd: 3,
                external: false,
                observation: observe_path(&input.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                pid: 10,
                path: output.to_string_lossy().to_string(),
                flags: 1,
                fd: 4,
                external: false,
                observation: observe_path(&output.to_string_lossy()),
            },
            TracedEvent::FileClose {
                pid: 10,
                fd: 4,
                path: Some(output.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&output.to_string_lossy())),
            },
            TracedEvent::Exec {
                pid: 20,
                observation: observe_path(&tool.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                pid: 20,
                path: volatile.to_string_lossy().to_string(),
                flags: 0,
                fd: 5,
                external: false,
                observation: observe_path(&volatile.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                pid: 20,
                path: cache.to_string_lossy().to_string(),
                flags: 1,
                fd: 6,
                external: false,
                observation: observe_path(&cache.to_string_lossy()),
            },
            TracedEvent::FileClose {
                pid: 20,
                fd: 6,
                path: Some(cache.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&cache.to_string_lossy())),
            },
        ];

        let ops = canonicalize_output_slice(
            events,
            10,
            &[OutputFile {
                path: output.to_string_lossy().to_string(),
                hash: output_hash,
            }],
        )
        .unwrap();

        assert!(!ops
            .iter()
            .any(|op| { op.input_hashes.iter().any(|hash| hash == &volatile_hash) }));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn child_output_writer_seeds_the_provenance_slice() {
        let dir = unique_dir("child-writer");
        fs::create_dir_all(&dir).unwrap();

        let root_tool = dir.join("root-tool");
        let child_tool = dir.join("child-tool");
        let output = dir.join("output.txt");
        fs::write(&root_tool, b"root").unwrap();
        fs::write(&child_tool, b"child").unwrap();
        fs::write(&output, b"output").unwrap();

        let output_hash = hash_file_contents(&output).unwrap();
        let events = vec![
            TracedEvent::Exec {
                pid: 10,
                observation: observe_path(&root_tool.to_string_lossy()),
            },
            TracedEvent::Exec {
                pid: 11,
                observation: observe_path(&child_tool.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                pid: 11,
                path: output.to_string_lossy().to_string(),
                flags: 1,
                fd: 4,
                external: false,
                observation: observe_path(&output.to_string_lossy()),
            },
            TracedEvent::FileClose {
                pid: 11,
                fd: 4,
                path: Some(output.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&output.to_string_lossy())),
            },
        ];

        let ops = canonicalize_output_slice(
            events,
            10,
            &[OutputFile {
                path: output.to_string_lossy().to_string(),
                hash: output_hash,
            }],
        )
        .unwrap();

        assert!(ops
            .iter()
            .any(|op| op.op_type == OpType::Exec && op.process_index == 11));
        assert!(ops.iter().any(|op| {
            op.op_type == OpType::FileWrite
                && op.process_index == 11
                && op.output_hashes == vec![hash_file_contents(&output).unwrap()]
        }));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_only_close_does_not_claim_output_authorship() {
        let dir = unique_dir("read-only-close");
        fs::create_dir_all(&dir).unwrap();
        let tool = dir.join("tool");
        let output = dir.join("output.txt");
        fs::write(&tool, b"tool").unwrap();
        fs::write(&output, b"output").unwrap();

        let ops = canonicalize_output_slice(
            vec![
                TracedEvent::Exec {
                    pid: 10,
                    observation: observe_path(&tool.to_string_lossy()),
                },
                TracedEvent::FileOpen {
                    pid: 10,
                    path: output.to_string_lossy().into_owned(),
                    flags: 0,
                    fd: 3,
                    external: false,
                    observation: observe_path(&output.to_string_lossy()),
                },
                TracedEvent::FileClose {
                    pid: 10,
                    fd: 3,
                    path: Some(output.to_string_lossy().into_owned()),
                    external: false,
                    observation: Some(observe_path(&output.to_string_lossy())),
                },
            ],
            10,
            &[OutputFile {
                path: output.to_string_lossy().into_owned(),
                hash: hash_file_contents(&output).unwrap(),
            }],
        )
        .unwrap();

        assert!(!ops.iter().any(|op| op.op_type == OpType::Exec));
        assert!(ops
            .iter()
            .any(|op| { op.op_type == OpType::FileWrite && op.process_index == u32::MAX }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn output_slice_omits_unavailable_transient_dependencies() {
        let dir = unique_dir("unavailable-transient");
        fs::create_dir_all(&dir).unwrap();
        let tool = dir.join("tool");
        let output = dir.join("output.txt");
        fs::write(&tool, b"tool").unwrap();
        fs::write(&output, b"output").unwrap();

        let unavailable = FileObservation::Missing("sha256:random-temp-path".to_string());
        let ops = canonicalize_output_slice(
            vec![
                TracedEvent::Exec {
                    pid: 10,
                    observation: observe_path(&tool.to_string_lossy()),
                },
                TracedEvent::FileOpen {
                    pid: 10,
                    path: "/tmp/cc-random.s".to_string(),
                    flags: 0,
                    fd: 3,
                    external: false,
                    observation: unavailable.clone(),
                },
                TracedEvent::FileOpen {
                    pid: 10,
                    path: output.to_string_lossy().into_owned(),
                    flags: 1,
                    fd: 4,
                    external: false,
                    observation: unavailable,
                },
                TracedEvent::FileClose {
                    pid: 10,
                    fd: 4,
                    path: Some(output.to_string_lossy().into_owned()),
                    external: false,
                    observation: Some(observe_path(&output.to_string_lossy())),
                },
            ],
            10,
            &[OutputFile {
                path: output.to_string_lossy().into_owned(),
                hash: hash_file_contents(&output).unwrap(),
            }],
        )
        .unwrap();

        assert!(ops.iter().any(|op| op.op_type == OpType::Exec));
        assert!(!ops.iter().any(|op| {
            op.input_hashes
                .iter()
                .chain(&op.output_hashes)
                .any(|hash| hash.starts_with("missing:"))
        }));
        let _ = fs::remove_dir_all(&dir);
    }
}
