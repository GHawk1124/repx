use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::canonicalize::{finalize_ops, CanonicalOp, OpType};
use crate::file_identity::{is_system_state, SYSTEM_STATE_SENTINEL};
use crate::tracer::{ProcessInstance, ProcessLifetime, TracedEvent};
use crate::workspace::OutputFile;

#[derive(Default)]
struct ProcessFlow {
    tool_hash: Option<String>,
    has_exec: bool,
    reads: HashSet<String>,
    writes: HashSet<String>,
    renames: HashSet<String>,
}

#[derive(Clone)]
struct PendingWrite {
    process: ProcessInstance,
    path: String,
}

pub fn canonicalize_output_slice(
    events: Vec<TracedEvent>,
    root_process: ProcessInstance,
    outputs: &[OutputFile],
) -> Result<Vec<CanonicalOp>> {
    let mut flows: HashMap<ProcessInstance, ProcessFlow> = HashMap::new();
    let mut pending_writes: HashMap<(ProcessLifetime, i32), PendingWrite> = HashMap::new();
    let mut writers_by_hash: HashMap<String, HashSet<ProcessInstance>> = HashMap::new();
    let mut writers_by_path: HashMap<String, HashSet<ProcessInstance>> = HashMap::new();
    let mut output_hashes: HashSet<String> = outputs.iter().map(|out| out.hash.clone()).collect();
    let mut root_exit = None;
    let mut rename_pairs: Vec<(String, String)> = Vec::new();

    for event in events {
        match event {
            TracedEvent::Exec {
                process,
                observation,
                ..
            } => {
                let flow = flows.entry(process).or_default();
                flow.tool_hash = Some(observation.identity());
                flow.has_exec = true;
            }
            TracedEvent::Fork { parent, child } => {
                let inherited_tool = flows.get(&parent).and_then(|flow| flow.tool_hash.clone());
                flows.entry(child).or_default().tool_hash = inherited_tool;
                let inherited_writes: Vec<(i32, PendingWrite)> = pending_writes
                    .iter()
                    .filter(|((lifetime, _), _)| *lifetime == parent.lifetime)
                    .map(|((_, fd), pending_write)| (*fd, pending_write.clone()))
                    .collect();
                for (fd, pending_write) in inherited_writes {
                    pending_writes.insert((child.lifetime, fd), pending_write);
                }
            }
            TracedEvent::FileOpen {
                process,
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
                        flows.entry(process).or_default().reads.insert(hash);
                    }
                }
                if can_write {
                    pending_writes.insert((process.lifetime, fd), PendingWrite { process, path });
                }
            }
            TracedEvent::FileMmap {
                process,
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
                        flows.entry(process).or_default().reads.insert(hash);
                    }
                    if is_write {
                        pending_writes
                            .insert((process.lifetime, fd), PendingWrite { process, path });
                    }
                }
            }
            TracedEvent::FileClose {
                process,
                fd,
                path,
                external,
                observation,
                ..
            } => {
                if external {
                    continue;
                }

                let pending_write = pending_writes.remove(&(process.lifetime, fd));
                if let (Some(pending_write), Some(observation)) = (pending_write, observation) {
                    let path = path.unwrap_or(pending_write.path);
                    writers_by_path
                        .entry(path)
                        .or_default()
                        .insert(pending_write.process);
                    if let Some(hash) = observation.content_hash() {
                        let hash = hash.to_string();
                        flows
                            .entry(pending_write.process)
                            .or_default()
                            .writes
                            .insert(hash.clone());
                        writers_by_hash
                            .entry(hash)
                            .or_default()
                            .insert(pending_write.process);
                    }
                }
            }
            TracedEvent::FileRename {
                process,
                from_path,
                to_path,
                external,
                observation,
                ..
            } => {
                if external {
                    continue;
                }

                for pending_write in pending_writes.values_mut() {
                    if let Some(rewritten) =
                        rewrite_path_prefix(&pending_write.path, &from_path, &to_path)
                    {
                        pending_write.path = rewritten;
                    }
                }

                let aliases: Vec<(String, HashSet<ProcessInstance>)> = writers_by_path
                    .iter()
                    .filter_map(|(path, writers)| {
                        rewrite_path_prefix(path, &from_path, &to_path)
                            .map(|rewritten| (rewritten, writers.clone()))
                    })
                    .collect();
                for (path, writers) in aliases {
                    writers_by_path.entry(path).or_default().extend(writers);
                }

                // Always attribute the final path to the renamer — even when
                // the observation doesn't carry a content hash, this process
                // is responsible for the file appearing at `to_path`.
                writers_by_path
                    .entry(to_path.clone())
                    .or_default()
                    .insert(process);

                // Record the rename pair so a post-scan fixup can re-apply
                // path aliasing for writes that arrived after the rename
                // (reordered by parallel CPU ring-buffer submissions).
                rename_pairs.push((from_path.clone(), to_path.clone()));

                if let Some(hash) = observation.content_hash() {
                    let hash = hash.to_string();
                    let flow = flows.entry(process).or_default();
                    flow.reads.insert(hash.clone());
                    flow.renames.insert(hash.clone());
                    writers_by_hash.entry(hash).or_default().insert(process);
                }
            }
            TracedEvent::FileUnlink { .. } => {}
            TracedEvent::Exit { process, exit_code } => {
                if process.lifetime == root_process.lifetime {
                    root_exit = Some((process, exit_code));
                }
            }
        }
    }

    // --- Post-scan rename fixup -------------------------------------------
    //
    // In parallel builds, rename events can arrive before the close events
    // for writes to the old path (per-CPU ring-buffer submissions are not
    // globally ordered).  Re-apply every rename alias now that all writes
    // have been recorded so late-arriving writers are still attributed to
    // the final output path.
    for (from_path, to_path) in &rename_pairs {
        let aliases: Vec<(String, HashSet<ProcessInstance>)> = writers_by_path
            .iter()
            .filter_map(|(path, writers)| {
                rewrite_path_prefix(path, from_path, to_path)
                    .map(|rewritten| (rewritten, writers.clone()))
            })
            .collect();
        for (path, writers) in aliases {
            writers_by_path.entry(path).or_default().extend(writers);
        }
    }

    if output_hashes.is_empty() {
        return Ok(Vec::new());
    }

    let mut included_processes = HashSet::new();
    let mut relevant_hashes = output_hashes.clone();
    let mut queue = VecDeque::new();

    for output in outputs {
        if let Some(writers) = writers_by_path.get(&output.path) {
            for process in writers {
                if included_processes.insert(*process) {
                    queue.push_back(*process);
                }
            }
        }
    }

    while let Some(process) = queue.pop_front() {
        let Some(flow) = flows.get(&process) else {
            continue;
        };

        for read_hash in &flow.reads {
            if relevant_hashes.insert(read_hash.clone()) {
                if let Some(writers) = writers_by_hash.get(read_hash) {
                    for writer in writers {
                        if included_processes.insert(*writer) {
                            queue.push_back(*writer);
                        }
                    }
                }
            }
        }
    }

    let mut ops = Vec::new();
    let mut processes: Vec<ProcessInstance> = included_processes.into_iter().collect();
    processes.sort_unstable();
    let mut process_to_index = HashMap::from([(root_process, 0u32)]);
    let mut next_index = 1u32;
    for process in &processes {
        if !process_to_index.contains_key(process) {
            process_to_index.insert(*process, next_index);
            next_index += 1;
        }
    }
    if let Some((process, _)) = root_exit {
        process_to_index.entry(process).or_insert(next_index);
    }

    for process in processes {
        let Some(flow) = flows.get(&process) else {
            continue;
        };
        let process_index = process_to_index[&process];

        if let (true, Some(tool_hash)) = (flow.has_exec, &flow.tool_hash) {
            ops.push(CanonicalOp {
                op_type: OpType::Exec,
                process_index,
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
                    process_index,
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
                    process_index,
                    tool_hash: flow.tool_hash.clone(),
                    args: vec![],
                    input_hashes: vec![],
                    output_hashes: vec![write_hash],
                });
            }
        }

        for rename_hash in sorted_hashes(&flow.renames) {
            if relevant_hashes.contains(&rename_hash) || output_hashes.contains(&rename_hash) {
                output_hashes.remove(&rename_hash);
                ops.push(CanonicalOp {
                    op_type: OpType::FileRename,
                    process_index,
                    tool_hash: flow.tool_hash.clone(),
                    args: vec![],
                    input_hashes: vec![rename_hash.clone()],
                    output_hashes: vec![rename_hash],
                });
            }
        }
    }

    for orphan_hash in sorted_hashes(&output_hashes) {
        // The BFS did not reach a writer for this hash.  Fall back to an
        // exhaustive scan: if any process in the trace wrote or renamed
        // this content, attribute the output to that process.
        let mut attributed = false;
        if let Some(writers) = writers_by_hash.get(&orphan_hash) {
            for writer in writers {
                if let Some(flow) = flows.get(writer) {
                    if flow.writes.contains(&orphan_hash)
                        || flow.renames.contains(&orphan_hash)
                    {
                        let process_index = process_to_index
                            .entry(*writer)
                            .or_insert_with(|| {
                                let idx = next_index;
                                next_index += 1;
                                idx
                            });
                        ops.push(CanonicalOp {
                            op_type: OpType::FileWrite,
                            process_index: *process_index,
                            tool_hash: flow.tool_hash.clone(),
                            args: vec![],
                            input_hashes: vec![],
                            output_hashes: vec![orphan_hash.clone()],
                        });
                        attributed = true;
                        break;
                    }
                }
            }
        }
        if !attributed {
            ops.push(CanonicalOp {
                op_type: OpType::FileWrite,
                process_index: u32::MAX,
                tool_hash: None,
                args: vec!["output".to_string()],
                input_hashes: vec![],
                output_hashes: vec![orphan_hash],
            });
        }
    }

    if let Some((process, exit_code)) = root_exit {
        ops.push(CanonicalOp {
            op_type: OpType::Exit,
            process_index: process_to_index[&process],
            tool_hash: flows.get(&process).and_then(|flow| flow.tool_hash.clone()),
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

fn rewrite_path_prefix(path: &str, from_path: &str, to_path: &str) -> Option<String> {
    if path == from_path {
        return Some(to_path.to_string());
    }
    let suffix = path.strip_prefix(from_path)?;
    suffix
        .starts_with('/')
        .then(|| format!("{to_path}{suffix}"))
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
                process: ProcessInstance::test(10),
                observation: observe_path(&tool.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                process: ProcessInstance::test(10),
                path: input.to_string_lossy().to_string(),
                flags: 0,
                fd: 3,
                external: false,
                observation: observe_path(&input.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                process: ProcessInstance::test(10),
                path: output.to_string_lossy().to_string(),
                flags: 1,
                fd: 4,
                external: false,
                observation: observe_path(&output.to_string_lossy()),
            },
            TracedEvent::FileClose {
                process: ProcessInstance::test(10),
                fd: 4,
                path: Some(output.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&output.to_string_lossy())),
            },
            TracedEvent::FileOpen {
                process: ProcessInstance::test(11),
                path: unrelated.to_string_lossy().to_string(),
                flags: 1,
                fd: 5,
                external: false,
                observation: observe_path(&unrelated.to_string_lossy()),
            },
            TracedEvent::FileClose {
                process: ProcessInstance::test(11),
                fd: 5,
                path: Some(unrelated.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&unrelated.to_string_lossy())),
            },
            TracedEvent::Exit {
                process: ProcessInstance::test(10),
                exit_code: 0,
            },
        ];

        let ops = canonicalize_output_slice(
            events,
            ProcessInstance::test(10),
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
                process: ProcessInstance::test(10),
                observation: observe_path(&tool.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                process: ProcessInstance::test(10),
                path: input.to_string_lossy().to_string(),
                flags: 0,
                fd: 3,
                external: false,
                observation: observe_path(&input.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                process: ProcessInstance::test(10),
                path: output.to_string_lossy().to_string(),
                flags: 1,
                fd: 4,
                external: false,
                observation: observe_path(&output.to_string_lossy()),
            },
            TracedEvent::FileClose {
                process: ProcessInstance::test(10),
                fd: 4,
                path: Some(output.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&output.to_string_lossy())),
            },
            TracedEvent::Exec {
                process: ProcessInstance::test(20),
                observation: observe_path(&tool.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                process: ProcessInstance::test(20),
                path: volatile.to_string_lossy().to_string(),
                flags: 0,
                fd: 5,
                external: false,
                observation: observe_path(&volatile.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                process: ProcessInstance::test(20),
                path: cache.to_string_lossy().to_string(),
                flags: 1,
                fd: 6,
                external: false,
                observation: observe_path(&cache.to_string_lossy()),
            },
            TracedEvent::FileClose {
                process: ProcessInstance::test(20),
                fd: 6,
                path: Some(cache.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&cache.to_string_lossy())),
            },
        ];

        let ops = canonicalize_output_slice(
            events,
            ProcessInstance::test(10),
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
        let child_tool_hash = hash_file_contents(&child_tool).unwrap();
        let events = vec![
            TracedEvent::Exec {
                process: ProcessInstance::test(10),
                observation: observe_path(&root_tool.to_string_lossy()),
            },
            TracedEvent::Exec {
                process: ProcessInstance::test(11),
                observation: observe_path(&child_tool.to_string_lossy()),
            },
            TracedEvent::FileOpen {
                process: ProcessInstance::test(11),
                path: output.to_string_lossy().to_string(),
                flags: 1,
                fd: 4,
                external: false,
                observation: observe_path(&output.to_string_lossy()),
            },
            TracedEvent::FileClose {
                process: ProcessInstance::test(11),
                fd: 4,
                path: Some(output.to_string_lossy().to_string()),
                external: false,
                observation: Some(observe_path(&output.to_string_lossy())),
            },
        ];

        let ops = canonicalize_output_slice(
            events,
            ProcessInstance::test(10),
            &[OutputFile {
                path: output.to_string_lossy().to_string(),
                hash: output_hash,
            }],
        )
        .unwrap();

        assert!(ops.iter().any(|op| {
            op.op_type == OpType::Exec && op.tool_hash.as_ref() == Some(&child_tool_hash)
        }));
        assert!(ops.iter().any(|op| {
            op.op_type == OpType::FileWrite
                && op.tool_hash.as_ref() == Some(&child_tool_hash)
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
                    process: ProcessInstance::test(10),
                    observation: observe_path(&tool.to_string_lossy()),
                },
                TracedEvent::FileOpen {
                    process: ProcessInstance::test(10),
                    path: output.to_string_lossy().into_owned(),
                    flags: 0,
                    fd: 3,
                    external: false,
                    observation: observe_path(&output.to_string_lossy()),
                },
                TracedEvent::FileClose {
                    process: ProcessInstance::test(10),
                    fd: 3,
                    path: Some(output.to_string_lossy().into_owned()),
                    external: false,
                    observation: Some(observe_path(&output.to_string_lossy())),
                },
            ],
            ProcessInstance::test(10),
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
                    process: ProcessInstance::test(10),
                    observation: observe_path(&tool.to_string_lossy()),
                },
                TracedEvent::FileOpen {
                    process: ProcessInstance::test(10),
                    path: "/tmp/cc-random.s".to_string(),
                    flags: 0,
                    fd: 3,
                    external: false,
                    observation: unavailable.clone(),
                },
                TracedEvent::FileOpen {
                    process: ProcessInstance::test(10),
                    path: output.to_string_lossy().into_owned(),
                    flags: 1,
                    fd: 4,
                    external: false,
                    observation: unavailable,
                },
                TracedEvent::FileClose {
                    process: ProcessInstance::test(10),
                    fd: 4,
                    path: Some(output.to_string_lossy().into_owned()),
                    external: false,
                    observation: Some(observe_path(&output.to_string_lossy())),
                },
            ],
            ProcessInstance::test(10),
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

    #[test]
    fn rename_propagates_writer_to_final_output_path() {
        let dir = unique_dir("rename-output");
        fs::create_dir_all(&dir).unwrap();
        let writer_tool = dir.join("writer-tool");
        let renamer_tool = dir.join("renamer-tool");
        let temporary = dir.join("artifact.tmp");
        let output = dir.join("artifact");
        fs::write(&writer_tool, b"writer").unwrap();
        fs::write(&renamer_tool, b"renamer").unwrap();
        fs::write(&output, b"artifact").unwrap();
        let output_hash = hash_file_contents(&output).unwrap();
        let writer_tool_hash = hash_file_contents(&writer_tool).unwrap();
        let renamer_tool_hash = hash_file_contents(&renamer_tool).unwrap();
        let content = FileObservation::Content(output_hash.clone());

        let ops = canonicalize_output_slice(
            vec![
                TracedEvent::Exec {
                    process: ProcessInstance::test(10),
                    observation: observe_path(&writer_tool.to_string_lossy()),
                },
                TracedEvent::FileOpen {
                    process: ProcessInstance::test(10),
                    path: temporary.to_string_lossy().into_owned(),
                    flags: 1,
                    fd: 3,
                    external: false,
                    observation: content.clone(),
                },
                TracedEvent::FileClose {
                    process: ProcessInstance::test(10),
                    fd: 3,
                    path: Some(temporary.to_string_lossy().into_owned()),
                    external: false,
                    observation: Some(content.clone()),
                },
                TracedEvent::Exec {
                    process: ProcessInstance::test(11),
                    observation: observe_path(&renamer_tool.to_string_lossy()),
                },
                TracedEvent::FileRename {
                    process: ProcessInstance::test(11),
                    from_path: temporary.to_string_lossy().into_owned(),
                    to_path: output.to_string_lossy().into_owned(),
                    flags: 0,
                    external: false,
                    observation: content,
                },
            ],
            ProcessInstance::test(10),
            &[OutputFile {
                path: output.to_string_lossy().into_owned(),
                hash: output_hash.clone(),
            }],
        )
        .unwrap();

        assert!(ops.iter().any(|op| {
            op.op_type == OpType::FileWrite
                && op.tool_hash.as_ref() == Some(&writer_tool_hash)
                && op.output_hashes == vec![output_hash.clone()]
        }));
        assert!(ops.iter().any(|op| {
            op.op_type == OpType::FileRename
                && op.tool_hash.as_ref() == Some(&renamer_tool_hash)
                && op.output_hashes == vec![output_hash.clone()]
        }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_attribution_survives_reordered_events() {
        // Parallel builds can deliver rename events before the close events
        // for writes to the old path (per-CPU ring-buffer submissions are
        // not globally ordered).  The post-scan fixup must still attribute
        // the write to the final output path.
        let dir = unique_dir("rename-reorder");
        fs::create_dir_all(&dir).unwrap();
        let writer_tool = dir.join("writer");
        let renamer_tool = dir.join("renamer");
        let output = dir.join("output");
        let temp = dir.join("output.tmp");

        fs::write(&writer_tool, b"writer").unwrap();
        fs::write(&renamer_tool, b"renamer").unwrap();
        fs::write(&output, b"content").unwrap();
        let output_hash = hash_file_contents(&output).unwrap();
        let writer_tool_hash = hash_file_contents(&writer_tool).unwrap();
        let content = FileObservation::Content(output_hash.clone());

        let writer = ProcessInstance::test(10);
        let renamer = ProcessInstance::test(11);

        // Simulate the reordered case: rename arrives BEFORE the close
        // that records the writer in writers_by_path.
        let ops = canonicalize_output_slice(
            vec![
                TracedEvent::Exec {
                    process: writer,
                    observation: observe_path(&writer_tool.to_string_lossy()),
                },
                TracedEvent::Exec {
                    process: renamer,
                    observation: observe_path(&renamer_tool.to_string_lossy()),
                },
                // Rename fires first (e.g., from a different CPU).
                TracedEvent::FileRename {
                    process: renamer,
                    from_path: temp.to_string_lossy().into_owned(),
                    to_path: output.to_string_lossy().into_owned(),
                    flags: 0,
                    external: false,
                    observation: content.clone(),
                },
                // Close arrives later.
                TracedEvent::FileOpen {
                    process: writer,
                    path: temp.to_string_lossy().into_owned(),
                    flags: 1,
                    fd: 3,
                    external: false,
                    observation: content.clone(),
                },
                TracedEvent::FileClose {
                    process: writer,
                    fd: 3,
                    path: Some(temp.to_string_lossy().into_owned()),
                    external: false,
                    observation: Some(content),
                },
            ],
            writer,
            &[OutputFile {
                path: output.to_string_lossy().into_owned(),
                hash: output_hash.clone(),
            }],
        )
        .unwrap();

        // No orphan sentinel.
        for op in &ops {
            assert_ne!(
                op.process_index, u32::MAX,
                "orphan op {:?} after reordered rename",
                op.op_type
            );
        }

        // The original writer must still be attributed.
        assert!(ops.iter().any(|op| {
            op.op_type == OpType::FileWrite
                && op.tool_hash.as_ref() == Some(&writer_tool_hash)
                && op.output_hashes == vec![output_hash.clone()]
        }));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writable_fd_keeps_its_opening_exec_instance_across_reexec() {
        let dir = unique_dir("reexec-writer");
        fs::create_dir_all(&dir).unwrap();
        let initial_tool = dir.join("initial-tool");
        let reexec_tool = dir.join("reexec-tool");
        let output = dir.join("output.txt");
        fs::write(&initial_tool, b"initial").unwrap();
        fs::write(&reexec_tool, b"reexec").unwrap();
        fs::write(&output, b"output").unwrap();

        let initial = ProcessInstance::test(10);
        let reexec = ProcessInstance::test_epoch(10, 1);
        let initial_tool_hash = hash_file_contents(&initial_tool).unwrap();
        let reexec_tool_hash = hash_file_contents(&reexec_tool).unwrap();
        let output_hash = hash_file_contents(&output).unwrap();
        let output_path = output.to_string_lossy().into_owned();

        let ops = canonicalize_output_slice(
            vec![
                TracedEvent::Exec {
                    process: initial,
                    observation: observe_path(&initial_tool.to_string_lossy()),
                },
                TracedEvent::FileOpen {
                    process: initial,
                    path: output_path.clone(),
                    flags: 1,
                    fd: 3,
                    external: false,
                    observation: observe_path(&output.to_string_lossy()),
                },
                TracedEvent::Exec {
                    process: reexec,
                    observation: observe_path(&reexec_tool.to_string_lossy()),
                },
                TracedEvent::FileClose {
                    process: reexec,
                    fd: 3,
                    path: Some(output_path.clone()),
                    external: false,
                    observation: Some(observe_path(&output.to_string_lossy())),
                },
            ],
            initial,
            &[OutputFile {
                path: output_path,
                hash: output_hash.clone(),
            }],
        )
        .unwrap();

        assert!(ops.iter().any(|op| {
            op.op_type == OpType::FileWrite
                && op.tool_hash.as_ref() == Some(&initial_tool_hash)
                && op.output_hashes == [output_hash.clone()]
        }));
        assert!(!ops.iter().any(|op| {
            op.op_type == OpType::FileWrite && op.tool_hash.as_ref() == Some(&reexec_tool_hash)
        }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn forked_writer_inherits_parent_tool_without_a_synthetic_exec() {
        let dir = unique_dir("fork-inheritance");
        fs::create_dir_all(&dir).unwrap();
        let tool = dir.join("tool");
        let output = dir.join("output.txt");
        fs::write(&tool, b"tool").unwrap();
        fs::write(&output, b"output").unwrap();

        let parent = ProcessInstance::test(10);
        let child = ProcessInstance::test(11);
        let tool_hash = hash_file_contents(&tool).unwrap();
        let output_hash = hash_file_contents(&output).unwrap();
        let output_path = output.to_string_lossy().into_owned();

        let ops = canonicalize_output_slice(
            vec![
                TracedEvent::Exec {
                    process: parent,
                    observation: observe_path(&tool.to_string_lossy()),
                },
                TracedEvent::Fork { parent, child },
                TracedEvent::FileOpen {
                    process: child,
                    path: output_path.clone(),
                    flags: 1,
                    fd: 3,
                    external: false,
                    observation: observe_path(&output.to_string_lossy()),
                },
                TracedEvent::FileClose {
                    process: child,
                    fd: 3,
                    path: Some(output_path.clone()),
                    external: false,
                    observation: Some(observe_path(&output.to_string_lossy())),
                },
            ],
            parent,
            &[OutputFile {
                path: output_path,
                hash: output_hash.clone(),
            }],
        )
        .unwrap();

        assert!(ops.iter().any(|op| {
            op.op_type == OpType::FileWrite
                && op.tool_hash.as_ref() == Some(&tool_hash)
                && op.output_hashes == [output_hash.clone()]
        }));
        assert!(!ops.iter().any(|op| op.op_type == OpType::Exec));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inherited_writable_fd_remains_attributed_to_its_opener() {
        let dir = unique_dir("inherited-fd");
        fs::create_dir_all(&dir).unwrap();
        let parent_tool = dir.join("parent-tool");
        let child_tool = dir.join("child-tool");
        let output = dir.join("output.txt");
        fs::write(&parent_tool, b"parent").unwrap();
        fs::write(&child_tool, b"child").unwrap();
        fs::write(&output, b"output").unwrap();

        let parent = ProcessInstance::test(10);
        let child = ProcessInstance::test(11);
        let child_exec = ProcessInstance::test_epoch(11, 1);
        let parent_tool_hash = hash_file_contents(&parent_tool).unwrap();
        let child_tool_hash = hash_file_contents(&child_tool).unwrap();
        let output_hash = hash_file_contents(&output).unwrap();
        let output_path = output.to_string_lossy().into_owned();

        let ops = canonicalize_output_slice(
            vec![
                TracedEvent::Exec {
                    process: parent,
                    observation: observe_path(&parent_tool.to_string_lossy()),
                },
                TracedEvent::FileOpen {
                    process: parent,
                    path: output_path.clone(),
                    flags: 1,
                    fd: 3,
                    external: false,
                    observation: observe_path(&output.to_string_lossy()),
                },
                TracedEvent::Fork { parent, child },
                TracedEvent::Exec {
                    process: child_exec,
                    observation: observe_path(&child_tool.to_string_lossy()),
                },
                TracedEvent::FileClose {
                    process: child_exec,
                    fd: 3,
                    path: Some(output_path.clone()),
                    external: false,
                    observation: Some(observe_path(&output.to_string_lossy())),
                },
            ],
            parent,
            &[OutputFile {
                path: output_path,
                hash: output_hash.clone(),
            }],
        )
        .unwrap();

        assert!(ops.iter().any(|op| {
            op.op_type == OpType::FileWrite
                && op.tool_hash.as_ref() == Some(&parent_tool_hash)
                && op.output_hashes == [output_hash.clone()]
        }));
        assert!(!ops.iter().any(|op| {
            op.op_type == OpType::FileWrite && op.tool_hash.as_ref() == Some(&child_tool_hash)
        }));
        let _ = fs::remove_dir_all(&dir);
    }
}
