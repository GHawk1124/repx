//! eBPF tracer: loads BPF programs, spawns the traced command,
//! and collects events from the ring buffer.

use anyhow::{bail, Context, Result};
use aya::maps::{HashMap as BpfHashMap, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use log::{debug, info, warn};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use repx_common::{Event, EventKind, WatchedPrefix, MAX_PREFIX_LEN, MAX_WATCH_PREFIXES};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::file_identity::{
    is_path_within, observe_file, observe_path, open_regular, FileObservation, EMPTY_CONTENT_HASH,
};

/// AT_FDCWD sentinel: openat interprets relative paths against the cwd.
const AT_FDCWD: i32 = -100;

/// One kernel process lifetime. The generation distinguishes PID reuse within
/// a trace without making scheduler-assigned values part of the commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessLifetime {
    pub pid: u32,
    pub generation: u32,
}

/// A specific executable image within a process lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessInstance {
    pub lifetime: ProcessLifetime,
    pub exec_epoch: u32,
}

impl ProcessInstance {
    #[cfg(test)]
    pub const fn test(pid: u32) -> Self {
        Self {
            lifetime: ProcessLifetime { pid, generation: 0 },
            exec_epoch: 0,
        }
    }

    #[cfg(test)]
    pub const fn test_epoch(pid: u32, exec_epoch: u32) -> Self {
        Self {
            lifetime: ProcessLifetime { pid, generation: 0 },
            exec_epoch,
        }
    }
}

/// A high-level traced event, extracted from raw BPF events.
#[derive(Debug, Clone)]
pub enum TracedEvent {
    Exec {
        process: ProcessInstance,
        observation: FileObservation,
    },
    Fork {
        parent: ProcessInstance,
        child: ProcessInstance,
    },
    FileOpen {
        process: ProcessInstance,
        path: String,
        flags: u32,
        fd: i32,
        /// True if this event came from a non-fork-tree process matching a watched prefix.
        external: bool,
        /// File identity captured as soon as the successful open event arrived.
        observation: FileObservation,
    },
    FileClose {
        process: ProcessInstance,
        fd: i32,
        /// Resolved path (looked up from our fd tracking table).
        path: Option<String>,
        /// True if this event came from a non-fork-tree process.
        external: bool,
        /// File identity captured when the close event arrived.
        observation: Option<FileObservation>,
    },
    FileMmap {
        process: ProcessInstance,
        fd: i32,
        prot: u32,
        flags: u32,
        /// Resolved path (looked up from our fd tracking table).
        path: Option<String>,
        /// True if this event came from a non-fork-tree process.
        external: bool,
        /// File identity captured when the mapping event arrived.
        observation: Option<FileObservation>,
    },
    FileRename {
        process: ProcessInstance,
        from_path: String,
        to_path: String,
        flags: u32,
        /// True if this event came from a non-fork-tree process.
        external: bool,
        /// Identity observed at the destination after the rename completed.
        observation: FileObservation,
    },
    FileUnlink {
        process: ProcessInstance,
        path: String,
        flags: u32,
        /// True if this event came from a non-fork-tree process.
        external: bool,
        /// Best available identity for the removed path.
        observation: FileObservation,
    },
    Exit {
        process: ProcessInstance,
        exit_code: i32,
    },
}

/// Result of tracing a command.
pub struct TraceResult {
    pub events: Vec<TracedEvent>,
    /// Initial executable image of the root traced process.
    pub root_process: ProcessInstance,
    /// Number of events dropped due to ring buffer overflow (0 = lossless).
    pub dropped_events: u64,
}

/// Trace a command and return the sequence of events that occurred.
pub fn trace_command(command: &[String], watch_dirs: &[PathBuf]) -> Result<TraceResult> {
    if watch_dirs.len() > MAX_WATCH_PREFIXES {
        bail!(
            "{} watch directories requested, but the tracer supports at most {}",
            watch_dirs.len(),
            MAX_WATCH_PREFIXES
        );
    }

    let watch_prefixes: Vec<String> = watch_dirs
        .iter()
        .map(|dir| {
            std::fs::canonicalize(dir)
                .unwrap_or_else(|_| dir.clone())
                .to_string_lossy()
                .into_owned()
        })
        .collect();

    for prefix in &watch_prefixes {
        if prefix.len() > MAX_PREFIX_LEN {
            bail!(
                "watch prefix is {} bytes, but the tracer supports at most {}: {}",
                prefix.len(),
                MAX_PREFIX_LEN,
                prefix
            );
        }
    }

    let ebpf_bytes = load_ebpf()?;
    let mut bpf = Ebpf::load(&ebpf_bytes).context("Failed to load eBPF program")?;

    // Attach all tracepoints.
    attach_tracepoint(
        &mut bpf,
        "repx_openat_enter",
        "syscalls",
        "sys_enter_openat",
    )?;
    attach_tracepoint(&mut bpf, "repx_openat_exit", "syscalls", "sys_exit_openat")?;
    attach_tracepoint(
        &mut bpf,
        "repx_rename_enter",
        "syscalls",
        "sys_enter_rename",
    )?;
    attach_tracepoint(&mut bpf, "repx_rename_exit", "syscalls", "sys_exit_rename")?;
    attach_tracepoint(
        &mut bpf,
        "repx_renameat_enter",
        "syscalls",
        "sys_enter_renameat",
    )?;
    attach_tracepoint(
        &mut bpf,
        "repx_renameat_exit",
        "syscalls",
        "sys_exit_renameat",
    )?;
    attach_tracepoint(
        &mut bpf,
        "repx_renameat2_enter",
        "syscalls",
        "sys_enter_renameat2",
    )?;
    attach_tracepoint(
        &mut bpf,
        "repx_renameat2_exit",
        "syscalls",
        "sys_exit_renameat2",
    )?;
    attach_tracepoint(
        &mut bpf,
        "repx_unlink_enter",
        "syscalls",
        "sys_enter_unlink",
    )?;
    attach_tracepoint(&mut bpf, "repx_unlink_exit", "syscalls", "sys_exit_unlink")?;
    attach_tracepoint(
        &mut bpf,
        "repx_unlinkat_enter",
        "syscalls",
        "sys_enter_unlinkat",
    )?;
    attach_tracepoint(
        &mut bpf,
        "repx_unlinkat_exit",
        "syscalls",
        "sys_exit_unlinkat",
    )?;
    attach_tracepoint(&mut bpf, "repx_close_enter", "syscalls", "sys_enter_close")?;
    attach_tracepoint(&mut bpf, "repx_mmap_enter", "syscalls", "sys_enter_mmap")?;
    attach_tracepoint(&mut bpf, "repx_exec", "sched", "sched_process_exec")?;
    attach_tracepoint(&mut bpf, "repx_fork", "sched", "sched_process_fork")?;
    attach_tracepoint(&mut bpf, "repx_exit", "sched", "sched_process_exit")?;
    // Reliably track child PIDs from the clone syscall return value.
    // sched_process_fork's tracepoint data offset for child_pid varies across
    // kernel builds; syscall exit tracepoints are arch-stable kernel ABI.
    // Attach best-effort: hardened kernels may disable syscall tracepoints,
    // in which case we fall back to sched_process_fork-based tracking.
    if let Err(e) =
        attach_tracepoint(&mut bpf, "repx_clone_exit", "syscalls", "sys_exit_clone")
    {
        warn!("sys_exit_clone not available: {e}");
    }
    // clone3 (Linux 5.3+) may not exist on older kernels.
    if let Err(e) =
        attach_tracepoint(&mut bpf, "repx_clone3_exit", "syscalls", "sys_exit_clone3")
    {
        warn!("sys_exit_clone3 not available (expected on older kernels): {e}");
    }

    // Populate watch-mode maps before spawning so sibling writes cannot race
    // the userspace arm step.
    if !watch_dirs.is_empty() {
        let mut watch_mode: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(bpf.map_mut("WATCH_MODE").unwrap())?;
        watch_mode.insert(0u32, 1u8, 0)?;

        let mut watched_prefixes: BpfHashMap<_, u32, WatchedPrefix> =
            BpfHashMap::try_from(bpf.map_mut("WATCHED_PREFIXES").unwrap())?;

        for (i, path_str) in watch_prefixes.iter().enumerate() {
            let path_bytes = path_str.as_bytes();

            let mut prefix = WatchedPrefix {
                prefix: [0u8; MAX_PREFIX_LEN],
                len: 0,
            };
            let copy_len = path_bytes.len();
            prefix.prefix[..copy_len].copy_from_slice(&path_bytes[..copy_len]);
            prefix.len = copy_len as u32;

            watched_prefixes.insert(i as u32, prefix, 0)?;
            info!("Watching prefix: {}", path_str);
        }
    }

    let root_binary = resolve_executable(&command[0]);
    let root_observation = observe_path(&root_binary);
    let root_cwd = std::env::current_dir().context("Failed to resolve trace working directory")?;
    let child_pid = spawn_suspended(command)?;
    info!("Tracing PID {} ({})", child_pid, command[0]);

    // Register the child PID for tracking in the BPF maps.
    {
        let mut root_pid: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(bpf.map_mut("ROOT_PID").unwrap())?;
        root_pid.insert(child_pid, 1u8, 0)?;

        let mut tracked: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(bpf.map_mut("TRACKED_PIDS").unwrap())?;
        tracked.insert(child_pid, 1u8, 0)?;
    }

    kill(Pid::from_raw(child_pid as i32), Signal::SIGCONT)
        .with_context(|| format!("Failed to resume traced child {}", child_pid))?;

    // Consume events from the ring buffer until the child exits.
    let mut events = Vec::new();
    let ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    // Track fd -> path mapping per process for resolving closes.
    let mut collector_state = EventCollectorState::new(child_pid, root_cwd);
    let root_process = collector_state.root_process;

    collect_events(
        ring_buf,
        child_pid,
        &mut events,
        &mut collector_state,
        &watch_prefixes,
    )?;

    // Use a single userspace-authored initial root Exec op. The first BPF root
    // exec is consumed by EventCollectorState, while later exec replacements
    // advance the epoch and remain visible.
    events.insert(
        0,
        TracedEvent::Exec {
            process: root_process,
            observation: root_observation,
        },
    );

    // Check for dropped events (ring buffer was full).
    let dropped_events = {
        let drop_count: BpfHashMap<_, u32, u64> =
            BpfHashMap::try_from(bpf.map_mut("DROP_COUNT").unwrap())?;
        drop_count
            .get(&0u32, 0)
            .unwrap_or(0)
            .saturating_add(collector_state.malformed_events)
    };

    if dropped_events > 0 {
        warn!("{} events were dropped (ring buffer full)", dropped_events);
    }

    info!("Collected {} events", events.len());
    Ok(TraceResult {
        events,
        root_process,
        dropped_events,
    })
}

fn attach_tracepoint(bpf: &mut Ebpf, prog_name: &str, category: &str, name: &str) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(prog_name)
        .unwrap()
        .try_into()
        .context("Program is not a TracePoint")?;
    prog.load()
        .with_context(|| format!("Failed to load {}", prog_name))?;
    prog.attach(category, name)
        .with_context(|| format!("Failed to attach {} to {}/{}", prog_name, category, name))?;
    info!("Attached {}/{}", category, name);
    Ok(())
}

fn spawn_suspended(command: &[String]) -> Result<u32> {
    let argv: Vec<CString> = command
        .iter()
        .map(|arg| CString::new(arg.as_str()))
        .collect::<std::result::Result<_, _>>()
        .context("Command contains an interior NUL byte")?;

    let child = match unsafe { fork() }.context("Failed to fork traced child")? {
        ForkResult::Child => {
            let _ = kill(Pid::this(), Signal::SIGSTOP);
            let _ = execvp(&argv[0], &argv);
            unsafe { nix::libc::_exit(127) };
        }
        ForkResult::Parent { child } => child,
    };

    loop {
        match waitpid(child, Some(WaitPidFlag::WUNTRACED))
            .with_context(|| format!("Failed waiting for traced child {}", child))?
        {
            WaitStatus::Stopped(_, Signal::SIGSTOP) => return Ok(child.as_raw() as u32),
            WaitStatus::Exited(_, code) => {
                anyhow::bail!("Traced child exited before exec with status {}", code);
            }
            WaitStatus::Signaled(_, signal, _) => {
                anyhow::bail!("Traced child died before exec from signal {}", signal);
            }
            _ => {}
        }
    }
}

fn resolve_executable(command: &str) -> String {
    if command.contains('/') {
        return std::fs::canonicalize(command)
            .unwrap_or_else(|_| PathBuf::from(command))
            .to_string_lossy()
            .into_owned();
    }

    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(command);
            if candidate.is_file() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }

    command.to_string()
}

fn process_event(
    event: &Event,
    events: &mut Vec<TracedEvent>,
    state: &mut EventCollectorState,
    watch_prefixes: &[String],
) -> bool {
    let Ok(kind) = EventKind::try_from(event.kind) else {
        warn!("Ignoring event with unknown kind {}", event.kind);
        return false;
    };

    match kind {
        EventKind::FileOpen => {
            let payload = unsafe { &event.payload.file_open };
            let external = event.source == 1;
            let process_id = payload.tgid;
            let process = state.current_process(process_id);
            let path_len = (payload.path_len as usize).min(payload.path.len());
            let raw_path = std::str::from_utf8(&payload.path[..path_len])
                .unwrap_or("<invalid utf8>")
                .trim_end_matches('\0')
                .to_string();

            let raw_resolved = state.resolve_path(process, payload.dfd, &raw_path);
            let proc_fd_path = format!("/proc/{}/fd/{}", payload.tgid, payload.fd);
            let proc_target = std::fs::read_link(&proc_fd_path)
                .ok()
                .map(|path| strip_deleted_suffix(path.to_string_lossy().into_owned()));
            let use_proc_target = proc_target
                .as_deref()
                .is_some_and(|target| paths_agree(&raw_resolved, target));
            let path = if use_proc_target {
                proc_target.unwrap()
            } else {
                raw_resolved
            };

            if external
                && !watch_prefixes
                    .iter()
                    .any(|prefix| is_path_within(&path, prefix))
            {
                return true;
            }

            // Only open a proc-fd magic link after watch filtering and a
            // regular-file metadata check. This retains unlinked files without
            // allowing FIFOs or devices to block the event loop.
            let handle_path = if use_proc_target {
                &proc_fd_path
            } else {
                &path
            };
            let handle = open_regular(handle_path).ok().flatten();
            // O_TRUNC destroys the previous contents at open, so the pre-image
            // is empty by definition. Observing the path instead would race
            // with the process already writing through the new descriptor.
            let truncated = payload.fd >= 0 && payload.flags & nix::libc::O_TRUNC as u32 != 0;
            let mut open_state = OpenFileState {
                path,
                handle,
                flags: payload.flags,
                open_observation: truncated
                    .then(|| FileObservation::Content(EMPTY_CONTENT_HASH.to_string())),
            };
            let observation = open_state.open_observation();
            let event_path = open_state.path.clone();

            debug!(
                "FileOpen pid={} tgid={} fd={} dfd={} path={} flags={:#x} external={} observation={}",
                payload.pid,
                process_id,
                payload.fd,
                payload.dfd,
                open_state.path,
                payload.flags,
                external,
                observation.identity()
            );

            // Track this fd for later close resolution.
            if payload.fd >= 0 {
                state
                    .fd_table
                    .insert((process.lifetime, payload.fd), open_state);
            }

            events.push(TracedEvent::FileOpen {
                process,
                path: event_path,
                flags: payload.flags,
                fd: payload.fd,
                external,
                observation,
            });
        }
        EventKind::FileClose => {
            let payload = unsafe { &event.payload.file_close };
            let external = event.source == 1;
            let process_id = payload.tgid;
            let process = state.current_process(process_id);
            let mut open_state = state.fd_table.remove(&(process.lifetime, payload.fd));
            if external && open_state.is_none() {
                return true;
            }
            let observation = open_state
                .as_mut()
                .and_then(OpenFileState::close_observation);
            let path = open_state.map(|state| state.path);

            debug!(
                "FileClose pid={} tgid={} fd={} path={:?} external={} observation={:?}",
                payload.pid,
                process_id,
                payload.fd,
                path,
                external,
                observation.as_ref().map(FileObservation::identity)
            );

            events.push(TracedEvent::FileClose {
                process,
                fd: payload.fd,
                path,
                external,
                observation,
            });
        }
        EventKind::FileMmap => {
            let payload = unsafe { &event.payload.file_mmap };
            let external = event.source == 1;
            let process_id = payload.tgid;
            let process = state.current_process(process_id);

            let (path, observation) = match state.fd_table.get_mut(&(process.lifetime, payload.fd))
            {
                Some(state) => (Some(state.path.clone()), Some(state.mmap_observation())),
                None if external => return true,
                None => (None, None),
            };

            debug!(
                "FileMmap pid={} tgid={} fd={} prot={:#x} flags={:#x} path={:?} external={} observation={:?}",
                payload.pid,
                process_id,
                payload.fd,
                payload.prot,
                payload.flags,
                path,
                external,
                observation.as_ref().map(FileObservation::identity)
            );

            events.push(TracedEvent::FileMmap {
                process,
                fd: payload.fd,
                prot: payload.prot,
                flags: payload.flags,
                path,
                external,
                observation,
            });
        }
        EventKind::FileRenameSource => {
            let payload = unsafe { &event.payload.file_path };
            let process_id = payload.tgid;
            let process = state.current_process(process_id);
            let Some(raw_path) = decode_event_path(&payload.path, payload.path_len) else {
                return false;
            };
            let path = state.resolve_path(process, payload.dfd, &raw_path);
            state.pending_renames.insert(
                (payload.pid, payload.operation_id),
                PendingRename {
                    process,
                    from_path: path,
                    flags: payload.flags,
                    external: event.source == 1,
                },
            );
        }
        EventKind::FileRenameDestination => {
            let payload = unsafe { &event.payload.file_path };
            let process_id = payload.tgid;
            let Some(pending) = state
                .pending_renames
                .remove(&(payload.pid, payload.operation_id))
            else {
                warn!(
                    "Rename destination without source pid={} operation={}",
                    payload.pid, payload.operation_id
                );
                return false;
            };
            let Some(raw_path) = decode_event_path(&payload.path, payload.path_len) else {
                return false;
            };
            let to_path = state.resolve_path(pending.process, payload.dfd, &raw_path);
            let external = pending.external || event.source == 1;
            if external
                && !watch_prefixes.iter().any(|prefix| {
                    is_path_within(&pending.from_path, prefix) || is_path_within(&to_path, prefix)
                })
            {
                return true;
            }

            rewrite_open_file_paths(
                &mut state.fd_table,
                &pending.from_path,
                &to_path,
                pending.flags,
            );
            let observation = observe_path(&to_path);
            let reverse_observation =
                (pending.flags & RENAME_EXCHANGE != 0).then(|| observe_path(&pending.from_path));
            debug!(
                "FileRename pid={} from={} to={} flags={:#x} external={}",
                process_id, pending.from_path, to_path, pending.flags, external
            );
            events.push(TracedEvent::FileRename {
                process: pending.process,
                from_path: pending.from_path.clone(),
                to_path: to_path.clone(),
                flags: pending.flags,
                external,
                observation,
            });
            if let Some(observation) = reverse_observation {
                events.push(TracedEvent::FileRename {
                    process: pending.process,
                    from_path: to_path,
                    to_path: pending.from_path,
                    flags: pending.flags,
                    external,
                    observation,
                });
            }
        }
        EventKind::FileUnlink => {
            let payload = unsafe { &event.payload.file_path };
            let process_id = payload.tgid;
            let process = state.current_process(process_id);
            let Some(raw_path) = decode_event_path(&payload.path, payload.path_len) else {
                return false;
            };
            let path = state.resolve_path(process, payload.dfd, &raw_path);
            let external = event.source == 1;
            if external
                && !watch_prefixes
                    .iter()
                    .any(|prefix| is_path_within(&path, prefix))
            {
                return true;
            }
            let observation = state
                .fd_table
                .values_mut()
                .find(|state| state.path == path)
                .map(OpenFileState::observe_current)
                .unwrap_or_else(|| observe_path(&path));
            debug!(
                "FileUnlink pid={} path={} flags={:#x} external={}",
                process_id, path, payload.flags, external
            );
            events.push(TracedEvent::FileUnlink {
                process,
                path,
                flags: payload.flags,
                external,
                observation,
            });
        }
        EventKind::ProcessExec => {
            let payload = unsafe { &event.payload.process_exec };
            let process_id = payload.tgid;
            let Some(process) = state.exec_process(process_id) else {
                return true;
            };
            let name_len = (payload.filename_len as usize).min(payload.filename.len());
            let raw_filename = std::str::from_utf8(&payload.filename[..name_len])
                .unwrap_or("<invalid utf8>")
                .trim_end_matches('\0')
                .to_string();
            let raw_filename = state.resolve_path(process, AT_FDCWD, &raw_filename);
            let proc_exe = format!("/proc/{}/exe", payload.tgid);
            let proc_target = std::fs::read_link(&proc_exe)
                .ok()
                .map(|path| strip_deleted_suffix(path.to_string_lossy().into_owned()));
            let use_proc_target = proc_target
                .as_deref()
                .is_some_and(|target| paths_agree(&raw_filename, target));
            let filename = if use_proc_target {
                proc_target.unwrap()
            } else {
                raw_filename
            };
            let executable_path = if use_proc_target {
                &proc_exe
            } else {
                &filename
            };
            let mut executable = open_regular(executable_path).ok().flatten();
            let observation = executable
                .as_mut()
                .map(|file| observe_file(file, &filename))
                .unwrap_or_else(|| observe_path(&filename));

            debug!(
                "Exec pid={} tgid={} file={}",
                payload.pid, process_id, filename
            );

            events.push(TracedEvent::Exec {
                process,
                observation,
            });
        }
        EventKind::ProcessFork => {
            let payload = unsafe { &event.payload.process_fork };
            let (parent, child) = state.fork_process(payload.parent_pid, payload.child_pid);
            debug!(
                "Fork parent={} generation={} epoch={} child={} generation={}",
                parent.lifetime.pid,
                parent.lifetime.generation,
                parent.exec_epoch,
                child.lifetime.pid,
                child.lifetime.generation
            );
            events.push(TracedEvent::Fork { parent, child });
        }
        EventKind::ProcessExit => {
            let payload = unsafe { &event.payload.process_exit };
            let process_id = payload.tgid;
            // Don't remove from current_processes during event processing.
            // With deferred (timestamp-sorted) processing, FileClose events
            // for short-lived processes like dd can sort after ProcessExit.
            // Removing the process would cause current_process() to create
            // a new ProcessInstance with a different generation, breaking
            // the fd_table lookup and losing write attribution.
            // PID reuse is still handled correctly: fork_process calls
            // start_process which overwrites current_processes entries.
            let process = state.current_process(process_id);
            debug!(
                "Exit pid={} tgid={} code={}",
                payload.pid, process_id, payload.exit_code
            );

            events.push(TracedEvent::Exit {
                process,
                exit_code: payload.exit_code,
            });
        }
    }

    true
}

fn drain_ring_into_buffer(
    ring_buf: &mut RingBuf<&mut aya::maps::MapData>,
    raw_events: &mut Vec<(u64, Vec<u8>)>,
    malformed: &mut u64,
) {
    while let Some(item) = ring_buf.next() {
        let data = item.as_ref();
        if data.len() < std::mem::size_of::<Event>() {
            warn!("Short event: {} bytes", data.len());
            *malformed = malformed.saturating_add(1);
            continue;
        }
        // timestamp_ns is at offset 8 in the repr(C) Event struct.
        let ts = u64::from_ne_bytes(<[u8; 8]>::try_from(&data[8..16]).unwrap());
        raw_events.push((ts, data.to_vec()));
    }
}

fn process_buffered_events(
    raw_events: &[(u64, Vec<u8>)],
    events: &mut Vec<TracedEvent>,
    state: &mut EventCollectorState,
    watch_prefixes: &[String],
) {
    for (_, data) in raw_events {
        if data.len() < std::mem::size_of::<Event>() {
            state.malformed_events = state.malformed_events.saturating_add(1);
            continue;
        }
        let event = unsafe { (data.as_ptr() as *const Event).read_unaligned() };
        if !process_event(&event, events, state, watch_prefixes) {
            state.malformed_events = state.malformed_events.saturating_add(1);
        }
    }
}

fn collect_events(
    mut ring_buf: RingBuf<&mut aya::maps::MapData>,
    child_pid: u32,
    events: &mut Vec<TracedEvent>,
    state: &mut EventCollectorState,
    watch_prefixes: &[String],
) -> Result<()> {
    // Buffer events with their timestamps instead of processing immediately.
    // Per-CPU ring buffers are drained in non-deterministic order, which can
    // cause a FileClose from one CPU to be processed before its matching
    // FileOpen from another CPU.  Sorting by bpf_ktime_get_ns() timestamp
    // restores the global syscall order and makes the trace deterministic.
    let mut raw_events: Vec<(u64, Vec<u8>)> = Vec::new();

    loop {
        drain_ring_into_buffer(&mut ring_buf, &mut raw_events, &mut state.malformed_events);

        match waitpid(Pid::from_raw(child_pid as i32), Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::Exited(_, real_exit_code) => {
                info!("Child exited with status {}", real_exit_code);
                finish_with_sort(
                    &mut ring_buf,
                    child_pid,
                    real_exit_code,
                    &mut raw_events,
                    events,
                    state,
                    watch_prefixes,
                )?;
                break;
            }
            WaitStatus::Signaled(_, signal, _) => {
                let real_exit_code = 128 + signal as i32;
                info!("Child exited from signal {}", signal);
                finish_with_sort(
                    &mut ring_buf,
                    child_pid,
                    real_exit_code,
                    &mut raw_events,
                    events,
                    state,
                    watch_prefixes,
                )?;
                break;
            }
            WaitStatus::StillAlive => {
                wait_for_ring_event(&ring_buf, 10)?;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Quiescence drain → timestamp sort → process → synthesize exit.
fn finish_with_sort(
    ring_buf: &mut RingBuf<&mut aya::maps::MapData>,
    child_pid: u32,
    real_exit_code: i32,
    raw_events: &mut Vec<(u64, Vec<u8>)>,
    events: &mut Vec<TracedEvent>,
    state: &mut EventCollectorState,
    watch_prefixes: &[String],
) -> Result<()> {
    // Let late events land before we sort.
    let quiescence = std::time::Duration::from_millis(100);
    let poll_interval = std::time::Duration::from_millis(10);
    let mut deadline = std::time::Instant::now() + quiescence;
    loop {
        let before = raw_events.len();
        drain_ring_into_buffer(ring_buf, raw_events, &mut state.malformed_events);
        if raw_events.len() > before {
            deadline = std::time::Instant::now() + quiescence;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        wait_for_ring_event(ring_buf, poll_interval.as_millis() as i32)?;
    }

    // Sort by bpf_ktime_get_ns timestamp for deterministic processing.
    raw_events.sort_unstable_by_key(|(ts, _)| *ts);
    process_buffered_events(raw_events, events, state, watch_prefixes);

    // Synthesize the root exit event (BPF exit events cannot reliably
    // carry the real exit code).
    let mut found_exit = false;
    for ev in events.iter_mut().rev() {
        if let TracedEvent::Exit {
            process, exit_code, ..
        } = ev
        {
            if process.lifetime.pid == child_pid {
                *exit_code = real_exit_code;
                found_exit = true;
                break;
            }
        }
    }
    if !found_exit {
        let process = state.exit_process(child_pid);
        events.push(TracedEvent::Exit {
            process,
            exit_code: real_exit_code,
        });
    }

    if !state.pending_renames.is_empty() {
        warn!(
            "{} rename operations were missing a paired path event",
            state.pending_renames.len()
        );
        state.malformed_events = state
            .malformed_events
            .saturating_add(state.pending_renames.len() as u64);
        state.pending_renames.clear();
    }

    Ok(())
}

fn wait_for_ring_event(ring_buf: &RingBuf<&mut aya::maps::MapData>, timeout_ms: i32) -> Result<()> {
    let mut poll_fd = nix::libc::pollfd {
        fd: ring_buf.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { nix::libc::poll(&mut poll_fd, 1, timeout_ms) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("Failed polling eBPF ring buffer");
    }
    Ok(())
}

struct PendingRename {
    process: ProcessInstance,
    from_path: String,
    flags: u32,
    external: bool,
}

struct EventCollectorState {
    root_process: ProcessInstance,
    root_cwd: PathBuf,
    root_initial_exec_pending: bool,
    current_processes: HashMap<u32, ProcessInstance>,
    next_generations: HashMap<u32, u32>,
    process_cwds: HashMap<ProcessLifetime, PathBuf>,
    fd_table: HashMap<(ProcessLifetime, i32), OpenFileState>,
    pending_renames: HashMap<(u32, u64), PendingRename>,
    malformed_events: u64,
}

impl EventCollectorState {
    fn new(root_pid: u32, root_cwd: PathBuf) -> Self {
        let root_process = ProcessInstance {
            lifetime: ProcessLifetime {
                pid: root_pid,
                generation: 0,
            },
            exec_epoch: 0,
        };
        let cwd_for_table = root_cwd.clone();
        Self {
            root_process,
            root_cwd,
            root_initial_exec_pending: true,
            current_processes: HashMap::from([(root_pid, root_process)]),
            next_generations: HashMap::from([(root_pid, 1)]),
            process_cwds: HashMap::from([(root_process.lifetime, cwd_for_table)]),
            fd_table: HashMap::new(),
            pending_renames: HashMap::new(),
            malformed_events: 0,
        }
    }

    fn current_process(&mut self, pid: u32) -> ProcessInstance {
        if let Some(process) = self.current_processes.get(&pid) {
            return *process;
        }
        self.start_process(pid)
    }

    fn start_process(&mut self, pid: u32) -> ProcessInstance {
        let generation = self.next_generations.entry(pid).or_insert(0);
        let process = ProcessInstance {
            lifetime: ProcessLifetime {
                pid,
                generation: *generation,
            },
            exec_epoch: 0,
        };
        *generation = generation.saturating_add(1);
        self.current_processes.insert(pid, process);
        process
    }

    fn fork_process(
        &mut self,
        parent_pid: u32,
        child_pid: u32,
    ) -> (ProcessInstance, ProcessInstance) {
        let parent = self.current_process(parent_pid);
        let child = self.start_process(child_pid);
        if let Some(cwd) = self.process_cwds.get(&parent.lifetime).cloned() {
            self.process_cwds.insert(child.lifetime, cwd);
        }
        let inherited_fds: Vec<(i32, OpenFileState)> = self
            .fd_table
            .iter()
            .filter(|((lifetime, _), _)| *lifetime == parent.lifetime)
            .map(|((_, fd), state)| (*fd, state.inherit()))
            .collect();
        for (fd, state) in inherited_fds {
            self.fd_table.insert((child.lifetime, fd), state);
        }
        (parent, child)
    }

    fn exec_process(&mut self, pid: u32) -> Option<ProcessInstance> {
        if pid == self.root_process.lifetime.pid && self.root_initial_exec_pending {
            self.root_initial_exec_pending = false;
            return None;
        }

        let mut process = self.current_process(pid);
        process.exec_epoch = process.exec_epoch.saturating_add(1);
        self.current_processes.insert(pid, process);
        Some(process)
    }

    fn resolve_path(&mut self, process: ProcessInstance, dfd: i32, raw_path: &str) -> String {
        if raw_path.starts_with('/') {
            return raw_path.to_string();
        }

        let proc_path = if dfd == AT_FDCWD {
            format!("/proc/{}/cwd", process.lifetime.pid)
        } else {
            format!("/proc/{}/fd/{dfd}", process.lifetime.pid)
        };
        if let Ok(base) = std::fs::read_link(proc_path) {
            if dfd == AT_FDCWD {
                self.process_cwds.insert(process.lifetime, base.clone());
            }
            return base.join(raw_path).to_string_lossy().into_owned();
        }

        if dfd == AT_FDCWD {
            if let Some(base) = self.process_cwds.get(&process.lifetime) {
                return base.join(raw_path).to_string_lossy().into_owned();
            }
        }

        // After deferred processing (timestamp sorting), /proc/{pid}/cwd may
        // no longer be readable because the process has exited.  All traced
        // processes inherit the root CWD unless they explicitly chdir, which
        // build tools do not.  Resolving against the root CWD produces an
        // absolute path that matches the workspace snapshot keys.
        if dfd == AT_FDCWD {
            return self
                .root_cwd
                .join(raw_path)
                .to_string_lossy()
                .into_owned();
        }

        raw_path.to_string()
    }

    fn exit_process(&mut self, pid: u32) -> ProcessInstance {
        let process = self.current_process(pid);
        self.current_processes.remove(&pid);
        process
    }
}

struct OpenFileState {
    path: String,
    handle: Option<File>,
    flags: u32,
    open_observation: Option<FileObservation>,
}

impl OpenFileState {
    fn inherit(&self) -> Self {
        Self {
            path: self.path.clone(),
            handle: self.handle.as_ref().and_then(|file| file.try_clone().ok()),
            flags: self.flags,
            open_observation: self.open_observation.clone(),
        }
    }

    fn observe_current(&mut self) -> FileObservation {
        self.handle
            .as_mut()
            .map(|file| observe_file(file, &self.path))
            .unwrap_or_else(|| observe_path(&self.path))
    }

    fn open_observation(&mut self) -> FileObservation {
        if let Some(observation) = &self.open_observation {
            return observation.clone();
        }
        let observation = self.observe_current();
        self.open_observation = Some(observation.clone());
        observation
    }

    fn mmap_observation(&mut self) -> FileObservation {
        self.open_observation()
    }

    fn close_observation(&mut self) -> Option<FileObservation> {
        let can_write = (self.flags & 0x3) != 0;
        can_write.then(|| self.observe_current())
    }
}

const RENAME_EXCHANGE: u32 = 1 << 1;

fn decode_event_path(path: &[u8], path_len: u32) -> Option<String> {
    let path_len = (path_len as usize).min(path.len());
    std::str::from_utf8(&path[..path_len])
        .ok()
        .map(|path| path.trim_end_matches('\0').to_string())
        .filter(|path| !path.is_empty())
}

fn rewrite_open_file_paths(
    fd_table: &mut HashMap<(ProcessLifetime, i32), OpenFileState>,
    from_path: &str,
    to_path: &str,
    flags: u32,
) {
    for state in fd_table.values_mut() {
        let original = state.path.clone();
        let replacement = rewrite_path_prefix(&original, from_path, to_path).or_else(|| {
            if flags & RENAME_EXCHANGE != 0 {
                rewrite_path_prefix(&original, to_path, from_path)
            } else {
                None
            }
        });
        if let Some(replacement) = replacement {
            state.path = replacement;
        }
    }
}

fn rewrite_path_prefix(path: &str, from_path: &str, to_path: &str) -> Option<String> {
    if path == from_path {
        return Some(to_path.to_string());
    }

    let suffix = path.strip_prefix(from_path)?;
    if !suffix.starts_with('/') {
        return None;
    }
    Some(format!("{to_path}{suffix}"))
}

fn paths_agree(raw_path: &str, proc_target: &str) -> bool {
    if raw_path == proc_target {
        return true;
    }

    if let (Ok(raw), Ok(target)) = (
        std::fs::canonicalize(raw_path),
        std::fs::canonicalize(proc_target),
    ) {
        if raw == target {
            return true;
        }
    }

    let raw_path = Path::new(raw_path);
    raw_path.is_relative() && Path::new(proc_target).ends_with(raw_path)
}

fn strip_deleted_suffix(path: String) -> String {
    path.strip_suffix(" (deleted)").unwrap_or(&path).to_string()
}

/// Load the eBPF bytecode.
///
/// When built with `REPX_EBPF_BIN` set (e.g. via nix build), the bytecode
/// is embedded directly into the binary at compile time. Otherwise, we
/// search for it on disk (development workflow).
fn load_ebpf() -> Result<Vec<u8>> {
    // If the eBPF binary was embedded at compile time, use it directly.
    if let Some(embedded) = option_env!("REPX_EBPF_BIN") {
        let data = std::fs::read(embedded)
            .with_context(|| format!("REPX_EBPF_BIN set but cannot read: {}", embedded))?;
        info!("Loaded embedded eBPF bytecode from: {}", embedded);
        return Ok(data);
    }

    // Development fallback: search for the binary on disk.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    let mut search_paths = vec![
        "repx-ebpf/target/bpfel-unknown-none/release/repx-ebpf".to_string(),
        "repx-ebpf/target/bpfel-unknown-none/debug/repx-ebpf".to_string(),
        "../repx-ebpf/target/bpfel-unknown-none/release/repx-ebpf".to_string(),
        "../repx-ebpf/target/bpfel-unknown-none/debug/repx-ebpf".to_string(),
        "target/bpfel-unknown-none/release/repx-ebpf".to_string(),
        "target/bpfel-unknown-none/debug/repx-ebpf".to_string(),
    ];

    if let Some(ref dir) = exe_dir {
        let workspace_root =
            dir.join("../../repx-ebpf/target/bpfel-unknown-none/release/repx-ebpf");
        search_paths.push(workspace_root.to_string_lossy().to_string());
    }

    for path in &search_paths {
        if let Ok(data) = std::fs::read(path) {
            info!("Loaded eBPF bytecode from: {}", path);
            return Ok(data);
        }
    }

    anyhow::bail!(
        "Could not find repx-ebpf binary. Build it first with:\n\
         cd repx-ebpf && cargo build --release\n\
         Searched: {:?}",
        search_paths
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LIFETIME: ProcessLifetime = ProcessLifetime {
        pid: 1,
        generation: 0,
    };

    fn test_state(root_pid: u32) -> EventCollectorState {
        EventCollectorState::new(root_pid, PathBuf::from("/workspace"))
    }

    #[test]
    fn proc_target_must_match_more_than_an_absolute_basename() {
        assert!(!paths_agree("/tmp/first/output.o", "/tmp/second/output.o"));
        assert!(paths_agree(
            "relative/output.o",
            "/tmp/build/relative/output.o"
        ));
    }

    #[test]
    fn rename_rewrites_open_file_paths_at_directory_boundaries() {
        let mut fd_table = HashMap::new();
        fd_table.insert(
            (TEST_LIFETIME, 3),
            OpenFileState {
                path: "/tmp/old/artifact".to_string(),
                handle: None,
                flags: 1,
                open_observation: None,
            },
        );
        fd_table.insert(
            (TEST_LIFETIME, 4),
            OpenFileState {
                path: "/tmp/older/unrelated".to_string(),
                handle: None,
                flags: 1,
                open_observation: None,
            },
        );

        rewrite_open_file_paths(&mut fd_table, "/tmp/old", "/tmp/new", 0);

        assert_eq!(fd_table[&(TEST_LIFETIME, 3)].path, "/tmp/new/artifact");
        assert_eq!(fd_table[&(TEST_LIFETIME, 4)].path, "/tmp/older/unrelated");
    }

    #[test]
    fn exchange_rename_swaps_open_file_paths() {
        let mut fd_table = HashMap::new();
        for (fd, path) in [(3, "/tmp/left"), (4, "/tmp/right")] {
            fd_table.insert(
                (TEST_LIFETIME, fd),
                OpenFileState {
                    path: path.to_string(),
                    handle: None,
                    flags: 1,
                    open_observation: None,
                },
            );
        }

        rewrite_open_file_paths(&mut fd_table, "/tmp/left", "/tmp/right", RENAME_EXCHANGE);

        assert_eq!(fd_table[&(TEST_LIFETIME, 3)].path, "/tmp/right");
        assert_eq!(fd_table[&(TEST_LIFETIME, 4)].path, "/tmp/left");
    }

    #[test]
    fn root_exec_epochs_advance_after_the_synthetic_initial_exec() {
        let mut state = test_state(42);

        assert_eq!(state.exec_process(42), None);
        assert_eq!(
            state.exec_process(42),
            Some(ProcessInstance::test_epoch(42, 1))
        );
        assert_eq!(
            state.exec_process(42),
            Some(ProcessInstance::test_epoch(42, 2))
        );
    }

    #[test]
    fn forked_processes_get_new_lifetimes_when_pids_are_reused() {
        let mut state = test_state(1);

        let (parent, child) = state.fork_process(1, 2);
        assert_eq!(parent, ProcessInstance::test(1));
        assert_eq!(child, ProcessInstance::test(2));
        assert_eq!(
            state.exec_process(2),
            Some(ProcessInstance::test_epoch(2, 1))
        );
        assert_eq!(state.exit_process(2), ProcessInstance::test_epoch(2, 1));

        let (_, reused) = state.fork_process(1, 2);
        assert_eq!(reused.lifetime.pid, 2);
        assert_eq!(reused.lifetime.generation, 1);
        assert_eq!(reused.exec_epoch, 0);
    }

    #[test]
    fn forked_processes_inherit_open_descriptor_state() {
        let mut state = test_state(1);
        state.fd_table.insert(
            (state.root_process.lifetime, 3),
            OpenFileState {
                path: "/tmp/inherited".to_string(),
                handle: None,
                flags: 1,
                open_observation: Some(FileObservation::Content("sha256:input".to_string())),
            },
        );

        let (_, child) = state.fork_process(1, 2);
        let inherited = &state.fd_table[&(child.lifetime, 3)];
        assert_eq!(inherited.path, "/tmp/inherited");
        assert_eq!(inherited.flags, 1);
        assert!(matches!(
            inherited.open_observation,
            Some(FileObservation::Content(ref hash)) if hash == "sha256:input"
        ));
    }

    #[test]
    fn cached_working_directory_resolves_paths_after_proc_disappears() {
        let mut state = test_state(u32::MAX);
        let process = state.root_process;

        assert_eq!(
            state.resolve_path(process, AT_FDCWD, "dist/hello"),
            "/workspace/dist/hello"
        );
    }

    #[test]
    fn forked_processes_inherit_cached_working_directories() {
        let mut state = test_state(u32::MAX - 1);
        let (_, child) = state.fork_process(u32::MAX - 1, u32::MAX);

        assert_eq!(
            state.resolve_path(child, AT_FDCWD, "dist/hello"),
            "/workspace/dist/hello"
        );
    }
}
