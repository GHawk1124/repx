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
    is_path_within, observe_file, observe_path, open_regular, FileObservation,
};

/// AT_FDCWD sentinel: openat interprets relative paths against the cwd.
const AT_FDCWD: i32 = -100;

/// A high-level traced event, extracted from raw BPF events.
#[derive(Debug, Clone)]
pub enum TracedEvent {
    Exec {
        pid: u32,
        observation: FileObservation,
    },
    FileOpen {
        pid: u32,
        path: String,
        flags: u32,
        fd: i32,
        /// True if this event came from a non-fork-tree process matching a watched prefix.
        external: bool,
        /// File identity captured as soon as the successful open event arrived.
        observation: FileObservation,
    },
    FileClose {
        pid: u32,
        fd: i32,
        /// Resolved path (looked up from our fd tracking table).
        path: Option<String>,
        /// True if this event came from a non-fork-tree process.
        external: bool,
        /// File identity captured when the close event arrived.
        observation: Option<FileObservation>,
    },
    FileMmap {
        pid: u32,
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
    Exit {
        pid: u32,
        exit_code: i32,
    },
}

/// Result of tracing a command.
pub struct TraceResult {
    pub events: Vec<TracedEvent>,
    /// PID of the root traced process.
    pub root_pid: u32,
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
    attach_tracepoint(&mut bpf, "repx_close_enter", "syscalls", "sys_enter_close")?;
    attach_tracepoint(&mut bpf, "repx_mmap_enter", "syscalls", "sys_enter_mmap")?;
    attach_tracepoint(&mut bpf, "repx_exec", "sched", "sched_process_exec")?;
    attach_tracepoint(&mut bpf, "repx_fork", "sched", "sched_process_fork")?;
    attach_tracepoint(&mut bpf, "repx_exit", "sched", "sched_process_exit")?;

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
    let mut fd_table: HashMap<(u32, i32), OpenFileState> = HashMap::new();
    let mut malformed_events = 0u64;

    collect_events(
        ring_buf,
        child_pid,
        &mut events,
        &mut fd_table,
        &watch_prefixes,
        &mut malformed_events,
    )?;

    // Use a single userspace-authored root Exec op. This avoids the original
    // spawn-to-map-registration race and prevents duplicate root Exec ops when
    // BPF also observes sched_process_exec.
    events.retain(|ev| !matches!(ev, TracedEvent::Exec { pid, .. } if *pid == child_pid));
    events.insert(
        0,
        TracedEvent::Exec {
            pid: child_pid,
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
            .saturating_add(malformed_events)
    };

    if dropped_events > 0 {
        warn!("{} events were dropped (ring buffer full)", dropped_events);
    }

    info!("Collected {} events", events.len());
    Ok(TraceResult {
        events,
        root_pid: child_pid,
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
    fd_table: &mut HashMap<(u32, i32), OpenFileState>,
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
            let path_len = (payload.path_len as usize).min(payload.path.len());
            let raw_path = std::str::from_utf8(&payload.path[..path_len])
                .unwrap_or("<invalid utf8>")
                .trim_end_matches('\0')
                .to_string();

            let raw_resolved = resolve_open_path(payload.tgid, payload.dfd, &raw_path);
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
            let mut state = OpenFileState {
                path,
                handle,
                flags: payload.flags,
                open_observation: None,
            };
            let observation = state.open_observation();
            let event_path = state.path.clone();

            debug!(
                "FileOpen pid={} tgid={} fd={} dfd={} path={} flags={} external={}",
                payload.pid,
                process_id,
                payload.fd,
                payload.dfd,
                state.path,
                payload.flags,
                external
            );

            // Track this fd for later close resolution.
            if payload.fd >= 0 {
                fd_table.insert((process_id, payload.fd), state);
            }

            events.push(TracedEvent::FileOpen {
                pid: process_id,
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
            let mut state = fd_table.remove(&(process_id, payload.fd));
            if external && state.is_none() {
                return true;
            }
            let observation = state.as_mut().and_then(OpenFileState::close_observation);
            let path = state.map(|state| state.path);

            debug!(
                "FileClose pid={} tgid={} fd={} path={:?} external={}",
                payload.pid, process_id, payload.fd, path, external
            );

            events.push(TracedEvent::FileClose {
                pid: process_id,
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

            let (path, observation) = match fd_table.get_mut(&(process_id, payload.fd)) {
                Some(state) => (Some(state.path.clone()), Some(state.mmap_observation())),
                None if external => return true,
                None => (None, None),
            };

            debug!(
                "FileMmap pid={} tgid={} fd={} prot={:#x} flags={:#x} path={:?} external={}",
                payload.pid, process_id, payload.fd, payload.prot, payload.flags, path, external
            );

            events.push(TracedEvent::FileMmap {
                pid: process_id,
                fd: payload.fd,
                prot: payload.prot,
                flags: payload.flags,
                path,
                external,
                observation,
            });
        }
        EventKind::ProcessExec => {
            let payload = unsafe { &event.payload.process_exec };
            let process_id = payload.tgid;
            let name_len = (payload.filename_len as usize).min(payload.filename.len());
            let raw_filename = std::str::from_utf8(&payload.filename[..name_len])
                .unwrap_or("<invalid utf8>")
                .trim_end_matches('\0')
                .to_string();
            let raw_filename = resolve_exec_path(payload.tgid, &raw_filename);
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
                pid: process_id,
                observation,
            });
        }
        EventKind::ProcessExit => {
            let payload = unsafe { &event.payload.process_exit };
            let process_id = payload.tgid;
            debug!(
                "Exit pid={} tgid={} code={}",
                payload.pid, process_id, payload.exit_code
            );

            events.push(TracedEvent::Exit {
                pid: process_id,
                exit_code: payload.exit_code,
            });
        }
    }

    true
}

fn collect_events(
    mut ring_buf: RingBuf<&mut aya::maps::MapData>,
    child_pid: u32,
    events: &mut Vec<TracedEvent>,
    fd_table: &mut HashMap<(u32, i32), OpenFileState>,
    watch_prefixes: &[String],
    malformed_events: &mut u64,
) -> Result<()> {
    loop {
        // Poll the ring buffer.
        while let Some(item) = ring_buf.next() {
            let data = item.as_ref();
            if data.len() < std::mem::size_of::<Event>() {
                warn!("Short event: {} bytes", data.len());
                *malformed_events = malformed_events.saturating_add(1);
                continue;
            }

            let event = unsafe { (data.as_ptr() as *const Event).read_unaligned() };
            if !process_event(&event, events, fd_table, watch_prefixes) {
                *malformed_events = malformed_events.saturating_add(1);
            }
        }

        // Check if the child has exited.
        match waitpid(Pid::from_raw(child_pid as i32), Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::Exited(_, real_exit_code) => {
                info!("Child exited with status {}", real_exit_code);
                finish_child_exit(
                    ring_buf,
                    child_pid,
                    real_exit_code,
                    events,
                    fd_table,
                    watch_prefixes,
                    malformed_events,
                )?;
                break;
            }
            WaitStatus::Signaled(_, signal, _) => {
                let real_exit_code = 128 + signal as i32;
                info!("Child exited from signal {}", signal);
                finish_child_exit(
                    ring_buf,
                    child_pid,
                    real_exit_code,
                    events,
                    fd_table,
                    watch_prefixes,
                    malformed_events,
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

fn finish_child_exit(
    mut ring_buf: RingBuf<&mut aya::maps::MapData>,
    child_pid: u32,
    real_exit_code: i32,
    events: &mut Vec<TracedEvent>,
    fd_table: &mut HashMap<(u32, i32), OpenFileState>,
    watch_prefixes: &[String],
    malformed_events: &mut u64,
) -> Result<()> {
    // Allow a short quiescence window for sibling watch-mode events that race
    // with the traced child's exit.
    let quiescence = std::time::Duration::from_millis(100);
    let poll_interval = std::time::Duration::from_millis(10);
    let mut deadline = std::time::Instant::now() + quiescence;

    loop {
        let mut saw_event = false;

        while let Some(item) = ring_buf.next() {
            let data = item.as_ref();
            if data.len() >= std::mem::size_of::<Event>() {
                let event = unsafe { (data.as_ptr() as *const Event).read_unaligned() };
                if !process_event(&event, events, fd_table, watch_prefixes) {
                    *malformed_events = malformed_events.saturating_add(1);
                }
                saw_event = true;
            } else {
                warn!("Short event: {} bytes", data.len());
                *malformed_events = malformed_events.saturating_add(1);
            }
        }

        if saw_event {
            deadline = std::time::Instant::now() + quiescence;
        }

        if std::time::Instant::now() >= deadline {
            break;
        }

        wait_for_ring_event(&ring_buf, poll_interval.as_millis() as i32)?;
    }

    // Patch the child's exit event with the real exit code from waitpid().
    // BPF can't reliably read exit_code from task_struct, so we use waitpid,
    // which is authoritative.
    let mut found_exit = false;
    for ev in events.iter_mut().rev() {
        if let TracedEvent::Exit { pid, exit_code, .. } = ev {
            if *pid == child_pid {
                *exit_code = real_exit_code;
                found_exit = true;
                break;
            }
        }
    }

    // If BPF missed the exit event, synthesize one.
    if !found_exit {
        events.push(TracedEvent::Exit {
            pid: child_pid,
            exit_code: real_exit_code,
        });
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

struct OpenFileState {
    path: String,
    handle: Option<File>,
    flags: u32,
    open_observation: Option<FileObservation>,
}

impl OpenFileState {
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

fn resolve_open_path(tgid: u32, dfd: i32, raw_path: &str) -> String {
    if raw_path.starts_with('/') {
        return raw_path.to_string();
    }

    let base = if dfd == AT_FDCWD {
        std::fs::read_link(format!("/proc/{tgid}/cwd"))
    } else {
        std::fs::read_link(format!("/proc/{tgid}/fd/{dfd}"))
    };
    base.map(|base| base.join(raw_path).to_string_lossy().into_owned())
        .unwrap_or_else(|_| raw_path.to_string())
}

fn resolve_exec_path(tgid: u32, raw_path: &str) -> String {
    if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        resolve_open_path(tgid, AT_FDCWD, raw_path)
    }
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

    #[test]
    fn proc_target_must_match_more_than_an_absolute_basename() {
        assert!(!paths_agree("/tmp/first/output.o", "/tmp/second/output.o"));
        assert!(paths_agree(
            "relative/output.o",
            "/tmp/build/relative/output.o"
        ));
    }
}
