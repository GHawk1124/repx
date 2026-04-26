//! eBPF tracer: loads BPF programs, spawns the traced command,
//! and collects events from the ring buffer.

use anyhow::{Context, Result};
use aya::maps::{HashMap as BpfHashMap, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use log::{debug, info, warn};
use repx_common::{Event, EventKind, WatchedPrefix, MAX_PREFIX_LEN, MAX_WATCH_PREFIXES};
use std::collections::HashMap;
use std::path::PathBuf;

/// AT_FDCWD sentinel: openat interprets relative paths against the cwd.
const AT_FDCWD: i32 = -100;

/// A high-level traced event, extracted from raw BPF events.
#[derive(Debug, Clone)]
pub enum TracedEvent {
    Exec {
        pid: u32,
        ppid: u32,
        filename: String,
        argv: Vec<String>,
    },
    FileOpen {
        pid: u32,
        path: String,
        flags: u32,
        fd: i32,
        /// Directory fd for relative path resolution (AT_FDCWD = -100).
        dfd: i32,
        /// True if this event came from a non-fork-tree process matching a watched prefix.
        external: bool,
    },
    FileClose {
        pid: u32,
        fd: i32,
        /// Resolved path (looked up from our fd tracking table).
        path: Option<String>,
        /// True if this event came from a non-fork-tree process.
        external: bool,
    },
    FileMmap {
        pid: u32,
        fd: i32,
        prot: u32,
        /// Resolved path (looked up from our fd tracking table).
        path: Option<String>,
        /// True if this event came from a non-fork-tree process.
        external: bool,
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

        for (i, dir) in watch_dirs.iter().enumerate().take(MAX_WATCH_PREFIXES) {
            let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
            let path_str = canonical.to_string_lossy();
            let path_bytes = path_str.as_bytes();

            let mut prefix = WatchedPrefix {
                prefix: [0u8; MAX_PREFIX_LEN],
                len: 0,
            };
            let copy_len = path_bytes.len().min(MAX_PREFIX_LEN);
            prefix.prefix[..copy_len].copy_from_slice(&path_bytes[..copy_len]);
            prefix.len = copy_len as u32;

            watched_prefixes.insert(i as u32, prefix, 0)?;
            info!("Watching prefix: {}", path_str);
        }
    }

    // Spawn the command and track its PID.
    let child = std::process::Command::new(&command[0])
        .args(&command[1..])
        .spawn()
        .with_context(|| format!("Failed to spawn: {}", command[0]))?;

    let child_pid = child.id();
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

    // Consume events from the ring buffer until the child exits.
    let mut events = Vec::new();
    let ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    // Track fd -> path mapping per process for resolving closes.
    let mut fd_table: HashMap<(u32, i32), String> = HashMap::new();

    collect_events(ring_buf, child, child_pid, &mut events, &mut fd_table)?;

    // Check for dropped events (ring buffer was full).
    let dropped_events = {
        let drop_count: BpfHashMap<_, u32, u64> =
            BpfHashMap::try_from(bpf.map_mut("DROP_COUNT").unwrap())?;
        drop_count.get(&0u32, 0).unwrap_or(0)
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

fn process_event(
    event: &Event,
    events: &mut Vec<TracedEvent>,
    fd_table: &mut HashMap<(u32, i32), String>,
) {
    match event.kind {
        EventKind::FileOpen => {
            let payload = unsafe { &event.payload.file_open };
            let external = event.source == 1;
            let path_len = (payload.path_len as usize).min(payload.path.len());
            let raw_path = std::str::from_utf8(&payload.path[..path_len])
                .unwrap_or("<invalid utf8>")
                .trim_end_matches('\0')
                .to_string();

            // Resolve relative paths to absolute.
            let path = if !raw_path.starts_with('/') {
                if payload.dfd == AT_FDCWD {
                    // Relative to process cwd — resolve via /proc.
                    if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", payload.tgid)) {
                        format!("{}/{}", cwd.display(), raw_path)
                    } else {
                        raw_path
                    }
                } else {
                    // Relative to an open directory fd — resolve via /proc.
                    if let Ok(dir_path) =
                        std::fs::read_link(format!("/proc/{}/fd/{}", payload.tgid, payload.dfd))
                    {
                        format!("{}/{}", dir_path.display(), raw_path)
                    } else {
                        raw_path
                    }
                }
            } else {
                raw_path
            };

            debug!(
                "FileOpen pid={} fd={} dfd={} path={} flags={} external={}",
                payload.pid, payload.fd, payload.dfd, path, payload.flags, external
            );

            // Track this fd for later close resolution.
            if payload.fd >= 0 {
                fd_table.insert((payload.pid, payload.fd), path.clone());
            }

            events.push(TracedEvent::FileOpen {
                pid: payload.pid,
                path,
                flags: payload.flags,
                fd: payload.fd,
                dfd: payload.dfd,
                external,
            });
        }
        EventKind::FileClose => {
            let payload = unsafe { &event.payload.file_close };
            let external = event.source == 1;
            let path = fd_table.remove(&(payload.pid, payload.fd));

            debug!(
                "FileClose pid={} fd={} path={:?} external={}",
                payload.pid, payload.fd, path, external
            );

            events.push(TracedEvent::FileClose {
                pid: payload.pid,
                fd: payload.fd,
                path,
                external,
            });
        }
        EventKind::FileMmap => {
            let payload = unsafe { &event.payload.file_mmap };
            let external = event.source == 1;

            // Look up the path from our fd table (populated by openat).
            let path = fd_table.get(&(payload.pid, payload.fd)).cloned();

            debug!(
                "FileMmap pid={} fd={} prot={:#x} path={:?} external={}",
                payload.pid, payload.fd, payload.prot, path, external
            );

            events.push(TracedEvent::FileMmap {
                pid: payload.pid,
                fd: payload.fd,
                prot: payload.prot,
                path,
                external,
            });
        }
        EventKind::ProcessExec => {
            let payload = unsafe { &event.payload.process_exec };
            let name_len = (payload.filename_len as usize).min(payload.filename.len());
            let filename = std::str::from_utf8(&payload.filename[..name_len])
                .unwrap_or("<invalid utf8>")
                .trim_end_matches('\0')
                .to_string();

            // Try to read argv from BPF buffer first, fall back to /proc.
            let argv_len = (payload.argv_total_len as usize).min(payload.argv_buf.len());
            let argv: Vec<String> = if argv_len > 0 {
                payload.argv_buf[..argv_len]
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect()
            } else {
                // BPF didn't capture argv — read from /proc/<pid>/cmdline.
                // This is best-effort: the process may have already exited.
                read_proc_cmdline(payload.tgid).unwrap_or_else(|| vec![filename.clone()])
            };

            // BPF can't read ppid (task_struct is opaque in aya-ebpf).
            // Read it from /proc instead. Best-effort: may fail if
            // the process has already exited.
            let ppid = read_proc_ppid(payload.tgid).unwrap_or(0);

            debug!(
                "Exec pid={} ppid={} file={} argv={:?}",
                payload.pid, ppid, filename, argv
            );

            events.push(TracedEvent::Exec {
                pid: payload.pid,
                ppid,
                filename,
                argv,
            });
        }
        EventKind::ProcessExit => {
            let payload = unsafe { &event.payload.process_exit };
            debug!("Exit pid={} code={}", payload.pid, payload.exit_code);

            events.push(TracedEvent::Exit {
                pid: payload.pid,
                exit_code: payload.exit_code,
            });
        }
    }
}

fn collect_events(
    mut ring_buf: RingBuf<&mut aya::maps::MapData>,
    child: std::process::Child,
    child_pid: u32,
    events: &mut Vec<TracedEvent>,
    fd_table: &mut HashMap<(u32, i32), String>,
) -> Result<()> {
    let mut child = child;

    loop {
        // Poll the ring buffer.
        while let Some(item) = ring_buf.next() {
            let data = item.as_ref();
            if data.len() < std::mem::size_of::<Event>() {
                warn!("Short event: {} bytes", data.len());
                continue;
            }

            let event: &Event = unsafe { &*(data.as_ptr() as *const Event) };
            process_event(event, events, fd_table);
        }

        // Check if the child has exited.
        match child.try_wait()? {
            Some(status) => {
                info!("Child exited with: {}", status);

                // Allow a short quiescence window for sibling watch-mode
                // events that race with the traced child's exit.
                let quiescence = std::time::Duration::from_millis(100);
                let poll_interval = std::time::Duration::from_millis(10);
                let mut deadline = std::time::Instant::now() + quiescence;

                loop {
                    let mut saw_event = false;

                    while let Some(item) = ring_buf.next() {
                        let data = item.as_ref();
                        if data.len() >= std::mem::size_of::<Event>() {
                            let event: &Event = unsafe { &*(data.as_ptr() as *const Event) };
                            process_event(event, events, fd_table);
                            saw_event = true;
                        }
                    }

                    if saw_event {
                        deadline = std::time::Instant::now() + quiescence;
                    }

                    if std::time::Instant::now() >= deadline {
                        break;
                    }

                    std::thread::sleep(poll_interval);
                }

                // Patch the child's exit event with the real exit code from wait().
                // BPF can't reliably read exit_code from task_struct, so we
                // use the waitpid result which is authoritative.
                let real_exit_code = status.code().unwrap_or(-1);
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

                // If BPF missed the exit event (race), synthesize one.
                if !found_exit {
                    events.push(TracedEvent::Exit {
                        pid: child_pid,
                        exit_code: real_exit_code,
                    });
                }

                break;
            }
            None => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    Ok(())
}

/// Read PPid from /proc/<pid>/status. Returns None if unreadable.
fn read_proc_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Read argv from /proc/<pid>/cmdline. Returns None if unreadable.
fn read_proc_cmdline(pid: u32) -> Option<Vec<String>> {
    let data = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    if data.is_empty() {
        return None;
    }
    let args: Vec<String> = data
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
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
