#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};
use repx_common::*;

/// Ring buffer for sending events to userspace. Bazel can emit tens of
/// thousands of file events in short bursts, so leave enough headroom for
/// userspace hashing without weakening fail-closed drop handling.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024 * 1024, 0);

/// Set of PIDs we're tracking (the traced process and its children).
/// Key: tgid, Value: 1 if tracked.
#[map]
static TRACKED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Root PID set by userspace to begin tracking.
#[map]
static ROOT_PID: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Temporary storage for openat enter data, keyed by pid_tgid.
/// We stash the path, flags, and dfd on enter, then emit the event on exit
/// when we have the actual fd return value.
#[map]
static OPENAT_STASH: HashMap<u64, OpenatStash> = HashMap::with_max_entries(4096, 0);

/// Temporary storage for rename/unlink arguments until syscall completion.
#[map]
static PATH_OP_STASH: HashMap<u64, PathOpStash> = HashMap::with_max_entries(4096, 0);

#[map]
static PATH_OP_OLD_PATH: HashMap<u64, PathStash> = HashMap::with_max_entries(4096, 0);

#[map]
static PATH_OP_NEW_PATH: HashMap<u64, PathStash> = HashMap::with_max_entries(4096, 0);

/// Counter for dropped events (ring buffer full). Keyed by 0, value is count.
#[map]
static DROP_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Flag to enable system-wide file monitoring (0=disabled, 1=enabled).
/// Key: 0, Value: 1 if watch mode active.
#[map]
static WATCH_MODE: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Watched path prefixes for system-wide monitoring.
/// Key: index (0..MAX_WATCH_PREFIXES), Value: prefix + length.
#[map]
static WATCHED_PREFIXES: HashMap<u32, WatchedPrefix> =
    HashMap::with_max_entries(8, 0);

/// Tracks file descriptors opened by external (non-tracked) processes that
/// match a watched prefix. Key: (tgid << 32) | fd, Value: 1 if watched.
#[map]
static WATCHED_FDS: HashMap<u64, u8> = HashMap::with_max_entries(8192, 0);

/// Stashed data from sys_enter_openat, waiting for sys_exit_openat.
#[repr(C)]
#[derive(Clone, Copy)]
struct OpenatStash {
    dfd: i32,
    flags: u32,
    path: [u8; MAX_PATH_LEN],
    path_len: u32,
    /// 0 = fork-tree tracked, 1 = watch-mode match from external process.
    from_watch: u8,
}

const PATH_OP_RENAME: u8 = 1;
const PATH_OP_UNLINK: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct PathOpStash {
    old_dfd: i32,
    new_dfd: i32,
    flags: u32,
    operation: u8,
    /// 0 = fork-tree tracked, 1 = watch-mode match from external process.
    from_watch: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PathStash {
    path: [u8; MAX_PATH_LEN],
    path_len: u32,
}

#[inline(always)]
fn is_tracked(tgid: u32) -> bool {
    unsafe { TRACKED_PIDS.get(&tgid).is_some() }
}

#[inline(always)]
fn track_pid(tgid: u32) {
    if TRACKED_PIDS.insert(&tgid, &1u8, 0).is_err() {
        record_drop();
    }
}

#[inline(always)]
fn untrack_pid(tgid: u32) {
    let _ = TRACKED_PIDS.remove(&tgid);
}

/// Increment the drop counter when a ring buffer reservation fails.
#[inline(always)]
fn record_drop() {
    let key: u32 = 0;
    let count = unsafe { DROP_COUNT.get(&key) }.copied().unwrap_or(0);
    let _ = DROP_COUNT.insert(&key, &(count + 1), 0);
}

/// Check whether a path matches any of the watched prefixes.
/// Uses bounded loops and index masking for BPF verifier compatibility.
#[inline(always)]
fn matches_watched_prefix(path: &[u8; MAX_PATH_LEN], path_len: u32) -> bool {
    let mut result = false;
    for i in 0..MAX_WATCH_PREFIXES {
        if result {
            break;
        }
        let key = i as u32;
        if let Some(p) = unsafe { WATCHED_PREFIXES.get(&key) } {
            let plen = p.len;
            if plen == 0 || plen > MAX_PREFIX_LEN as u32 || path_len < plen {
                continue;
            }
            let mut matches = true;
            for j in 0..MAX_PREFIX_LEN {
                if (j as u32) >= plen {
                    break;
                }
                // Bitmask hints to help the BPF verifier prove array bounds.
                let pi = j & (MAX_PATH_LEN - 1);   // j < 256
                let ji = j & (MAX_PREFIX_LEN - 1);  // j < 128
                if path[pi] != p.prefix[ji] {
                    matches = false;
                    break;
                }
            }
            if matches {
                result = true;
            }
        }
    }
    result
}

#[inline(always)]
fn path_is_absolute(path: &[u8; MAX_PATH_LEN], path_len: u32) -> bool {
    path_len > 0 && path[0] == b'/'
}

#[inline(never)]
fn stash_old_path(pid_tgid: u64, path_ptr: *const u8) -> Result<u32, i64> {
    let mut path = PathStash {
        path: [0u8; MAX_PATH_LEN],
        path_len: 0,
    };
    if let Ok(bytes) = unsafe { bpf_probe_read_user_str_bytes(path_ptr, &mut path.path) } {
        path.path_len = bytes.len() as u32;
    }
    if path.path_len == 0 {
        record_drop();
        return Ok(0);
    }
    if PATH_OP_OLD_PATH.insert(&pid_tgid, &path, 0).is_err() {
        record_drop();
        return Ok(0);
    }
    Ok(path.path_len)
}

#[inline(never)]
fn stash_new_path(pid_tgid: u64, path_ptr: *const u8) -> Result<u32, i64> {
    let mut path = PathStash {
        path: [0u8; MAX_PATH_LEN],
        path_len: 0,
    };
    if let Ok(bytes) = unsafe { bpf_probe_read_user_str_bytes(path_ptr, &mut path.path) } {
        path.path_len = bytes.len() as u32;
    }
    if path.path_len == 0 {
        record_drop();
        return Ok(0);
    }
    if PATH_OP_NEW_PATH.insert(&pid_tgid, &path, 0).is_err() {
        record_drop();
        return Ok(0);
    }
    Ok(path.path_len)
}

#[inline(always)]
fn remove_path_stash(pid_tgid: u64) {
    let _ = PATH_OP_STASH.remove(&pid_tgid);
    let _ = PATH_OP_OLD_PATH.remove(&pid_tgid);
    let _ = PATH_OP_NEW_PATH.remove(&pid_tgid);
}

#[inline(always)]
fn stash_rename(
    pid_tgid: u64,
    old_dfd: i32,
    old_path_ptr: *const u8,
    new_dfd: i32,
    new_path_ptr: *const u8,
    flags: u32,
) -> Result<u32, i64> {
    let tgid = (pid_tgid >> 32) as u32;
    let tracked = is_tracked(tgid);
    if !tracked && unsafe { WATCH_MODE.get(&0u32) }.copied().unwrap_or(0) == 0 {
        return Ok(0);
    }
    let stash = PathOpStash {
        old_dfd,
        new_dfd,
        flags,
        operation: PATH_OP_RENAME,
        from_watch: if tracked { 0 } else { 1 },
    };
    let old_path_len = stash_old_path(pid_tgid, old_path_ptr)?;
    let new_path_len = stash_new_path(pid_tgid, new_path_ptr)?;
    if old_path_len == 0 || new_path_len == 0 {
        remove_path_stash(pid_tgid);
        return Ok(0);
    }

    let old_path = match unsafe { PATH_OP_OLD_PATH.get(&pid_tgid) } {
        Some(path) => path,
        None => {
            record_drop();
            remove_path_stash(pid_tgid);
            return Ok(0);
        }
    };
    let new_path = match unsafe { PATH_OP_NEW_PATH.get(&pid_tgid) } {
        Some(path) => path,
        None => {
            record_drop();
            remove_path_stash(pid_tgid);
            return Ok(0);
        }
    };

    if !tracked {
        let both_absolute = path_is_absolute(&old_path.path, old_path.path_len)
            && path_is_absolute(&new_path.path, new_path.path_len);
        if both_absolute
            && !matches_watched_prefix(&old_path.path, old_path.path_len)
            && !matches_watched_prefix(&new_path.path, new_path.path_len)
        {
            remove_path_stash(pid_tgid);
            return Ok(0);
        }
    }

    if PATH_OP_STASH.insert(&pid_tgid, &stash, 0).is_err() {
        record_drop();
        remove_path_stash(pid_tgid);
    }
    Ok(0)
}

#[inline(always)]
fn stash_unlink(
    pid_tgid: u64,
    dfd: i32,
    path_ptr: *const u8,
    flags: u32,
) -> Result<u32, i64> {
    let tgid = (pid_tgid >> 32) as u32;
    let tracked = is_tracked(tgid);
    if !tracked && unsafe { WATCH_MODE.get(&0u32) }.copied().unwrap_or(0) == 0 {
        return Ok(0);
    }
    let stash = PathOpStash {
        old_dfd: dfd,
        new_dfd: 0,
        flags,
        operation: PATH_OP_UNLINK,
        from_watch: if tracked { 0 } else { 1 },
    };
    let path_len = stash_old_path(pid_tgid, path_ptr)?;
    if path_len == 0 {
        remove_path_stash(pid_tgid);
        return Ok(0);
    }
    let path = match unsafe { PATH_OP_OLD_PATH.get(&pid_tgid) } {
        Some(path) => path,
        None => {
            record_drop();
            remove_path_stash(pid_tgid);
            return Ok(0);
        }
    };

    if !tracked {
        if path_is_absolute(&path.path, path.path_len)
            && !matches_watched_prefix(&path.path, path.path_len)
        {
            remove_path_stash(pid_tgid);
            return Ok(0);
        }
    }

    if PATH_OP_STASH.insert(&pid_tgid, &stash, 0).is_err() {
        record_drop();
        remove_path_stash(pid_tgid);
    }
    Ok(0)
}

#[inline(always)]
fn emit_path_event(
    kind: EventKind,
    source: u8,
    timestamp_ns: u64,
    pid: u32,
    tgid: u32,
    dfd: i32,
    flags: u32,
    path: &[u8; MAX_PATH_LEN],
    path_len: u32,
) {
    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = kind as u32;
        event.source = source;
        event.timestamp_ns = timestamp_ns;

        let payload = unsafe { &mut event.payload.file_path };
        payload.pid = pid;
        payload.tgid = tgid;
        payload.dfd = dfd;
        payload.flags = flags;
        payload.operation_id = timestamp_ns;
        payload.path = *path;
        payload.path_len = path_len;

        entry.submit(0);
    } else {
        record_drop();
    }
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_openat
// Stash the path, dfd, and flags; the fd comes from the exit probe.
// For watch mode: stash untracked write opens unconditionally, and only keep
// read opens when the raw path matches a watched prefix.
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn repx_openat_enter(ctx: TracePointContext) -> u32 {
    match try_openat_enter(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_openat_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    let tracked = is_tracked(tgid);

    // sys_enter_openat layout (x86-64):
    //   offset  0: common fields (8 bytes)
    //   offset  8: __syscall_nr  (int, 4 bytes + 4 pad)
    //   offset 16: dfd           (unsigned long, 8 bytes)
    //   offset 24: filename      (pointer,       8 bytes)
    //   offset 32: flags         (unsigned long, 8 bytes)
    //   offset 40: mode          (umode_t,       2 bytes)
    let dfd: i32 = unsafe { ctx.read_at(16)? };
    let filename_ptr: *const u8 = unsafe { ctx.read_at(24)? };
    let flags: u32 = unsafe { ctx.read_at(32)? };

    let mut stash = OpenatStash {
        dfd,
        flags,
        path: [0u8; MAX_PATH_LEN],
        path_len: 0,
        from_watch: if tracked { 0 } else { 1 },
    };

    if let Ok(path_bytes) =
        unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut stash.path) }
    {
        stash.path_len = path_bytes.len() as u32;
    }

    if !tracked {
        let watch_enabled = unsafe { WATCH_MODE.get(&0u32) }.copied().unwrap_or(0);
        if watch_enabled == 0 {
            return Ok(0);
        }

        // O_WRONLY = 1, O_RDWR = 2 on Linux. Absolute paths can be
        // filtered here; relative writes need userspace resolution first.
        let is_write = (flags & 0x3) != 0;
        let is_absolute = stash.path.first().copied() == Some(b'/');
        if (!is_write || is_absolute)
            && !matches_watched_prefix(&stash.path, stash.path_len)
        {
            return Ok(0);
        }
    }

    if OPENAT_STASH.insert(&pid_tgid, &stash, 0).is_err() {
        record_drop();
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_exit_openat
// Now we have the fd return value — emit the full event.
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn repx_openat_exit(ctx: TracePointContext) -> u32 {
    match try_openat_exit(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_openat_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    // Only proceed if we stashed data on enter (tracked or watch-mode match).
    let stash = match unsafe { OPENAT_STASH.get(&pid_tgid) } {
        Some(s) => *s,
        None => return Ok(0),
    };
    let _ = OPENAT_STASH.remove(&pid_tgid);

    // sys_exit_openat: __syscall_nr at offset 8 (4+4 pad), ret at offset 16.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let fd = ret as i32;

    // Skip failed opens (fd < 0).
    if fd < 0 {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = EventKind::FileOpen as u32;
        event.source = stash.from_watch;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        let payload = unsafe { &mut event.payload.file_open };
        payload.pid = pid;
        payload.tgid = tgid;
        payload.fd = fd;
        payload.dfd = stash.dfd;
        payload.flags = stash.flags;
        payload.path = stash.path;
        payload.path_len = stash.path_len;

        entry.submit(0);
    } else {
        record_drop();
    }

    // For watch-mode opens, register the fd so we can track close/mmap.
    if stash.from_watch == 1 {
        let fd_key: u64 = ((tgid as u64) << 32) | (fd as u32 as u64);
        if WATCHED_FDS.insert(&fd_key, &1u8, 0).is_err() {
            record_drop();
        }
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Rename/unlink syscall tracepoints. Arguments are stashed on entry and only
// emitted after a successful syscall return. Rename emits one fixed-size event
// per path so the shared ring record remains compact.
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn repx_rename_enter(ctx: TracePointContext) -> u32 {
    match try_rename_enter(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_rename_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let old_path: *const u8 = unsafe { ctx.read_at(16)? };
    let new_path: *const u8 = unsafe { ctx.read_at(24)? };
    stash_rename(pid_tgid, -100, old_path, -100, new_path, 0)
}

#[tracepoint]
pub fn repx_renameat_enter(ctx: TracePointContext) -> u32 {
    match try_renameat_enter(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_renameat_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let old_dfd: i32 = unsafe { ctx.read_at(16)? };
    let old_path: *const u8 = unsafe { ctx.read_at(24)? };
    let new_dfd: i32 = unsafe { ctx.read_at(32)? };
    let new_path: *const u8 = unsafe { ctx.read_at(40)? };
    stash_rename(pid_tgid, old_dfd, old_path, new_dfd, new_path, 0)
}

#[tracepoint]
pub fn repx_renameat2_enter(ctx: TracePointContext) -> u32 {
    match try_renameat2_enter(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_renameat2_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let old_dfd: i32 = unsafe { ctx.read_at(16)? };
    let old_path: *const u8 = unsafe { ctx.read_at(24)? };
    let new_dfd: i32 = unsafe { ctx.read_at(32)? };
    let new_path: *const u8 = unsafe { ctx.read_at(40)? };
    let flags: u32 = unsafe { ctx.read_at(48)? };
    stash_rename(pid_tgid, old_dfd, old_path, new_dfd, new_path, flags)
}

#[tracepoint]
pub fn repx_unlink_enter(ctx: TracePointContext) -> u32 {
    match try_unlink_enter(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_unlink_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let path: *const u8 = unsafe { ctx.read_at(16)? };
    stash_unlink(pid_tgid, -100, path, 0)
}

#[tracepoint]
pub fn repx_unlinkat_enter(ctx: TracePointContext) -> u32 {
    match try_unlinkat_enter(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_unlinkat_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let dfd: i32 = unsafe { ctx.read_at(16)? };
    let path: *const u8 = unsafe { ctx.read_at(24)? };
    let flags: u32 = unsafe { ctx.read_at(32)? };
    stash_unlink(pid_tgid, dfd, path, flags)
}

#[tracepoint]
pub fn repx_rename_exit(ctx: TracePointContext) -> u32 {
    match try_path_op_exit(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

#[tracepoint]
pub fn repx_renameat_exit(ctx: TracePointContext) -> u32 {
    match try_path_op_exit(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

#[tracepoint]
pub fn repx_renameat2_exit(ctx: TracePointContext) -> u32 {
    match try_path_op_exit(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

#[tracepoint]
pub fn repx_unlink_exit(ctx: TracePointContext) -> u32 {
    match try_path_op_exit(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

#[tracepoint]
pub fn repx_unlinkat_exit(ctx: TracePointContext) -> u32 {
    match try_path_op_exit(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_path_op_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    let stash = match unsafe { PATH_OP_STASH.get(&pid_tgid) } {
        Some(stash) => *stash,
        None => return Ok(0),
    };

    let ret: i64 = unsafe { ctx.read_at(16)? };
    if ret < 0 {
        remove_path_stash(pid_tgid);
        return Ok(0);
    }

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    if stash.operation == PATH_OP_RENAME {
        let old_path = match unsafe { PATH_OP_OLD_PATH.get(&pid_tgid) } {
            Some(path) => path,
            None => {
                record_drop();
                remove_path_stash(pid_tgid);
                return Ok(0);
            }
        };
        emit_path_event(
            EventKind::FileRenameSource,
            stash.from_watch,
            timestamp_ns,
            pid,
            tgid,
            stash.old_dfd,
            stash.flags,
            &old_path.path,
            old_path.path_len,
        );
        let new_path = match unsafe { PATH_OP_NEW_PATH.get(&pid_tgid) } {
            Some(path) => path,
            None => {
                record_drop();
                remove_path_stash(pid_tgid);
                return Ok(0);
            }
        };
        emit_path_event(
            EventKind::FileRenameDestination,
            stash.from_watch,
            timestamp_ns,
            pid,
            tgid,
            stash.new_dfd,
            stash.flags,
            &new_path.path,
            new_path.path_len,
        );
    } else if stash.operation == PATH_OP_UNLINK {
        let path = match unsafe { PATH_OP_OLD_PATH.get(&pid_tgid) } {
            Some(path) => path,
            None => {
                record_drop();
                remove_path_stash(pid_tgid);
                return Ok(0);
            }
        };
        emit_path_event(
            EventKind::FileUnlink,
            stash.from_watch,
            timestamp_ns,
            pid,
            tgid,
            stash.old_dfd,
            stash.flags,
            &path.path,
            path.path_len,
        );
    }

    remove_path_stash(pid_tgid);

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_close
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn repx_close_enter(ctx: TracePointContext) -> u32 {
    match try_close_enter(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_close_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    // sys_enter_close: __syscall_nr at offset 8 (4+4 pad), fd at offset 16.
    let fd: i32 = unsafe { ctx.read_at(16)? };

    let source: u8;
    if is_tracked(tgid) {
        source = 0;
    } else {
        // Check if this fd was opened by a watch-mode match.
        let fd_key: u64 = ((tgid as u64) << 32) | (fd as u32 as u64);
        if unsafe { WATCHED_FDS.get(&fd_key) }.is_some() {
            source = 1;
            let _ = WATCHED_FDS.remove(&fd_key);
        } else {
            return Ok(0);
        }
    }

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = EventKind::FileClose as u32;
        event.source = source;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        let payload = unsafe { &mut event.payload.file_close };
        payload.pid = pid;
        payload.tgid = tgid;
        payload.fd = fd;

        entry.submit(0);
    } else {
        record_drop();
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_mmap
// Captures file-backed memory mappings (fd >= 0).
// Many programs (linkers, loaders) use mmap instead of read() to access files.
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn repx_mmap_enter(ctx: TracePointContext) -> u32 {
    match try_mmap_enter(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_mmap_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    // sys_enter_mmap layout (x86-64):
    //   offset  8: __syscall_nr (int, 4+4 pad)
    //   offset 16: addr  (unsigned long)
    //   offset 24: len   (size_t)
    //   offset 32: prot  (unsigned long)
    //   offset 40: flags (unsigned long)
    //   offset 48: fd    (unsigned long)
    //   offset 56: off   (unsigned long)
    let prot: u64 = unsafe { ctx.read_at(32)? };
    let flags: u64 = unsafe { ctx.read_at(40)? };
    let fd: i64 = unsafe { ctx.read_at(48)? };

    // Only care about file-backed mappings (fd >= 0).
    if fd < 0 {
        return Ok(0);
    }

    let source: u8;
    if is_tracked(tgid) {
        source = 0;
    } else {
        // Check if this fd was opened by a watch-mode match.
        let fd_key: u64 = ((tgid as u64) << 32) | (fd as u32 as u64);
        if unsafe { WATCHED_FDS.get(&fd_key) }.is_some() {
            source = 1;
        } else {
            return Ok(0);
        }
    }

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = EventKind::FileMmap as u32;
        event.source = source;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        let payload = unsafe { &mut event.payload.file_mmap };
        payload.pid = pid;
        payload.tgid = tgid;
        payload.fd = fd as i32;
        payload.prot = prot as u32;
        payload.flags = flags as u32;

        entry.submit(0);
    } else {
        record_drop();
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sched_process_exec
//
// The filename in this tracepoint is a __data_loc field (not a raw pointer).
// __data_loc encodes the offset in the lower 16 bits and length in upper 16.
// We read the offset, then use bpf_probe_read_kernel_str_bytes to read the
// actual string from the tracepoint context at that offset.
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn repx_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    // Auto-track: if this is the root PID, start tracking.
    if unsafe { ROOT_PID.get(&tgid).is_some() } {
        track_pid(tgid);
    }

    if !is_tracked(tgid) {
        return Ok(0);
    }

    // sched_process_exec tracepoint format (after common fields):
    //   offset 8:  __data_loc char[] filename  (u32: high 16 = len, low 16 = offset)
    //   offset 12: pid_t pid
    //   offset 16: pid_t old_pid
    let data_loc: u32 = unsafe { ctx.read_at(8)? };
    let filename_offset = (data_loc & 0xFFFF) as usize;
    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = EventKind::ProcessExec as u32;
        event.source = 0;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        let payload = unsafe { &mut event.payload.process_exec };
        payload.pid = pid;
        payload.tgid = tgid;
        payload.filename = [0u8; MAX_PATH_LEN];
        payload.filename_len = 0;

        let ctx_ptr = ctx.as_ptr() as *const u8;
        let filename_ptr = unsafe { ctx_ptr.add(filename_offset) };
        if let Ok(name_bytes) =
            unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr, &mut payload.filename) }
        {
            payload.filename_len = name_bytes.len() as u32;
        }

        entry.submit(0);
    } else {
        record_drop();
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sched_process_fork
// Track children of tracked processes.
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn repx_fork(ctx: TracePointContext) -> u32 {
    match try_fork(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    // sched_process_fork layout:
    //   offset  8: parent_comm[16] (char[16])
    //   offset 28: child_comm[16]  (char[16])
    //   offset 44: child_pid       (pid_t, 4 bytes)
    // Use the current thread-group ID for the parent so forks issued by a
    // non-leader thread still attach to the correct process lifetime.
    let parent_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let child_pid: u32 = unsafe { ctx.read_at(44)? };

    if !is_tracked(parent_pid) {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = EventKind::ProcessFork as u32;
        event.source = 0;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        let payload = unsafe { &mut event.payload.process_fork };
        payload.parent_pid = parent_pid;
        payload.child_pid = child_pid;

        entry.submit(0);
    } else {
        record_drop();
    }

    track_pid(child_pid);

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: sched_process_exit
//
// Only untrack when pid == tgid (the thread group leader exits).
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn repx_exit(ctx: TracePointContext) -> u32 {
    match try_exit(&ctx) {
        Ok(_) | Err(_) => 0,
    }
}

fn try_exit(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    if !is_tracked(tgid) {
        return Ok(0);
    }

    // sched_process_exit fires for every thread. Process lifetimes end only
    // when the thread-group leader exits.
    if pid != tgid {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = EventKind::ProcessExit as u32;
        event.source = 0;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        let payload = unsafe { &mut event.payload.process_exit };
        payload.pid = pid;
        payload.tgid = tgid;
        payload.exit_code = 0;

        entry.submit(0);
    } else {
        record_drop();
    }

    untrack_pid(tgid);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
