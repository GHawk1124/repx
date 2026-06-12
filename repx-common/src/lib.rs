//! Shared types between repx eBPF probes and userspace.
//!
//! These types are used in the ring buffer to communicate events
//! from kernel eBPF programs to the userspace consumer.

#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum path length we capture in BPF events.
/// Longer paths are truncated.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum number of watched path prefixes.
pub const MAX_WATCH_PREFIXES: usize = 8;

/// Maximum length of a watched path prefix.
pub const MAX_PREFIX_LEN: usize = 128;

/// Discriminant for event types sent over the ring buffer.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A file was opened (captures path + flags).
    FileOpen = 1,
    /// A file descriptor was closed (triggers output hashing in userspace).
    FileClose = 2,
    /// A process was exec'd (captures the binary path).
    ProcessExec = 3,
    /// Process exited.
    ProcessExit = 4,
    /// A file was memory-mapped (captures fd + prot + flags).
    FileMmap = 5,
}

impl TryFrom<u32> for EventKind {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::FileOpen),
            2 => Ok(Self::FileClose),
            3 => Ok(Self::ProcessExec),
            4 => Ok(Self::ProcessExit),
            5 => Ok(Self::FileMmap),
            _ => Err(()),
        }
    }
}

/// Event emitted when a file is opened via openat/open.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    /// PID of the process.
    pub pid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// File descriptor returned (populated on exit probe).
    pub fd: i32,
    /// Directory fd for relative path resolution (AT_FDCWD = -100).
    pub dfd: i32,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc).
    pub flags: u32,
    /// Path of the file being opened.
    pub path: [u8; MAX_PATH_LEN],
    /// Actual length of the path (before potential truncation).
    pub path_len: u32,
}

/// Event emitted when a file descriptor is closed.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileCloseEvent {
    /// PID of the process.
    pub pid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// File descriptor being closed.
    pub fd: i32,
}

/// Event emitted when a process calls execve.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecEvent {
    /// PID of the new process.
    pub pid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// Path of the executable.
    pub filename: [u8; MAX_PATH_LEN],
    /// Actual length of filename.
    pub filename_len: u32,
}

/// Event emitted when a process exits.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitEvent {
    /// PID of the exiting process.
    pub pid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// Exit code.
    pub exit_code: i32,
}

/// Event emitted when a file is memory-mapped via mmap.
/// Only emitted for file-backed mappings (fd >= 0).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileMmapEvent {
    /// PID of the process.
    pub pid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// File descriptor being mapped.
    pub fd: i32,
    /// Protection flags (PROT_READ, PROT_WRITE, etc).
    pub prot: u32,
    /// Mapping flags (MAP_SHARED, MAP_PRIVATE, etc).
    pub flags: u32,
}

/// A watched path prefix for system-wide file monitoring.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WatchedPrefix {
    pub prefix: [u8; MAX_PREFIX_LEN],
    pub len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for WatchedPrefix {}

/// Top-level event wrapper sent over the ring buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub kind: u32,             // EventKind discriminant at offset 0
    pub source: u8,            // 1 byte at offset 4 (0=fork-tree, 1=watched-path)
    pub _pad: [u8; 3],         // 3 bytes of padding at offset 5
    pub timestamp_ns: u64,     // 8 bytes at offset 8
    pub payload: EventPayload, // at offset 16
}

/// Union-like payload. We use a byte array and interpret
/// based on `kind` since BPF ring buffers work with fixed-size entries.
#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    pub file_open: FileOpenEvent,
    pub file_close: FileCloseEvent,
    pub file_mmap: FileMmapEvent,
    pub process_exec: ProcessExecEvent,
    pub process_exit: ProcessExitEvent,
    pub _pad: [u8; core::mem::size_of::<FileOpenEvent>()],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_size_stays_small_enough_for_bursty_builds() {
        assert!(core::mem::size_of::<Event>() <= 320);
    }

    #[test]
    fn unknown_event_kinds_are_rejected() {
        assert_eq!(EventKind::try_from(3), Ok(EventKind::ProcessExec));
        assert!(EventKind::try_from(u32::MAX).is_err());
    }
}
