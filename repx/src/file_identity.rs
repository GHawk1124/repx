use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const SYSTEM_STATE_SENTINEL: &str =
    "SYSTEM_STATE:0000000000000000000000000000000000000000000000000000000000000000";

const SYSTEM_STATE_DIRS: &[&str] = &["/proc", "/sys"];
const SYSTEM_STATE_FILES: &[&str] = &[
    "/etc/hostname",
    "/etc/os-release",
    "/etc/machine-id",
    "/dev/urandom",
    "/dev/random",
    "/dev/null",
    "/dev/zero",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileObservation {
    Content(String),
    Missing(String),
    Unreadable(String),
    NonRegular(String),
}

impl FileObservation {
    pub fn identity(&self) -> String {
        match self {
            Self::Content(hash) => hash.clone(),
            Self::Missing(path_hash) => format!("missing:{path_hash}"),
            Self::Unreadable(path_hash) => format!("unreadable:{path_hash}"),
            Self::NonRegular(path_hash) => format!("non-regular:{path_hash}"),
        }
    }

    pub fn content_hash(&self) -> Option<&str> {
        match self {
            Self::Content(hash) => Some(hash),
            _ => None,
        }
    }
}

pub fn observe_path(path: &str) -> FileObservation {
    let path_hash = hash_path(path);
    let mut file = match open_regular(path) {
        Ok(Some(file)) => file,
        Ok(None) => return FileObservation::NonRegular(path_hash),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return FileObservation::Missing(path_hash)
        }
        Err(_) => return FileObservation::Unreadable(path_hash),
    };
    observe_file(&mut file, path)
}

/// Open a regular file without allowing FIFOs or terminal devices to block
/// the single-threaded event consumer. Metadata is checked before open and
/// O_NONBLOCK protects against a path replacement race.
pub fn open_regular(path: &str) -> std::io::Result<Option<File>> {
    if !fs::metadata(path)?.is_file() {
        return Ok(None);
    }

    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open(path)
        .map(Some)
}

pub fn observe_file(file: &mut File, path: &str) -> FileObservation {
    let path_hash = hash_path(path);
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return FileObservation::Missing(path_hash)
        }
        Err(_) => return FileObservation::Unreadable(path_hash),
    };

    if !metadata.is_file() {
        return FileObservation::NonRegular(path_hash);
    }

    if file.seek(SeekFrom::Start(0)).is_err() {
        return FileObservation::Unreadable(path_hash);
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(_) => return FileObservation::Unreadable(path_hash),
        }
    }

    FileObservation::Content(format!("sha256:{:x}", hasher.finalize()))
}

pub fn hash_file_contents(path: &Path) -> Option<String> {
    observe_path(&path.to_string_lossy())
        .content_hash()
        .map(ToOwned::to_owned)
}

pub fn is_system_state(path: &str) -> bool {
    SYSTEM_STATE_DIRS
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
        || SYSTEM_STATE_FILES.contains(&path)
}

pub fn is_path_within(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    prefix.is_empty() || path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn hash_path(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"repx-path-v1\0");
    hasher.update(
        normalize_unavailable_path(path)
            .to_string_lossy()
            .as_bytes(),
    );
    format!("sha256:{:x}", hasher.finalize())
}

fn normalize_unavailable_path(path: &str) -> PathBuf {
    if path.starts_with("/dev/pts/")
        && path[9..]
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return PathBuf::from("/dev/pts/<session>");
    }

    let mut normalized = PathBuf::new();
    let under_temp = path.starts_with("/tmp/") || path.starts_with("/var/tmp/");
    for component in Path::new(path).components() {
        let value = component.as_os_str().to_string_lossy();
        if under_temp && is_session_temp_component(&value) {
            normalized.push("<session>");
        } else if under_temp {
            normalized.push(normalize_compiler_temp_component(&value));
        } else {
            normalized.push(component.as_os_str());
        }
    }
    normalized
}

fn is_session_temp_component(component: &str) -> bool {
    component.strip_prefix("tmp.").is_some_and(|suffix| {
        suffix.len() >= 6 && suffix.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

fn normalize_compiler_temp_component(component: &str) -> String {
    let (stem, extension) = component
        .split_once('.')
        .map_or((component, None), |(stem, extension)| {
            (stem, Some(extension))
        });
    let generated = (stem.starts_with("cc") && stem.len() >= 8)
        || (stem.starts_with("rustc") && stem.len() >= 10);
    if generated
        && stem
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        extension.map_or_else(
            || "<compiler-temp>".to_string(),
            |extension| format!("<compiler-temp>.{extension}"),
        )
    } else {
        component.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_state_matching_respects_path_boundaries() {
        assert!(is_system_state("/proc/cpuinfo"));
        assert!(is_system_state("/etc/os-release"));
        assert!(!is_system_state("/etc/os-release-evil"));
        assert!(!is_system_state("/proc-evil/cpuinfo"));
    }

    #[test]
    fn missing_files_are_bound_to_their_paths() {
        let first = observe_path("/definitely-missing/repx-a").identity();
        let second = observe_path("/definitely-missing/repx-b").identity();
        assert!(first.starts_with("missing:sha256:"));
        assert_ne!(first, second);
    }

    #[test]
    fn unavailable_session_paths_are_normalized() {
        let first = observe_path("/tmp/tmp.ABCDEF/src/gone").identity();
        let second = observe_path("/tmp/tmp.XYZ123/src/gone").identity();
        assert_eq!(first, second);

        let compiler_first = observe_path("/tmp/ccABCDEF.s").identity();
        let compiler_second = observe_path("/tmp/ccUVWXYZ.s").identity();
        assert_eq!(compiler_first, compiler_second);
    }

    #[test]
    fn watched_paths_respect_directory_boundaries() {
        assert!(is_path_within("/tmp/build/out", "/tmp/build"));
        assert!(!is_path_within("/tmp/build-evil/out", "/tmp/build"));
    }
}
