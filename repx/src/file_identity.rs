use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const SYSTEM_STATE_SENTINEL: &str =
    "SYSTEM_STATE:0000000000000000000000000000000000000000000000000000000000000000";
/// Identity of empty file contents (sha256 of zero bytes).
pub const EMPTY_CONTENT_HASH: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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
const MAX_NORMALIZED_CONTROL_FILE_SIZE: u64 = 16 * 1024 * 1024;
/// Go action-cache index entries are fixed-size records:
/// `v1 <actionID:64 hex> <outputID:64 hex> <size:%20d> <unixnano:%20d>\n`.
const GO_CACHE_ENTRY_SIZE: u64 = 175;

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

    if metadata.len() <= MAX_NORMALIZED_CONTROL_FILE_SIZE && is_go_import_config_path(path) {
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        if file.read_to_end(&mut contents).is_err() {
            return FileObservation::Unreadable(path_hash);
        }
        if let Some(normalized) = normalize_go_import_config(&contents) {
            let mut hasher = Sha256::new();
            hasher.update(b"repx-go-importcfg-v1\0");
            hasher.update(normalized);
            return FileObservation::Content(format!("sha256:{:x}", hasher.finalize()));
        }
        if file.seek(SeekFrom::Start(0)).is_err() {
            return FileObservation::Unreadable(path_hash);
        }
    }

    if metadata.len() == GO_CACHE_ENTRY_SIZE && is_go_cache_entry_path(path) {
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        if file.read_to_end(&mut contents).is_err() {
            return FileObservation::Unreadable(path_hash);
        }
        if let Some(normalized) = normalize_go_cache_entry(&contents) {
            let mut hasher = Sha256::new();
            hasher.update(b"repx-go-cache-entry-v1\0");
            hasher.update(normalized);
            return FileObservation::Content(format!("sha256:{:x}", hasher.finalize()));
        }
        if file.seek(SeekFrom::Start(0)).is_err() {
            return FileObservation::Unreadable(path_hash);
        }
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
        || is_go_telemetry_path(path)
}

/// Go telemetry state lives under `os.UserConfigDir()/go/telemetry`. Every
/// toolchain process maps its counter file read-write, and the counters
/// accumulate across invocations: machine state, not a build input.
fn is_go_telemetry_path(path: &str) -> bool {
    path.contains("/go/telemetry/")
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
        } else if under_temp && is_go_work_dir_component(&value) {
            normalized.push("<go-work>");
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

fn is_go_import_config_path(path: &str) -> bool {
    let path = Path::new(path);
    let is_import_config = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "importcfg" | "importcfg.link"));
    is_import_config
        && path.components().any(|component| {
            component
                .as_os_str()
                .to_str()
                .is_some_and(is_go_work_dir_component)
        })
}

fn is_go_work_dir_component(component: &str) -> bool {
    component.strip_prefix("go-build").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    })
}

fn normalize_go_import_config(contents: &[u8]) -> Option<Vec<u8>> {
    let contents = std::str::from_utf8(contents).ok()?;
    let mut normalized = String::with_capacity(contents.len());
    let mut changed = false;

    for line_with_ending in contents.split_inclusive('\n') {
        let (line, ending) = line_with_ending
            .strip_suffix('\n')
            .map_or((line_with_ending, ""), |line| (line, "\n"));

        if let Some(rest) = line
            .strip_prefix("packagefile ")
            .or_else(|| line.strip_prefix("packageshlib "))
        {
            let equals = rest.find('=')?;
            let value_offset = line.len() - rest.len() + equals + 1;
            let value = &line[value_offset..];
            if let Some(work_relative) = normalize_go_work_path(value) {
                normalized.push_str(&line[..value_offset]);
                normalized.push_str(&work_relative);
                normalized.push_str(ending);
                changed = true;
                continue;
            }
        } else if !(line.is_empty()
            || line == "# import config"
            || line.starts_with("importmap ")
            || line.starts_with("modinfo "))
        {
            return None;
        }

        normalized.push_str(line);
        normalized.push_str(ending);
    }

    changed.then(|| normalized.into_bytes())
}

fn is_go_cache_entry_path(path: &str) -> bool {
    let path = Path::new(path);
    let Some(hash) = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix("-a"))
    else {
        return false;
    };
    hash.len() == 64
        && hash.bytes().all(is_lower_hex)
        && path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            == Some(&hash[..2])
}

fn is_lower_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

/// Hash a Go action-cache index entry with its put timestamp zeroed. The
/// timestamp is wall-clock cache bookkeeping that Go rewrites on every build;
/// the action and output identifiers carry the semantic content.
fn normalize_go_cache_entry(contents: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(contents).ok()?;
    let rest = text.strip_prefix("v1 ")?.strip_suffix('\n')?;
    if rest.len() != 64 + 1 + 64 + 1 + 20 + 1 + 20 {
        return None;
    }

    let (action_id, rest) = rest.split_at(64);
    let rest = rest.strip_prefix(' ')?;
    let (output_id, rest) = rest.split_at(64);
    let rest = rest.strip_prefix(' ')?;
    let (size, rest) = rest.split_at(20);
    let timestamp = rest.strip_prefix(' ')?;

    let is_padded_decimal = |field: &str| {
        let digits = field.trim_start_matches(' ');
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !(action_id.bytes().all(is_lower_hex)
        && output_id.bytes().all(is_lower_hex)
        && is_padded_decimal(size)
        && is_padded_decimal(timestamp))
    {
        return None;
    }

    Some(format!("v1 {action_id} {output_id} {size} {:>20}\n", 0).into_bytes())
}

fn normalize_go_work_path(path: &str) -> Option<String> {
    let marker = "/go-build";
    let start = path.rfind(marker)?;
    let suffix = &path[start + marker.len()..];
    let digit_count = suffix
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_count == 0 || suffix.as_bytes().get(digit_count) != Some(&b'/') {
        return None;
    }

    Some(format!("$WORK{}", &suffix[digit_count..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("repx-file-identity-{name}-{nonce}"))
    }

    #[test]
    fn system_state_matching_respects_path_boundaries() {
        assert!(is_system_state("/proc/cpuinfo"));
        assert!(is_system_state("/etc/os-release"));
        assert!(!is_system_state("/etc/os-release-evil"));
        assert!(!is_system_state("/proc-evil/cpuinfo"));
    }

    #[test]
    fn go_telemetry_state_is_system_state() {
        assert!(is_system_state(
            "/root/.config/go/telemetry/local/go@go1.25.7-go1.25.7-linux-amd64-2026-06-12.v1.count"
        ));
        assert!(is_system_state("/home/user/.config/go/telemetry/mode"));
        assert!(!is_system_state("/srv/go/telemetry-archive/data"));
        assert!(!is_system_state("/srv/django/telemetry/data"));
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

    #[test]
    fn go_import_configs_normalize_random_work_roots() {
        let first = b"# import config\npackagefile fmt=/tmp/go-tmp/go-build123/b002/_pkg_.a\n";
        let second = b"# import config\npackagefile fmt=/tmp/go-tmp/go-build987/b002/_pkg_.a\n";

        assert_eq!(
            normalize_go_import_config(first),
            normalize_go_import_config(second)
        );
        assert_eq!(
            normalize_go_import_config(first),
            Some(b"# import config\npackagefile fmt=$WORK/b002/_pkg_.a\n".to_vec())
        );
    }

    #[test]
    fn go_import_configs_preserve_stable_dependency_paths() {
        let first = b"packagefile fmt=/nix/store/first/fmt.a\nmodinfo \"same\"\n";
        let second = b"packagefile fmt=/nix/store/second/fmt.a\nmodinfo \"same\"\n";

        assert_eq!(normalize_go_import_config(first), None);
        assert_eq!(normalize_go_import_config(second), None);
    }

    #[test]
    fn go_import_config_detection_is_path_scoped() {
        assert!(is_go_import_config_path(
            "/tmp/go-tmp/go-build123/b001/importcfg.link"
        ));
        assert!(!is_go_import_config_path("/workspace/importcfg"));
        assert!(!is_go_import_config_path(
            "/tmp/go-tmp/go-builder/b001/importcfg"
        ));
    }

    #[test]
    fn unavailable_go_work_paths_are_normalized() {
        let first = observe_path("/tmp/go-tmp/go-build123/b001/gone").identity();
        let second = observe_path("/tmp/go-tmp/go-build987654/b001/gone").identity();
        assert!(first.starts_with("missing:sha256:"));
        assert_eq!(first, second);

        let work_root_first = observe_path("/tmp/go-tmp/go-build123").identity();
        let work_root_second = observe_path("/tmp/go-tmp/go-build987654").identity();
        assert_eq!(work_root_first, work_root_second);

        let unrelated = observe_path("/tmp/go-tmp/go-builder/b001/gone").identity();
        assert_ne!(first, unrelated);
    }

    #[test]
    fn go_cache_entries_normalize_put_timestamps() {
        let action_id = "a".repeat(64);
        let output_id = "b".repeat(64);
        let first = format!(
            "v1 {action_id} {output_id} {:>20} {:>20}\n",
            0, 1111111111111111111u64
        );
        let second = format!(
            "v1 {action_id} {output_id} {:>20} {:>20}\n",
            0, 2222222222222222222u64
        );

        assert_eq!(
            normalize_go_cache_entry(first.as_bytes()),
            normalize_go_cache_entry(second.as_bytes())
        );
        assert_eq!(
            normalize_go_cache_entry(first.as_bytes()),
            Some(format!("v1 {action_id} {output_id} {:>20} {:>20}\n", 0, 0).into_bytes())
        );

        let other_action = format!("v1 {output_id} {output_id} {:>20} {:>20}\n", 0, 0);
        assert_ne!(
            normalize_go_cache_entry(first.as_bytes()),
            normalize_go_cache_entry(other_action.as_bytes())
        );

        assert_eq!(normalize_go_cache_entry(b"v1 not a cache entry\n"), None);
        let truncated = &first.as_bytes()[..first.len() - 1];
        assert_eq!(normalize_go_cache_entry(truncated), None);
    }

    #[test]
    fn go_cache_entry_detection_requires_matching_shard_dir() {
        let hash = "a1".to_string() + &"c".repeat(62);
        assert!(is_go_cache_entry_path(&format!("/cache/a1/{hash}-a")));
        assert!(!is_go_cache_entry_path(&format!("/cache/ff/{hash}-a")));
        assert!(!is_go_cache_entry_path(&format!("/cache/a1/{hash}-d")));
        assert!(!is_go_cache_entry_path("/cache/a1/short-a"));
    }

    #[test]
    fn observed_go_cache_entries_share_an_identity_across_timestamps() {
        let root = unique_test_dir("go-cache-entry");
        let action_id = "a1".to_string() + &"c".repeat(62);
        let output_id = "d".repeat(64);
        let first = root.join(format!("one/a1/{action_id}-a"));
        let second = root.join(format!("two/a1/{action_id}-a"));
        fs::create_dir_all(first.parent().unwrap()).unwrap();
        fs::create_dir_all(second.parent().unwrap()).unwrap();
        fs::write(
            &first,
            format!(
                "v1 {action_id} {output_id} {:>20} {:>20}\n",
                0, 1111111111111111111u64
            ),
        )
        .unwrap();
        fs::write(
            &second,
            format!(
                "v1 {action_id} {output_id} {:>20} {:>20}\n",
                0, 2222222222222222222u64
            ),
        )
        .unwrap();

        assert_eq!(
            observe_path(&first.to_string_lossy()),
            observe_path(&second.to_string_lossy())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn observed_go_import_configs_share_an_identity_across_work_roots() {
        let root = unique_test_dir("go-importcfg");
        let first = root.join("go-build123/b001/importcfg");
        let second = root.join("go-build987/b001/importcfg");
        fs::create_dir_all(first.parent().unwrap()).unwrap();
        fs::create_dir_all(second.parent().unwrap()).unwrap();
        fs::write(
            &first,
            b"# import config\npackagefile fmt=/tmp/go-tmp/go-build123/b002/_pkg_.a\n",
        )
        .unwrap();
        fs::write(
            &second,
            b"# import config\npackagefile fmt=/tmp/go-tmp/go-build987/b002/_pkg_.a\n",
        )
        .unwrap();

        assert_eq!(
            observe_path(&first.to_string_lossy()),
            observe_path(&second.to_string_lossy())
        );
        let _ = fs::remove_dir_all(root);
    }
}
