use anyhow::{bail, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::file_identity::hash_file_contents;

#[derive(Debug, Clone)]
pub struct Snapshot {
    entries: HashMap<String, SnapshotEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotEntry {
    kind: EntryKind,
    hash: Option<String>,
    target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryKind {
    File,
    Symlink,
    Directory,
}

#[derive(Debug, Clone)]
pub struct OutputFile {
    pub path: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputMode {
    Inferred,
    Explicit,
}

#[derive(Debug, Clone)]
pub struct SelectedOutputs {
    pub mode: OutputMode,
    pub outputs: Vec<OutputFile>,
}

pub fn snapshot(root: &Path) -> Result<Snapshot> {
    let mut entries = HashMap::new();
    let mut seen_dirs = HashSet::new();
    walk(root, root, &mut entries, &mut seen_dirs)?;
    Ok(Snapshot { entries })
}

pub fn changed_outputs(before: &Snapshot, after: &Snapshot) -> Vec<OutputFile> {
    let mut outputs = Vec::new();

    for (path, entry) in &after.entries {
        if entry.kind != EntryKind::File {
            continue;
        }

        let changed = before.entries.get(path) != Some(entry);
        if changed {
            if let Some(hash) = &entry.hash {
                outputs.push(OutputFile {
                    path: path.clone(),
                    hash: hash.clone(),
                });
            }
        }
    }

    outputs.sort_by(|a, b| a.path.cmp(&b.path));
    outputs.dedup_by(|a, b| a.path == b.path && a.hash == b.hash);
    outputs
}

pub fn select_outputs(
    before: &Snapshot,
    after: &Snapshot,
    workspace_root: &Path,
    artifacts: &[PathBuf],
    output_roots: &[PathBuf],
) -> Result<SelectedOutputs> {
    let mode = if artifacts.is_empty() && output_roots.is_empty() {
        OutputMode::Inferred
    } else {
        OutputMode::Explicit
    };

    if mode == OutputMode::Inferred {
        return Ok(SelectedOutputs {
            mode,
            outputs: changed_outputs(before, after),
        });
    }

    let mut outputs = Vec::new();
    let changed = changed_outputs(before, after);
    let roots: Vec<PathBuf> = output_roots
        .iter()
        .map(|root| absolutize(workspace_root, root))
        .collect();

    for output in changed {
        let path = PathBuf::from(&output.path);
        if roots.iter().any(|root| path.starts_with(root)) {
            outputs.push(output);
        }
    }

    for artifact in artifacts {
        let path = absolutize(workspace_root, artifact);
        let key = path.to_string_lossy().into_owned();
        let Some(entry) = after.entries.get(&key) else {
            bail!(
                "explicit artifact does not exist after build: {}",
                artifact.display()
            );
        };
        if entry.kind != EntryKind::File {
            bail!(
                "explicit artifact is not a regular file: {}",
                artifact.display()
            );
        }
        let Some(hash) = &entry.hash else {
            bail!(
                "explicit artifact could not be hashed: {}",
                artifact.display()
            );
        };
        outputs.push(OutputFile {
            path: key,
            hash: hash.clone(),
        });
    }

    outputs.sort_by(|a, b| a.path.cmp(&b.path));
    outputs.dedup_by(|a, b| a.path == b.path && a.hash == b.hash);

    Ok(SelectedOutputs { mode, outputs })
}

pub fn display_path(workspace_root: &Path, path: &str) -> String {
    let path = Path::new(path);
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn absolutize(workspace_root: &Path, path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    };
    normalize_path(&absolute)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn walk(
    actual: &Path,
    logical: &Path,
    entries: &mut HashMap<String, SnapshotEntry>,
    seen_dirs: &mut HashSet<PathBuf>,
) -> Result<()> {
    let file_type = match fs::symlink_metadata(actual) {
        Ok(meta) => meta.file_type(),
        Err(_) => return Ok(()),
    };

    let logical_key = logical.to_string_lossy().into_owned();

    if file_type.is_symlink() {
        let target = fs::read_link(actual).ok();
        entries.insert(
            logical_key,
            SnapshotEntry {
                kind: EntryKind::Symlink,
                hash: None,
                target: target
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
            },
        );

        if let Ok(meta) = fs::metadata(actual) {
            if meta.is_file() {
                if let Some(hash) = hash_file_contents(actual) {
                    entries.insert(
                        logical.to_string_lossy().into_owned(),
                        SnapshotEntry {
                            kind: EntryKind::File,
                            hash: Some(hash),
                            target: target.map(|path| path.to_string_lossy().into_owned()),
                        },
                    );
                }
            }
        }
        return Ok(());
    }

    if file_type.is_dir() {
        let name = actual.file_name().and_then(|name| name.to_str());
        if matches!(name, Some(".git")) {
            return Ok(());
        }

        entries.insert(
            logical_key,
            SnapshotEntry {
                kind: EntryKind::Directory,
                hash: None,
                target: None,
            },
        );

        let canonical = fs::canonicalize(actual)?;
        if seen_dirs.insert(canonical) {
            walk_dir(actual, logical, entries, seen_dirs)?;
        }
    } else if file_type.is_file() {
        if let Some(hash) = hash_file_contents(actual) {
            entries.insert(
                logical_key,
                SnapshotEntry {
                    kind: EntryKind::File,
                    hash: Some(hash),
                    target: None,
                },
            );
        }
    }

    Ok(())
}

fn walk_dir(
    actual: &Path,
    logical: &Path,
    entries: &mut HashMap<String, SnapshotEntry>,
    seen_dirs: &mut HashSet<PathBuf>,
) -> Result<()> {
    let mut children = Vec::new();
    for child in fs::read_dir(actual)? {
        children.push(child?);
    }
    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let child_actual = child.path();
        let child_logical = logical.join(child.file_name());
        walk(&child_actual, &child_logical, entries, seen_dirs)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "repx-workspace-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn detects_changed_regular_file() {
        let root = unique_dir("regular");
        fs::create_dir_all(&root).unwrap();

        let before = snapshot(&root).unwrap();
        fs::write(root.join("artifact.txt"), b"artifact").unwrap();
        let after = snapshot(&root).unwrap();

        let outputs = changed_outputs(&before, &after);
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].path.ends_with("artifact.txt"));

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn follows_symlinked_output_file() {
        let root = unique_dir("symlink-root");
        let target = unique_dir("symlink-target");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&target).unwrap();

        let before = snapshot(&root).unwrap();
        fs::write(target.join("artifact.txt"), b"artifact").unwrap();
        std::os::unix::fs::symlink(target.join("artifact.txt"), root.join("artifact-link"))
            .unwrap();
        let after = snapshot(&root).unwrap();

        let outputs = changed_outputs(&before, &after);
        assert!(outputs
            .iter()
            .any(|output| output.path.ends_with("artifact-link")));

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&target);
    }

    #[test]
    fn explicit_artifact_is_selected_even_if_unchanged() {
        let root = unique_dir("explicit-artifact");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("artifact.txt"), b"artifact").unwrap();

        let before = snapshot(&root).unwrap();
        let after = snapshot(&root).unwrap();

        let selected = select_outputs(
            &before,
            &after,
            &root,
            &[PathBuf::from("artifact.txt")],
            &[],
        )
        .unwrap();

        assert_eq!(selected.mode, OutputMode::Explicit);
        assert_eq!(selected.outputs.len(), 1);
        assert!(selected.outputs[0].path.ends_with("artifact.txt"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn output_root_filters_changed_outputs() {
        let root = unique_dir("output-root");
        fs::create_dir_all(root.join("dist")).unwrap();
        fs::create_dir_all(root.join("logs")).unwrap();

        let before = snapshot(&root).unwrap();
        fs::write(root.join("dist/app"), b"app").unwrap();
        fs::write(root.join("logs/build.log"), b"log").unwrap();
        let after = snapshot(&root).unwrap();

        let selected =
            select_outputs(&before, &after, &root, &[], &[PathBuf::from("dist")]).unwrap();

        assert_eq!(selected.outputs.len(), 1);
        assert!(selected.outputs[0].path.ends_with("dist/app"));

        let _ = fs::remove_dir_all(&root);
    }
}
