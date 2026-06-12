//! Determinism harness: repeated-trace stability measurement.
//!
//! Runs a command under `repx trace` N times in a freshly-reset workspace,
//! collects attestations, and reports root stability and leaf-set Jaccard.
//! Designed as a permanent CI artifact — for a system whose core claim is
//! "same build, same root," root-stability regression testing is as
//! important as the unit test suite.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::fs;

use crate::attestation::{Attestation, AttestedOutput, OutputSelection};
use crate::merkle;
use crate::stability;
use crate::{canonicalize, slice, tracer, workspace};

/// Configuration for a determinism experiment.
pub struct HarnessConfig {
    /// Number of repeated trace runs.
    pub runs: usize,
    /// Directories to monitor system-wide (watch mode).
    pub watch_dirs: Vec<PathBuf>,
    /// Explicit artifact files to attest.
    pub artifacts: Vec<PathBuf>,
    /// Directories whose changed files should be attested.
    pub output_roots: Vec<PathBuf>,
    /// Produce attestations even if the eBPF ring dropped events.
    pub allow_dropped_events: bool,
    /// The command to trace repeatedly.
    pub command: Vec<String>,
    /// Directory in which to store run attestations (optional).
    pub output_dir: Option<PathBuf>,
}

/// Result of a single harness run.
struct RunOutcome {
    attestation: Attestation,
    path: String,
    dropped_events: u64,
}

/// Run the determinism harness and return a stability report.
pub fn run_harness(config: &HarnessConfig, out: &mut dyn Write) -> Result<()> {
    if config.runs < 2 {
        bail!("determinism harness requires at least 2 runs (got {})", config.runs);
    }

    let workspace_root = std::env::current_dir()?;
    let watch_prefixes: Vec<String> = config
        .watch_dirs
        .iter()
        .map(|dir| {
            std::fs::canonicalize(dir)
                .unwrap_or_else(|_| dir.clone())
                .to_string_lossy()
                .into_owned()
        })
        .collect();

    writeln!(
        out,
        "repx determinism harness — {} runs",
        config.runs
    )?;
    writeln!(out, "  Command: {}", format_command(&config.command))?;
    if !config.output_roots.is_empty() {
        writeln!(out, "  Output roots: {:?}", config.output_roots)?;
    }
    if !config.artifacts.is_empty() {
        writeln!(out, "  Artifacts: {:?}", config.artifacts)?;
    }
    writeln!(out)?;

    let output_dir = config
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("repx-harness-output"));
    fs::create_dir_all(&output_dir)?;

    let mut outcomes: Vec<RunOutcome> = Vec::with_capacity(config.runs);

    for run_index in 1..=config.runs {
        write!(out, "  Run {}/{} ... ", run_index, config.runs)?;
        let _ = out.flush();

        let run_att_path = output_dir.join(format!("run-{:03}-attestation.json", run_index));

        let before = workspace::snapshot(&workspace_root)?;
        let trace_result = tracer::trace_command(&config.command, &config.watch_dirs)?;
        let after = workspace::snapshot(&workspace_root)?;

        if trace_result.dropped_events > 0 {
            if config.allow_dropped_events {
                write!(
                    out,
                    "WARNING: {} dropped, ",
                    trace_result.dropped_events
                )?;
            } else {
                writeln!(out, "FAILED ({} events dropped)", trace_result.dropped_events)?;
                bail!(
                    "Run {} dropped {} events. Use --allow-dropped-events to continue anyway.",
                    run_index,
                    trace_result.dropped_events
                );
            }
        }

        let selected_outputs = workspace::select_outputs(
            &before,
            &after,
            &workspace_root,
            &config.artifacts,
            &config.output_roots,
        )?;

        let canonical = if selected_outputs.outputs.is_empty() {
            canonicalize::canonicalize_events(
                trace_result.events,
                trace_result.root_process,
                &watch_prefixes,
            )?
        } else {
            slice::canonicalize_output_slice(
                trace_result.events,
                trace_result.root_process,
                &selected_outputs.outputs,
            )?
        };

        let tree = merkle::build_merkle_tree(&canonical);
        let attestation = Attestation::new_with_outputs(
            tree,
            &config.command,
            output_selection_metadata(
                &workspace_root,
                &config.artifacts,
                &config.output_roots,
                &selected_outputs,
            ),
            attested_outputs_metadata(&workspace_root, &selected_outputs.outputs),
        );

        attestation
            .write_to_file(&run_att_path)
            .with_context(|| format!("writing attestation to {}", run_att_path.display()))?;

        let short_root = &attestation.root_hash[..16.min(attestation.root_hash.len())];
        writeln!(
            out,
            "root={}... leaf_count={}",
            short_root,
            attestation.tree.leaf_count
        )?;

        outcomes.push(RunOutcome {
            attestation,
            path: run_att_path.to_string_lossy().into_owned(),
            dropped_events: trace_result.dropped_events,
        });
    }

    writeln!(out)?;

    // Run stability analysis across all collected attestations.
    let inputs: Vec<(String, Attestation)> = outcomes
        .iter()
        .map(|o| (o.path.clone(), o.attestation.clone()))
        .collect();

    let report = stability::analyze(&inputs)?;

    writeln!(
        out,
        "Attestation root stability: {}/{} ({:.1}%)",
        report.root_matches,
        report.run_count,
        percentage(report.root_matches, report.run_count)
    )?;
    writeln!(
        out,
        "Process root stability:    {}/{} ({:.1}%)",
        report.process_root_matches,
        report.run_count,
        percentage(report.process_root_matches, report.run_count)
    )?;
    writeln!(
        out,
        "Leaf-set Jaccard:          min {:.6}, mean {:.6}",
        report.minimum_leaf_jaccard, report.mean_leaf_jaccard
    )?;

    if report.root_matches < report.run_count {
        writeln!(out)?;
        writeln!(out, "Mismatched runs:")?;
        for run in report.runs.iter().filter(|r| !r.root_match) {
            writeln!(
                out,
                "  {} (process_root={:?}, jaccard={:.6}, missing={}, added={})",
                run.path,
                if run.process_root_match {
                    "match"
                } else {
                    "changed"
                },
                run.leaf_jaccard,
                run.missing_leaves,
                run.added_leaves
            )?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "WARNING: {} of {} runs produced a different attestation root.",
            report.run_count - report.root_matches,
            report.run_count
        )?;
    } else {
        writeln!(out)?;
        writeln!(
            out,
            "All {} runs produced identical attestation roots.",
            report.run_count
        )?;
    }

    let total_dropped: u64 = outcomes.iter().map(|o| o.dropped_events).sum();
    if total_dropped > 0 {
        writeln!(
            out,
            "Total dropped events across {} runs: {}",
            config.runs, total_dropped
        )?;
    }

    Ok(())
}

fn output_selection_metadata(
    workspace_root: &Path,
    artifacts: &[PathBuf],
    output_roots: &[PathBuf],
    selected: &workspace::SelectedOutputs,
) -> OutputSelection {
    let mode = match selected.mode {
        workspace::OutputMode::Inferred => "inferred",
        workspace::OutputMode::Explicit => "explicit",
    };

    let mut selection = OutputSelection {
        mode: mode.to_string(),
        artifacts: artifacts
            .iter()
            .map(|p| metadata_path(workspace_root, p))
            .collect(),
        output_roots: output_roots
            .iter()
            .map(|p| metadata_path(workspace_root, p))
            .collect(),
    };
    selection.artifacts.sort();
    selection.output_roots.sort();
    selection
}

fn attested_outputs_metadata(
    workspace_root: &Path,
    outputs: &[workspace::OutputFile],
) -> Vec<AttestedOutput> {
    outputs
        .iter()
        .map(|o| AttestedOutput {
            path: workspace::display_path(workspace_root, &o.path),
            hash: o.hash.clone(),
        })
        .collect()
}

fn metadata_path(workspace_root: &Path, path: &Path) -> String {
    if path.is_absolute() {
        workspace::display_path(workspace_root, &path.to_string_lossy())
    } else {
        path.to_string_lossy().into_owned()
    }
}

fn format_command(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| shell_display_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_display_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | '=' | ':' | '+'))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\"'\"'"))
    }
}

fn percentage(matches: usize, total: usize) -> f64 {
    matches as f64 * 100.0 / total as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_requires_at_least_two_runs() {
        let config = HarnessConfig {
            runs: 1,
            watch_dirs: vec![],
            artifacts: vec![],
            output_roots: vec![],
            allow_dropped_events: false,
            command: vec!["true".to_string()],
            output_dir: None,
        };
        let mut out: Vec<u8> = Vec::new();
        let result = run_harness(&config, &mut out);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("at least 2 runs"),
            "expected 'at least 2 runs' error"
        );
    }
}
