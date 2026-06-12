mod attestation;
mod canonicalize;
mod file_identity;
mod harness;
mod merkle;
mod slice;
mod stability;
mod tracer;
mod workspace;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "repx",
    about = "Reproducible process attestations for supply chain security",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Trace a build command and produce an attestation.
    Trace {
        /// Output path for the attestation file.
        #[arg(short, long, default_value = "repx-attestation.json")]
        output: PathBuf,

        /// Optional path for a JSON dump of the canonical operations list.
        /// Useful for asserting properties not visible in the attestation
        /// (which only stores merkle hashes).
        #[arg(long = "dump-ops", value_name = "PATH")]
        dump_ops: Option<PathBuf>,

        /// Directories to monitor system-wide (any process touching files here is recorded).
        #[arg(short, long = "watch", value_name = "DIR")]
        watch_dirs: Vec<PathBuf>,

        /// Explicit artifact file to attest. May be repeated.
        #[arg(long = "artifact", value_name = "PATH")]
        artifacts: Vec<PathBuf>,

        /// Directory whose changed files should be attested. May be repeated.
        #[arg(long = "output-root", value_name = "DIR")]
        output_roots: Vec<PathBuf>,

        /// Produce an attestation even if the eBPF event ring dropped events.
        #[arg(long)]
        allow_dropped_events: bool,

        /// The command to trace (everything after --).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Verify a build by re-running it and comparing against an existing attestation.
    Verify {
        /// Path to the expected attestation file.
        #[arg(short, long)]
        attestation: PathBuf,

        /// Trusted root hash supplied out of band. Detects attestation-file replacement.
        #[arg(long = "expected-root", value_name = "SHA256")]
        expected_root: Option<String>,

        /// Directories to monitor system-wide (must match the dirs used during trace).
        #[arg(short, long = "watch", value_name = "DIR")]
        watch_dirs: Vec<PathBuf>,

        /// Explicit artifact file to attest. Must match trace-time selection.
        #[arg(long = "artifact", value_name = "PATH")]
        artifacts: Vec<PathBuf>,

        /// Directory whose changed files should be attested. Must match trace-time selection.
        #[arg(long = "output-root", value_name = "DIR")]
        output_roots: Vec<PathBuf>,

        /// The command to re-run for verification.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Explain what an attestation covers in human-readable terms.
    Explain {
        /// Path to the attestation file.
        #[arg(short, long)]
        attestation: PathBuf,
    },

    /// Compare two attestations and show semantic differences.
    Diff {
        /// Expected/baseline attestation.
        expected: PathBuf,

        /// Actual/candidate attestation.
        actual: PathBuf,
    },

    /// Measure root and operation-set stability across repeated traces.
    Stability {
        /// Attestation files from repeated runs; the first is the baseline.
        #[arg(required = true, num_args = 2..)]
        attestations: Vec<PathBuf>,

        /// Emit the report as JSON.
        #[arg(long)]
        json: bool,

        /// Exit unsuccessfully unless every attestation root matches.
        #[arg(long)]
        strict: bool,
    },

    /// Run a command N times and report attestation-root stability.
    Harness {
        /// Number of repeated traces (minimum 2).
        #[arg(short, long, default_value = "20")]
        runs: usize,

        /// Output path for the JSON stability report (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Directory to store per-run attestations.
        #[arg(long = "attestation-dir", value_name = "DIR", default_value = "repx-harness-output")]
        attestation_dir: PathBuf,

        /// Directories to monitor system-wide.
        #[arg(short, long = "watch", value_name = "DIR")]
        watch_dirs: Vec<PathBuf>,

        /// Explicit artifact file to attest. May be repeated.
        #[arg(long = "artifact", value_name = "PATH")]
        artifacts: Vec<PathBuf>,

        /// Directory whose changed files should be attested. May be repeated.
        #[arg(long = "output-root", value_name = "DIR")]
        output_roots: Vec<PathBuf>,

        /// Produce attestations even if the eBPF ring dropped events.
        #[arg(long)]
        allow_dropped_events: bool,

        /// The command to trace (everything after --).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Trace {
            output,
            dump_ops,
            watch_dirs,
            artifacts,
            output_roots,
            allow_dropped_events,
            command,
        } => {
            log::info!("Tracing command: {:?}", command);

            let workspace_root = std::env::current_dir()?;
            let before = workspace::snapshot(&workspace_root)?;
            let result = tracer::trace_command(&command, &watch_dirs)?;
            let after = workspace::snapshot(&workspace_root)?;
            let selected_outputs = workspace::select_outputs(
                &before,
                &after,
                &workspace_root,
                &artifacts,
                &output_roots,
            )?;
            let watch_prefixes: Vec<String> = watch_dirs
                .iter()
                .map(|dir| {
                    std::fs::canonicalize(dir)
                        .unwrap_or_else(|_| dir.clone())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();

            if result.dropped_events > 0 {
                if allow_dropped_events {
                    eprintln!(
                        "WARNING: {} events dropped (ring buffer full). \
                         Attestation may be incomplete.",
                        result.dropped_events
                    );
                } else {
                    eprintln!(
                        "FAILED: {} events dropped during trace. \
                         Use --allow-dropped-events to write an incomplete attestation anyway.",
                        result.dropped_events
                    );
                    std::process::exit(1);
                }
            }

            let canonical = if selected_outputs.outputs.is_empty() {
                canonicalize::canonicalize_events(
                    result.events,
                    result.root_process,
                    &watch_prefixes,
                )?
            } else {
                slice::canonicalize_output_slice(
                    result.events,
                    result.root_process,
                    &selected_outputs.outputs,
                )?
            };

            if let Some(ref path) = dump_ops {
                let file = std::fs::File::create(path)?;
                serde_json::to_writer_pretty(file, &canonical)?;
            }

            let tree = merkle::build_merkle_tree(&canonical);
            let att = attestation::Attestation::new_with_outputs(
                tree,
                &command,
                output_selection_metadata(
                    &selected_outputs.mode,
                    &workspace_root,
                    &artifacts,
                    &output_roots,
                ),
                attested_outputs_metadata(&workspace_root, &selected_outputs.outputs),
            );

            att.write_to_file(&output)?;

            println!("Attestation root: {}", att.root_hash);
            println!("Written to: {}", output.display());
            if !selected_outputs.outputs.is_empty() {
                println!("Workspace outputs: {}", selected_outputs.outputs.len());
            }

            Ok(())
        }
        Commands::Verify {
            attestation,
            expected_root,
            watch_dirs,
            artifacts,
            output_roots,
            command,
        } => {
            log::info!("Verifying command: {:?}", command);

            let expected = attestation::Attestation::read_from_file(&attestation)?;
            if let Some(pinned_root) = expected_root {
                if expected.root_hash != pinned_root {
                    bail!(
                        "attestation root does not match --expected-root\n  expected: {}\n  file:     {}",
                        pinned_root,
                        expected.root_hash
                    );
                }
            }
            if expected.command != command {
                bail!(
                    "command differs from attestation\n  attestation: {}\n  current:     {}",
                    format_command(&expected.command),
                    format_command(&command)
                );
            }

            let workspace_root = std::env::current_dir()?;
            validate_output_selection(&expected, &workspace_root, &artifacts, &output_roots)?;
            let before = workspace::snapshot(&workspace_root)?;
            let result = tracer::trace_command(&command, &watch_dirs)?;
            let after = workspace::snapshot(&workspace_root)?;
            let selected_outputs = workspace::select_outputs(
                &before,
                &after,
                &workspace_root,
                &artifacts,
                &output_roots,
            )?;
            let watch_prefixes: Vec<String> = watch_dirs
                .iter()
                .map(|dir| {
                    std::fs::canonicalize(dir)
                        .unwrap_or_else(|_| dir.clone())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();

            // Fail verification if events were dropped — integrity cannot
            // be guaranteed with missing data.
            if result.dropped_events > 0 {
                eprintln!(
                    "FAILED: {} events dropped during verification. \
                     Cannot guarantee attestation integrity.",
                    result.dropped_events
                );
                std::process::exit(1);
            }

            let canonical = if selected_outputs.outputs.is_empty() {
                canonicalize::canonicalize_events(
                    result.events,
                    result.root_process,
                    &watch_prefixes,
                )?
            } else {
                slice::canonicalize_output_slice(
                    result.events,
                    result.root_process,
                    &selected_outputs.outputs,
                )?
            };
            let tree = merkle::build_merkle_tree(&canonical);
            let actual = attestation::Attestation::new_with_outputs(
                tree,
                &command,
                output_selection_metadata(
                    &selected_outputs.mode,
                    &workspace_root,
                    &artifacts,
                    &output_roots,
                ),
                attested_outputs_metadata(&workspace_root, &selected_outputs.outputs),
            );

            if expected.root_hash == actual.root_hash {
                println!("VERIFIED: Attestation matches.");
                println!("Root hash: {}", actual.root_hash);
                Ok(())
            } else {
                eprintln!("MISMATCH: Attestation does not match.");
                eprintln!("  Expected: {}", expected.root_hash);
                eprintln!("  Actual:   {}", actual.root_hash);
                eprintln!();
                print_attestation_diff(&mut std::io::stderr(), &expected, &actual)?;

                std::process::exit(1);
            }
        }
        Commands::Explain { attestation } => {
            let att = attestation::Attestation::read_from_file(&attestation)?;
            explain_attestation(&mut std::io::stdout(), &att)?;
            Ok(())
        }
        Commands::Diff { expected, actual } => {
            let expected = attestation::Attestation::read_from_file(&expected)?;
            let actual = attestation::Attestation::read_from_file(&actual)?;
            print_attestation_diff(&mut std::io::stdout(), &expected, &actual)?;
            if expected.root_hash == actual.root_hash {
                Ok(())
            } else {
                std::process::exit(1);
            }
        }
        Commands::Stability {
            attestations,
            json,
            strict,
        } => {
            let inputs = attestations
                .iter()
                .map(|path| {
                    Ok((
                        path.display().to_string(),
                        attestation::Attestation::read_from_file(path)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let report = stability::analyze(&inputs)?;

            if json {
                serde_json::to_writer_pretty(std::io::stdout(), &report)?;
                println!();
            } else {
                stability::print_human(&mut std::io::stdout(), &report)?;
            }

            if strict && report.root_matches != report.run_count {
                std::process::exit(1);
            }
            Ok(())
        }
        Commands::Harness {
            runs,
            output,
            attestation_dir,
            watch_dirs,
            artifacts,
            output_roots,
            allow_dropped_events,
            command,
        } => {
            let config = harness::HarnessConfig {
                runs,
                watch_dirs,
                artifacts,
                output_roots,
                allow_dropped_events,
                command,
                output_dir: Some(attestation_dir),
            };

            if let Some(ref report_path) = output {
                let mut file = std::fs::File::create(report_path)?;
                harness::run_harness(&config, &mut file)?;
                println!("Report written to: {}", report_path.display());
            } else {
                harness::run_harness(&config, &mut std::io::stdout())?;
            }
            Ok(())
        }
    }
}

fn explain_attestation(out: &mut dyn Write, att: &attestation::Attestation) -> Result<()> {
    writeln!(out, "Root hash: {}", att.root_hash)?;
    writeln!(out, "Process-set root: {}", att.process_root)?;
    writeln!(out, "Predicate: {}", att.predicate_type)?;
    writeln!(out, "Command: {}", format_command(&att.command))?;
    writeln!(out, "Output selection: {}", att.output_selection.mode)?;

    if !att.output_selection.artifacts.is_empty() {
        writeln!(out, "Artifacts:")?;
        for artifact in &att.output_selection.artifacts {
            writeln!(out, "  - {}", artifact)?;
        }
    }

    if !att.output_selection.output_roots.is_empty() {
        writeln!(out, "Output roots:")?;
        for root in &att.output_selection.output_roots {
            writeln!(out, "  - {}", root)?;
        }
    }

    writeln!(out, "Outputs: {}", att.outputs.len())?;
    for output in &att.outputs {
        writeln!(out, "  - {} {}", output.hash, output.path)?;
    }

    writeln!(out, "Merkle leaves: {}", att.tree.leaf_count)?;
    writeln!(
        out,
        "Commitment semantics: sorted set of distinct covered operations"
    )?;
    Ok(())
}

fn print_attestation_diff(
    out: &mut dyn Write,
    expected: &attestation::Attestation,
    actual: &attestation::Attestation,
) -> Result<()> {
    if expected.root_hash == actual.root_hash {
        writeln!(out, "Root hash: matches ({})", expected.root_hash)?;
    } else {
        writeln!(out, "Root hash:")?;
        writeln!(out, "  expected: {}", expected.root_hash)?;
        writeln!(out, "  actual:   {}", actual.root_hash)?;
    }

    if expected.command != actual.command {
        writeln!(out, "Command changed:")?;
        writeln!(out, "  expected: {}", format_command(&expected.command))?;
        writeln!(out, "  actual:   {}", format_command(&actual.command))?;
    }

    if expected.output_selection != actual.output_selection {
        writeln!(out, "Output selection changed:")?;
        writeln!(out, "  expected mode: {}", expected.output_selection.mode)?;
        writeln!(out, "  actual mode:   {}", actual.output_selection.mode)?;
        print_string_list_delta(
            out,
            "artifact",
            &expected.output_selection.artifacts,
            &actual.output_selection.artifacts,
        )?;
        print_string_list_delta(
            out,
            "output root",
            &expected.output_selection.output_roots,
            &actual.output_selection.output_roots,
        )?;
    }

    print_output_delta(out, &expected.outputs, &actual.outputs)?;

    if expected.tree.leaf_count != actual.tree.leaf_count {
        writeln!(out, "Canonical op count changed:")?;
        writeln!(out, "  expected: {}", expected.tree.leaf_count)?;
        writeln!(out, "  actual:   {}", actual.tree.leaf_count)?;
    } else {
        writeln!(out, "Canonical op count: {}", expected.tree.leaf_count)?;
    }

    let operation_diff = merkle::diff_leaf_sets(&expected.tree, &actual.tree);
    if operation_diff.missing.is_empty() && operation_diff.added.is_empty() {
        writeln!(out, "Operation set: no differences")?;
    } else {
        writeln!(
            out,
            "Operation set changed: {} missing, {} added",
            operation_diff.missing.len(),
            operation_diff.added.len()
        )?;
        for hash in operation_diff.missing.iter().take(12) {
            writeln!(out, "  missing: {}", hash)?;
        }
        for hash in operation_diff.added.iter().take(12) {
            writeln!(out, "  added:   {}", hash)?;
        }
        let omitted = operation_diff.missing.len().saturating_sub(12)
            + operation_diff.added.len().saturating_sub(12);
        if omitted > 0 {
            writeln!(out, "  ... {} more", omitted)?;
        }
    }

    Ok(())
}

fn print_output_delta(
    out: &mut dyn Write,
    expected: &[attestation::AttestedOutput],
    actual: &[attestation::AttestedOutput],
) -> Result<()> {
    let expected_by_path = outputs_by_path(expected);
    let actual_by_path = outputs_by_path(actual);
    let paths: BTreeSet<&String> = expected_by_path
        .keys()
        .copied()
        .chain(actual_by_path.keys().copied())
        .collect();

    if paths.is_empty() {
        writeln!(out, "Outputs: none recorded")?;
        return Ok(());
    }

    let mut changed = 0usize;
    let mut missing = 0usize;
    let mut added = 0usize;

    for path in &paths {
        match (expected_by_path.get(*path), actual_by_path.get(*path)) {
            (Some(expected_hash), Some(actual_hash)) if expected_hash != actual_hash => {
                changed += 1;
            }
            (Some(_), None) => missing += 1,
            (None, Some(_)) => added += 1,
            _ => {}
        }
    }

    if changed == 0 && missing == 0 && added == 0 {
        writeln!(out, "Outputs: all {} match", paths.len())?;
        return Ok(());
    }

    writeln!(
        out,
        "Outputs changed: {} changed, {} missing, {} added",
        changed, missing, added
    )?;

    let mut shown = 0usize;
    for path in paths {
        match (expected_by_path.get(path), actual_by_path.get(path)) {
            (Some(expected_hash), Some(actual_hash)) if expected_hash != actual_hash => {
                writeln!(out, "  changed: {}", path)?;
                writeln!(out, "    expected: {}", expected_hash)?;
                writeln!(out, "    actual:   {}", actual_hash)?;
                shown += 1;
            }
            (Some(expected_hash), None) => {
                writeln!(out, "  missing: {} {}", expected_hash, path)?;
                shown += 1;
            }
            (None, Some(actual_hash)) => {
                writeln!(out, "  added:   {} {}", actual_hash, path)?;
                shown += 1;
            }
            _ => {}
        }

        if shown >= 20 {
            writeln!(out, "  ... more output differences omitted")?;
            break;
        }
    }

    Ok(())
}

fn outputs_by_path(outputs: &[attestation::AttestedOutput]) -> BTreeMap<&String, &String> {
    outputs
        .iter()
        .map(|output| (&output.path, &output.hash))
        .collect()
}

fn print_string_list_delta(
    out: &mut dyn Write,
    label: &str,
    expected: &[String],
    actual: &[String],
) -> Result<()> {
    let expected: BTreeSet<&String> = expected.iter().collect();
    let actual: BTreeSet<&String> = actual.iter().collect();

    for value in expected.difference(&actual) {
        writeln!(out, "  missing {}: {}", label, value)?;
    }
    for value in actual.difference(&expected) {
        writeln!(out, "  added {}: {}", label, value)?;
    }

    Ok(())
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

    if arg.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | '=' | ':' | '+')
    }) {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\"'\"'"))
    }
}

fn output_selection_metadata(
    mode: &workspace::OutputMode,
    workspace_root: &std::path::Path,
    artifacts: &[PathBuf],
    output_roots: &[PathBuf],
) -> attestation::OutputSelection {
    let mode = match mode {
        workspace::OutputMode::Inferred => "inferred",
        workspace::OutputMode::Explicit => "explicit",
    };

    let mut selection = attestation::OutputSelection {
        mode: mode.to_string(),
        artifacts: artifacts
            .iter()
            .map(|path| metadata_path(workspace_root, path))
            .collect(),
        output_roots: output_roots
            .iter()
            .map(|path| metadata_path(workspace_root, path))
            .collect(),
    };
    selection.artifacts.sort();
    selection.output_roots.sort();
    selection
}

fn attested_outputs_metadata(
    workspace_root: &std::path::Path,
    outputs: &[workspace::OutputFile],
) -> Vec<attestation::AttestedOutput> {
    outputs
        .iter()
        .map(|output| attestation::AttestedOutput {
            path: workspace::display_path(workspace_root, &output.path),
            hash: output.hash.clone(),
        })
        .collect()
}

fn validate_output_selection(
    expected: &attestation::Attestation,
    workspace_root: &std::path::Path,
    artifacts: &[PathBuf],
    output_roots: &[PathBuf],
) -> Result<()> {
    if expected.output_selection.mode == "explicit"
        && artifacts.is_empty()
        && output_roots.is_empty()
    {
        bail!(
            "the attestation used explicit output selection; repeat its --artifact/--output-root flags rather than trusting policy from the attestation file"
        );
    }

    let mode = if artifacts.is_empty() && output_roots.is_empty() {
        workspace::OutputMode::Inferred
    } else {
        workspace::OutputMode::Explicit
    };
    let requested = output_selection_metadata(&mode, workspace_root, artifacts, output_roots);
    if requested != expected.output_selection {
        bail!("verification output selection differs from the attestation");
    }
    Ok(())
}

fn metadata_path(workspace_root: &std::path::Path, path: &std::path::Path) -> String {
    if path.is_absolute() {
        workspace::display_path(workspace_root, &path.to_string_lossy())
    } else {
        path.to_string_lossy().into_owned()
    }
}
