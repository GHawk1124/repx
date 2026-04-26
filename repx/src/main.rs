mod attestation;
mod canonicalize;
mod merkle;
mod tracer;

use anyhow::Result;
use clap::{Parser, Subcommand};
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

        /// The command to trace (everything after --).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Verify a build by re-running it and comparing against an existing attestation.
    Verify {
        /// Path to the expected attestation file.
        #[arg(short, long)]
        attestation: PathBuf,

        /// Directories to monitor system-wide (must match the dirs used during trace).
        #[arg(short, long = "watch", value_name = "DIR")]
        watch_dirs: Vec<PathBuf>,

        /// The command to re-run for verification.
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
            command,
        } => {
            log::info!("Tracing command: {:?}", command);

            let result = tracer::trace_command(&command, &watch_dirs)?;
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
                eprintln!(
                    "WARNING: {} events dropped (ring buffer full). \
                     Attestation may be incomplete.",
                    result.dropped_events
                );
            }

            let canonical =
                canonicalize::canonicalize_events(result.events, result.root_pid, &watch_prefixes)?;

            if let Some(ref path) = dump_ops {
                let file = std::fs::File::create(path)?;
                serde_json::to_writer_pretty(file, &canonical)?;
            }

            let tree = merkle::build_merkle_tree(&canonical);
            let att = attestation::Attestation::new(tree, &command);

            att.write_to_file(&output)?;

            println!("Attestation root: {}", att.root_hash);
            println!("Written to: {}", output.display());

            Ok(())
        }
        Commands::Verify {
            attestation,
            watch_dirs,
            command,
        } => {
            log::info!("Verifying command: {:?}", command);

            let expected = attestation::Attestation::read_from_file(&attestation)?;

            // Check that the command matches what was originally traced.
            if expected.command != command {
                eprintln!("WARNING: Command differs from attestation.");
                eprintln!("  Attestation: {:?}", expected.command);
                eprintln!("  Current:     {:?}", command);
            }

            let result = tracer::trace_command(&command, &watch_dirs)?;
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

            let canonical =
                canonicalize::canonicalize_events(result.events, result.root_pid, &watch_prefixes)?;
            let tree = merkle::build_merkle_tree(&canonical);
            let actual = attestation::Attestation::new(tree, &command);

            if expected.root_hash == actual.root_hash {
                println!("VERIFIED: Attestation matches.");
                println!("Root hash: {}", actual.root_hash);
                Ok(())
            } else {
                eprintln!("MISMATCH: Attestation does not match.");
                eprintln!("  Expected: {}", expected.root_hash);
                eprintln!("  Actual:   {}", actual.root_hash);

                // Find divergence point in the merkle tree.
                let divergences = merkle::find_divergences(&expected.tree, &actual.tree);
                for d in &divergences {
                    eprintln!(
                        "  Divergence at node {}: {} vs {}",
                        d.index, d.expected, d.actual
                    );
                }

                std::process::exit(1);
            }
        }
    }
}
