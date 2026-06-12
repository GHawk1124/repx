//! Repeated-trace stability analysis.

use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::Write;

use crate::attestation::Attestation;

#[derive(Debug, Serialize)]
pub struct StabilityReport {
    pub baseline: String,
    pub run_count: usize,
    pub root_matches: usize,
    pub process_root_matches: usize,
    pub minimum_leaf_jaccard: f64,
    pub mean_leaf_jaccard: f64,
    pub runs: Vec<RunStability>,
}

#[derive(Debug, Serialize)]
pub struct RunStability {
    pub path: String,
    pub root_match: bool,
    pub process_root_match: bool,
    pub leaf_count: usize,
    pub leaf_jaccard: f64,
    pub missing_leaves: usize,
    pub added_leaves: usize,
}

pub fn analyze(inputs: &[(String, Attestation)]) -> Result<StabilityReport> {
    if inputs.len() < 2 {
        bail!("stability analysis requires at least two attestations");
    }

    let (baseline_path, baseline) = &inputs[0];
    let baseline_leaves: BTreeSet<String> = baseline.tree.leaf_hashes().into_iter().collect();
    let mut runs = Vec::with_capacity(inputs.len());

    for (path, attestation) in inputs {
        let leaves: BTreeSet<String> = attestation.tree.leaf_hashes().into_iter().collect();
        let intersection = baseline_leaves.intersection(&leaves).count();
        let union = baseline_leaves.union(&leaves).count();
        let leaf_jaccard = if union == 0 {
            1.0
        } else {
            intersection as f64 / union as f64
        };

        runs.push(RunStability {
            path: path.clone(),
            root_match: attestation.root_hash == baseline.root_hash,
            process_root_match: attestation.process_root == baseline.process_root,
            leaf_count: leaves.len(),
            leaf_jaccard,
            missing_leaves: baseline_leaves.difference(&leaves).count(),
            added_leaves: leaves.difference(&baseline_leaves).count(),
        });
    }

    let root_matches = runs.iter().filter(|run| run.root_match).count();
    let process_root_matches = runs.iter().filter(|run| run.process_root_match).count();
    let minimum_leaf_jaccard = runs.iter().map(|run| run.leaf_jaccard).fold(1.0, f64::min);
    let mean_leaf_jaccard =
        runs.iter().map(|run| run.leaf_jaccard).sum::<f64>() / runs.len() as f64;

    Ok(StabilityReport {
        baseline: baseline_path.clone(),
        run_count: runs.len(),
        root_matches,
        process_root_matches,
        minimum_leaf_jaccard,
        mean_leaf_jaccard,
        runs,
    })
}

pub fn print_human(out: &mut dyn Write, report: &StabilityReport) -> Result<()> {
    writeln!(out, "Baseline: {}", report.baseline)?;
    writeln!(
        out,
        "Attestation root stability: {}/{} ({:.1}%)",
        report.root_matches,
        report.run_count,
        percentage(report.root_matches, report.run_count)
    )?;
    writeln!(
        out,
        "Process root stability: {}/{} ({:.1}%)",
        report.process_root_matches,
        report.run_count,
        percentage(report.process_root_matches, report.run_count)
    )?;
    writeln!(
        out,
        "Leaf-set Jaccard: min {:.6}, mean {:.6}",
        report.minimum_leaf_jaccard, report.mean_leaf_jaccard
    )?;

    for run in report.runs.iter().filter(|run| !run.root_match) {
        writeln!(
            out,
            "  mismatch: {} (process_root={}, jaccard={:.6}, missing={}, added={})",
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

    Ok(())
}

fn percentage(matches: usize, total: usize) -> f64 {
    matches as f64 * 100.0 / total as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{AttestedOutput, OutputSelection};
    use crate::merkle::MerkleTree;

    fn attestation(leaves: &[&str], command: &str) -> Attestation {
        Attestation::new_with_outputs(
            MerkleTree {
                leaves: leaves.iter().map(|leaf| (*leaf).to_string()).collect(),
                nodes: Vec::new(),
                leaf_count: leaves.len(),
            },
            &[command.to_string()],
            OutputSelection::default(),
            Vec::<AttestedOutput>::new(),
        )
    }

    #[test]
    fn reports_root_and_leaf_set_stability() {
        let report = analyze(&[
            ("first.json".into(), attestation(&["a", "b"], "make")),
            ("second.json".into(), attestation(&["a", "b"], "make")),
            ("third.json".into(), attestation(&["a", "c"], "make")),
        ])
        .unwrap();

        assert_eq!(report.root_matches, 2);
        assert_eq!(report.process_root_matches, 2);
        assert_eq!(report.minimum_leaf_jaccard, 1.0 / 3.0);
        assert_eq!(report.runs[2].missing_leaves, 1);
        assert_eq!(report.runs[2].added_leaves, 1);
    }

    #[test]
    fn empty_leaf_sets_are_identical() {
        let report = analyze(&[
            ("first.json".into(), attestation(&[], "true")),
            ("second.json".into(), attestation(&[], "true")),
        ])
        .unwrap();

        assert_eq!(report.minimum_leaf_jaccard, 1.0);
    }
}
