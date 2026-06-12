//! Attestation output format.
//!
//! Produces a JSON attestation document containing a command-bound root,
//! the process-operation leaf set, and output-selection metadata.
//! Designed to eventually slot into an in-toto/SLSA predicate.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::merkle::MerkleTree;

/// How outputs were selected for output-rooted attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputSelection {
    pub mode: String,
    pub artifacts: Vec<String>,
    pub output_roots: Vec<String>,
}

impl Default for OutputSelection {
    fn default() -> Self {
        Self {
            mode: "inferred".to_string(),
            artifacts: Vec::new(),
            output_roots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestedOutput {
    pub path: String,
    pub hash: String,
}

/// The attestation document produced by `repx trace`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Schema version for forward compatibility.
    pub version: String,

    /// The type URI for this predicate (SLSA-compatible).
    pub predicate_type: String,

    /// Commitment over process_root, command, output selection, and outputs.
    pub root_hash: String,

    /// Merkle root over the deterministic set of covered operations.
    #[serde(default)]
    pub process_root: String,

    /// The command that was traced.
    pub command: Vec<String>,

    /// Output selection policy used to decide which workspace artifacts are
    /// included in the output-rooted attestation.
    #[serde(default)]
    pub output_selection: OutputSelection,

    /// Final workspace outputs attested by path and content hash.
    #[serde(default)]
    pub outputs: Vec<AttestedOutput>,

    /// Sorted operation leaves; internal Merkle nodes are derived on demand.
    pub tree: MerkleTree,
}

impl Attestation {
    pub fn new_with_outputs(
        tree: MerkleTree,
        command: &[String],
        output_selection: OutputSelection,
        outputs: Vec<AttestedOutput>,
    ) -> Self {
        let process_root = tree.root_hash();
        let mut output_selection = output_selection;
        output_selection.artifacts.sort();
        output_selection.output_roots.sort();
        let mut outputs = outputs;
        outputs.sort_by(|a, b| a.path.cmp(&b.path).then(a.hash.cmp(&b.hash)));
        let root_hash = commitment_hash(&process_root, command, &output_selection, &outputs);

        Attestation {
            version: "0.2.0".to_string(),
            predicate_type: "https://repx.dev/process-provenance/v0.2".to_string(),
            root_hash,
            process_root,
            command: command.to_vec(),
            output_selection,
            outputs,
            tree,
        }
    }

    /// Serialize and write the attestation to a JSON file.
    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Read an attestation from a JSON file.
    pub fn read_from_file(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        let mut att: Attestation = serde_json::from_str(&data)?;
        att.validate()?;
        Ok(att)
    }

    fn validate(&mut self) -> Result<()> {
        let derived_process_root = self.tree.root_hash();
        match self.version.as_str() {
            "0.1.0" => {
                if self.root_hash != derived_process_root {
                    bail!("legacy attestation root does not match its operation tree");
                }
                self.process_root = derived_process_root;
            }
            "0.2.0" => {
                if self.process_root.is_empty() {
                    self.process_root = derived_process_root.clone();
                }
                if derived_process_root != self.process_root {
                    bail!("attestation process root does not match its operation leaves");
                }
                let computed = commitment_hash(
                    &self.process_root,
                    &self.command,
                    &self.output_selection,
                    &self.outputs,
                );
                if computed != self.root_hash {
                    bail!("attestation root does not match its command and predicate data");
                }
            }
            version => bail!("unsupported attestation version: {version}"),
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct Commitment<'a> {
    domain: &'static str,
    process_root: &'a str,
    command: &'a [String],
    output_selection: &'a OutputSelection,
    outputs: &'a [AttestedOutput],
}

fn commitment_hash(
    process_root: &str,
    command: &[String],
    output_selection: &OutputSelection,
    outputs: &[AttestedOutput],
) -> String {
    let commitment = Commitment {
        domain: "repx-attestation-v0.2",
        process_root,
        command,
        output_selection,
        outputs,
    };
    // This exact compact JSON field order is part of the v0.2 commitment
    // format. A future canonical encoding must use a new attestation version.
    let encoded = serde_json::to_vec(&commitment).expect("serializing commitment cannot fail");
    let hash = Sha256::digest(encoded);
    format!("sha256:{:x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> MerkleTree {
        MerkleTree {
            leaves: vec!["sha256:operation".to_string()],
            nodes: Vec::new(),
            leaf_count: 1,
        }
    }

    #[test]
    fn command_is_bound_into_the_attestation_root() {
        let first = Attestation::new_with_outputs(
            tree(),
            &["make".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        let second = Attestation::new_with_outputs(
            tree(),
            &["make".to_string(), "release".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        assert_ne!(first.root_hash, second.root_hash);
    }

    #[test]
    fn serialized_tree_omits_internal_nodes() {
        let attestation = Attestation::new_with_outputs(
            tree(),
            &["true".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        let value = serde_json::to_value(attestation).unwrap();
        assert!(value["tree"].get("leaves").is_some());
        assert!(value["tree"].get("nodes").is_none());
    }

    #[test]
    fn v0_2_commitment_encoding_is_frozen() {
        let output_selection = OutputSelection {
            mode: "explicit".to_string(),
            artifacts: vec!["dist/app".to_string()],
            output_roots: vec!["dist".to_string()],
        };
        let outputs = vec![AttestedOutput {
            path: "dist/app".to_string(),
            hash: "sha256:artifact".to_string(),
        }];

        assert_eq!(
            commitment_hash(
                "sha256:process",
                &["make".to_string(), "release".to_string()],
                &output_selection,
                &outputs,
            ),
            "sha256:acbd954b2c7a7196ef706989898068ac1b26c82237855ccc7c071b592953adc5"
        );
    }

    #[test]
    fn unknown_versions_are_rejected() {
        let mut attestation = Attestation::new_with_outputs(
            tree(),
            &["true".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        attestation.version = "0.3.0".to_string();
        assert!(attestation.validate().is_err());
    }

    #[test]
    fn legacy_roots_are_still_validated() {
        let mut attestation = Attestation::new_with_outputs(
            tree(),
            &["true".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        attestation.version = "0.1.0".to_string();
        attestation.root_hash = attestation.tree.root_hash();
        attestation.process_root.clear();
        assert!(attestation.validate().is_ok());

        attestation.root_hash = "sha256:tampered".to_string();
        assert!(attestation.validate().is_err());
    }
}
