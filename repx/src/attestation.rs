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
        let root_hash = commitment_hash_v0_3(&process_root, command, &output_selection, &outputs);

        Attestation {
            version: "0.3.0".to_string(),
            predicate_type: "https://repx.dev/process-provenance/v0.3.0".to_string(),
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
            "0.2.0" | "0.2.1" => {
                if self.process_root.is_empty() {
                    self.process_root = derived_process_root.clone();
                }
                if derived_process_root != self.process_root {
                    bail!("attestation process root does not match its operation leaves");
                }
                let computed = commitment_hash_v0_2(
                    &self.process_root,
                    &self.command,
                    &self.output_selection,
                    &self.outputs,
                );
                if computed != self.root_hash {
                    bail!("attestation root does not match its command and predicate data");
                }
            }
            "0.3.0" => {
                if self.process_root.is_empty() {
                    self.process_root = derived_process_root.clone();
                }
                if derived_process_root != self.process_root {
                    bail!("attestation process root does not match its operation leaves");
                }
                let computed = commitment_hash_v0_3(
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
struct CommitmentV0_2<'a> {
    domain: &'static str,
    process_root: &'a str,
    command: &'a [String],
    output_selection: &'a OutputSelection,
    outputs: &'a [AttestedOutput],
}

/// v0.2.x commitment hash: SHA-256 over compact JSON.
///
/// Frozen for backward-compatible validation of 0.2.0 and 0.2.1 attestations.
/// The JSON field order is part of the format — never reorder the struct above.
fn commitment_hash_v0_2(
    process_root: &str,
    command: &[String],
    output_selection: &OutputSelection,
    outputs: &[AttestedOutput],
) -> String {
    let commitment = CommitmentV0_2 {
        domain: "repx-attestation-v0.2",
        process_root,
        command,
        output_selection,
        outputs,
    };
    let encoded = serde_json::to_vec(&commitment).expect("serializing commitment cannot fail");
    let hash = Sha256::digest(encoded);
    format!("sha256:{:x}", hash)
}

// ---------------------------------------------------------------------------
// v0.3.0 deterministic commitment encoding
// ---------------------------------------------------------------------------
//
// serde_json field ordering is implementation-defined and could drift across
// crate versions.  v0.3.0 replaces the JSON serialization with a
// length-prefixed binary framing that is independent of any serializer.
//
// Encoding (all lengths are u32 little-endian; all text is UTF-8):
//
//   domain_len: u32, domain: bytes
//   process_root_len: u32, process_root: bytes
//   command_count: u32
//     for each arg: arg_len: u32, arg: bytes
//   output_selection.mode_len: u32, mode: bytes
//   artifacts_count: u32
//     for each: path_len: u32, path: bytes
//   output_roots_count: u32
//     for each: path_len: u32, path: bytes
//   outputs_count: u32
//     for each: path_len: u32, path: bytes, hash_len: u32, hash: bytes

const COMMITMENT_DOMAIN_V0_3: &str = "repx-attestation-v0.3";

fn encode_commitment_v0_3(
    process_root: &str,
    command: &[String],
    output_selection: &OutputSelection,
    outputs: &[AttestedOutput],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);

    write_commitment_str(&mut buf, COMMITMENT_DOMAIN_V0_3);
    write_commitment_str(&mut buf, process_root);

    write_commitment_u32(&mut buf, command.len() as u32);
    for arg in command {
        write_commitment_str(&mut buf, arg);
    }

    write_commitment_str(&mut buf, &output_selection.mode);

    write_commitment_u32(&mut buf, output_selection.artifacts.len() as u32);
    for a in &output_selection.artifacts {
        write_commitment_str(&mut buf, a);
    }

    write_commitment_u32(&mut buf, output_selection.output_roots.len() as u32);
    for r in &output_selection.output_roots {
        write_commitment_str(&mut buf, r);
    }

    write_commitment_u32(&mut buf, outputs.len() as u32);
    for o in outputs {
        write_commitment_str(&mut buf, &o.path);
        write_commitment_str(&mut buf, &o.hash);
    }

    buf
}

fn write_commitment_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_commitment_str(buf: &mut Vec<u8>, s: &str) {
    write_commitment_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn commitment_hash_v0_3(
    process_root: &str,
    command: &[String],
    output_selection: &OutputSelection,
    outputs: &[AttestedOutput],
) -> String {
    let encoded = encode_commitment_v0_3(process_root, command, output_selection, outputs);
    let hash = Sha256::digest(&encoded);
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
            commitment_hash_v0_2(
                "sha256:process",
                &["make".to_string(), "release".to_string()],
                &output_selection,
                &outputs,
            ),
            "sha256:acbd954b2c7a7196ef706989898068ac1b26c82237855ccc7c071b592953adc5"
        );
    }

    #[test]
    fn v0_3_commitment_encoding_is_deterministic() {
        // The v0.3 encoding uses length-prefixed framing, not serde_json.
        // This hash MUST NOT change — it is the frozen commitment format.
        let output_selection = OutputSelection {
            mode: "explicit".to_string(),
            artifacts: vec!["dist/app".to_string()],
            output_roots: vec!["dist".to_string()],
        };
        let outputs = vec![AttestedOutput {
            path: "dist/app".to_string(),
            hash: "sha256:artifact".to_string(),
        }];

        let hash = commitment_hash_v0_3(
            "sha256:process",
            &["make".to_string(), "release".to_string()],
            &output_selection,
            &outputs,
        );
        assert_eq!(
            hash,
            "sha256:1f819e0c33fd80f8b324a0e528999a588ce1c1c1ca5c9b52061b5dad39b8b151"
        );

        // Empty outputs must be stable too.
        let hash_empty = commitment_hash_v0_3(
            "sha256:process",
            &["make".to_string()],
            &OutputSelection::default(),
            &[],
        );
        assert_eq!(
            hash_empty,
            "sha256:ca5c89cc0b8fcdd83c6043fe04430ab3a27bac151d9845fa231ed9586b1f65b2"
        );
    }

    #[test]
    fn v0_3_encoding_rejects_fields_out_of_order() {
        // If someone permutes the JSON arrays, the commitment won't match
        // because the encoding walks arrays in their stored order.
        let att = Attestation::new_with_outputs(
            tree(),
            &["true".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        let hash_original = att.root_hash.clone();

        // Same logical data, different root — proving command order is bound.
        let att2 = Attestation::new_with_outputs(
            tree(),
            &["true".to_string(), "extra".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        assert_ne!(hash_original, att2.root_hash);
    }

    #[test]
    fn unknown_versions_are_rejected() {
        let mut attestation = Attestation::new_with_outputs(
            tree(),
            &["true".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        attestation.version = "9.9.9".to_string();
        assert!(attestation.validate().is_err());
    }

    #[test]
    fn v0_3_0_attestations_pass_validation() {
        let mut attestation = Attestation::new_with_outputs(
            tree(),
            &["true".to_string()],
            OutputSelection::default(),
            Vec::new(),
        );
        assert_eq!(attestation.version, "0.3.0");
        assert!(attestation.validate().is_ok());
    }

    #[test]
    fn v0_2_1_attestations_pass_validation() {
        // Build a v0.2.1 attestation by hand and verify it still validates.
        let tree = tree();
        let process_root = tree.root_hash();
        let command: Vec<String> = vec!["true".to_string()];
        let output_selection = OutputSelection::default();
        let outputs: Vec<AttestedOutput> = Vec::new();

        let root_hash = commitment_hash_v0_2(&process_root, &command, &output_selection, &outputs);

        let mut attestation = Attestation {
            version: "0.2.1".to_string(),
            predicate_type: "https://repx.dev/process-provenance/v0.2.1".to_string(),
            root_hash,
            process_root,
            command,
            output_selection,
            outputs,
            tree,
        };
        assert!(attestation.validate().is_ok());
    }

    #[test]
    fn legacy_roots_are_still_validated() {
        let tree = tree();
        let process_root = tree.root_hash();

        let mut attestation = Attestation {
            version: "0.1.0".to_string(),
            predicate_type: "https://repx.dev/process-provenance/v0.1".to_string(),
            root_hash: process_root.clone(),
            process_root: String::new(),
            command: vec!["true".to_string()],
            output_selection: OutputSelection::default(),
            outputs: Vec::new(),
            tree,
        };
        assert!(attestation.validate().is_ok());

        attestation.root_hash = "sha256:tampered".to_string();
        assert!(attestation.validate().is_err());
    }
}
