//! Attestation output format.
//!
//! Produces a JSON attestation document containing the merkle tree
//! root hash, the full tree for divergence analysis, and metadata.
//! Designed to eventually slot into an in-toto/SLSA predicate.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::merkle::MerkleTree;

/// The attestation document produced by `repx trace`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Schema version for forward compatibility.
    pub version: String,

    /// The type URI for this predicate (SLSA-compatible).
    pub predicate_type: String,

    /// Root hash of the merkle tree — the single value to compare.
    pub root_hash: String,

    /// The command that was traced.
    pub command: Vec<String>,

    /// The full merkle tree (for divergence analysis on verification failure).
    pub tree: MerkleTree,
}

impl Attestation {
    /// Create a new attestation from a merkle tree and the traced command.
    pub fn new(tree: MerkleTree, command: &[String]) -> Self {
        let root_hash = tree
            .nodes
            .first()
            .map(|n| n.hash.clone())
            .unwrap_or_default();

        Attestation {
            version: "0.1.0".to_string(),
            predicate_type: "https://repx.dev/process-provenance/v0.1".to_string(),
            root_hash,
            command: command.to_vec(),
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
        let att: Attestation = serde_json::from_str(&data)?;
        Ok(att)
    }
}
