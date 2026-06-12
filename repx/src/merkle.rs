//! Merkle tree construction over canonicalized build operations.
//!
//! Each leaf is the hash of a distinct canonical operation. Internal nodes
//! are derived, so attestations persist only the sorted leaf set.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::canonicalize::CanonicalOp;

/// A complete merkle tree over build operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Sorted hashes of distinct canonical operations.
    #[serde(default)]
    pub leaves: Vec<String>,
    /// In-memory tree nodes. Old attestations can still deserialize this field,
    /// but new attestations omit it because internal nodes are derivable.
    #[serde(default, skip_serializing)]
    pub nodes: Vec<MerkleNode>,
    /// Number of leaf nodes (= number of canonical operations).
    pub leaf_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: String,
    pub is_leaf: bool,
}

pub struct LeafSetDiff {
    pub missing: Vec<String>,
    pub added: Vec<String>,
}

/// Build a merkle tree from a sequence of canonical operations.
pub fn build_merkle_tree(ops: &[CanonicalOp]) -> MerkleTree {
    let leaves: Vec<String> = ops.iter().map(|op| op.hash()).collect();
    MerkleTree {
        leaf_count: leaves.len(),
        leaves,
        nodes: Vec::new(),
    }
}

impl MerkleTree {
    pub fn root_hash(&self) -> String {
        if let Some(root) = self.nodes.first() {
            return root.hash.clone();
        }

        root_from_leaves(&self.leaf_hashes())
    }

    pub fn leaf_hashes(&self) -> Vec<String> {
        if !self.leaves.is_empty() || self.leaf_count == 0 {
            return self.leaves.clone();
        }

        let padded_leaf_count = self.nodes.len().div_ceil(2);
        let first_leaf = padded_leaf_count.saturating_sub(1);
        self.nodes
            .iter()
            .skip(first_leaf)
            .take(self.leaf_count)
            .map(|node| node.hash.clone())
            .collect()
    }
}

/// Hash two child hashes together to form a parent hash.
fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

pub fn diff_leaf_sets(expected: &MerkleTree, actual: &MerkleTree) -> LeafSetDiff {
    let expected: BTreeSet<String> = expected.leaf_hashes().into_iter().collect();
    let actual: BTreeSet<String> = actual.leaf_hashes().into_iter().collect();
    LeafSetDiff {
        missing: expected.difference(&actual).cloned().collect(),
        added: actual.difference(&expected).cloned().collect(),
    }
}

fn root_from_leaves(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return hash_pair("empty", "empty");
    }

    let mut level = leaves.to_vec();
    let target_len = level.len().next_power_of_two();
    while level.len() < target_len {
        level.push(hash_pair("padding", "padding"));
    }

    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();
    }
    level.pop().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_diff_does_not_cascade_after_an_insertion() {
        let expected = MerkleTree {
            leaves: vec!["a".into(), "c".into()],
            nodes: Vec::new(),
            leaf_count: 2,
        };
        let actual = MerkleTree {
            leaves: vec!["a".into(), "b".into(), "c".into()],
            nodes: Vec::new(),
            leaf_count: 3,
        };

        let diff = diff_leaf_sets(&expected, &actual);
        assert!(diff.missing.is_empty());
        assert_eq!(diff.added, vec!["b"]);
    }
}
