//! Merkle tree construction over canonicalized build operations.
//!
//! Each leaf is the hash of a single `CanonicalOp`. Internal nodes
//! are the hash of their two children concatenated. This gives us
//! a single root hash representing the entire build process, plus
//! the ability to pinpoint exactly where two builds diverge.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonicalize::CanonicalOp;

/// A complete merkle tree over build operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// All nodes in the tree, stored as a flat array.
    /// Index 0 is the root. Children of node i are at 2i+1 and 2i+2.
    pub nodes: Vec<MerkleNode>,
    /// Number of leaf nodes (= number of canonical operations).
    pub leaf_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: String,
    pub is_leaf: bool,
}

/// Describes a point where two merkle trees diverge.
pub struct Divergence {
    pub index: usize,
    pub expected: String,
    pub actual: String,
}

/// Build a merkle tree from a sequence of canonical operations.
pub fn build_merkle_tree(ops: &[CanonicalOp]) -> MerkleTree {
    if ops.is_empty() {
        return MerkleTree {
            nodes: vec![MerkleNode {
                hash: hash_pair("empty", "empty"),
                is_leaf: true,
            }],
            leaf_count: 0,
        };
    }

    // Compute leaf hashes.
    let mut leaves: Vec<String> = ops.iter().map(|op| op.hash()).collect();

    // Pad to next power of 2 for a balanced tree.
    let target_len = leaves.len().next_power_of_two();
    while leaves.len() < target_len {
        leaves.push(hash_pair("padding", "padding"));
    }

    let leaf_count = ops.len();
    let total_nodes = 2 * target_len - 1;
    let internal_count = target_len - 1;

    // Allocate all nodes.
    let mut nodes = vec![
        MerkleNode {
            hash: String::new(),
            is_leaf: false,
        };
        total_nodes
    ];

    // Fill in leaves (they start at index internal_count).
    for (i, leaf_hash) in leaves.iter().enumerate() {
        nodes[internal_count + i] = MerkleNode {
            hash: leaf_hash.clone(),
            is_leaf: true,
        };
    }

    // Build internal nodes bottom-up.
    for i in (0..internal_count).rev() {
        let left = 2 * i + 1;
        let right = 2 * i + 2;
        nodes[i] = MerkleNode {
            hash: hash_pair(&nodes[left].hash, &nodes[right].hash),
            is_leaf: false,
        };
    }

    MerkleTree { nodes, leaf_count }
}

/// Hash two child hashes together to form a parent hash.
fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// Walk two merkle trees and find the nodes where they diverge.
/// Returns divergence points at the leaf level for actionable diagnostics.
pub fn find_divergences(expected: &MerkleTree, actual: &MerkleTree) -> Vec<Divergence> {
    let mut divergences = Vec::new();
    find_divergences_recursive(expected, actual, 0, &mut divergences);
    divergences
}

fn find_divergences_recursive(
    expected: &MerkleTree,
    actual: &MerkleTree,
    index: usize,
    divergences: &mut Vec<Divergence>,
) {
    // Bounds check.
    let e_node = expected.nodes.get(index);
    let a_node = actual.nodes.get(index);

    match (e_node, a_node) {
        (Some(e), Some(a)) => {
            if e.hash == a.hash {
                return; // Subtrees match, no need to descend.
            }

            if e.is_leaf || a.is_leaf {
                // Reached a leaf-level divergence.
                divergences.push(Divergence {
                    index,
                    expected: e.hash.clone(),
                    actual: a.hash.clone(),
                });
                return;
            }

            // Descend into children.
            find_divergences_recursive(expected, actual, 2 * index + 1, divergences);
            find_divergences_recursive(expected, actual, 2 * index + 2, divergences);
        }
        _ => {
            // Trees have different sizes — structural divergence.
            divergences.push(Divergence {
                index,
                expected: e_node
                    .map(|n| n.hash.clone())
                    .unwrap_or_else(|| "<missing>".to_string()),
                actual: a_node
                    .map(|n| n.hash.clone())
                    .unwrap_or_else(|| "<missing>".to_string()),
            });
        }
    }
}
