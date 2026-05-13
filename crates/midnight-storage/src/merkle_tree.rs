use crate::LedgerType;

/// Append-only Merkle tree for membership proofs.
///
/// Maps to `StateValue::BoundedMerkleTree` at the VM level.
/// Depth must satisfy 1 < DEPTH <= 32.
///
/// In test mode this uses a simple Vec-backed store.
#[derive(Debug, Clone)]
pub struct MerkleTree<const DEPTH: usize> {
    leaves: Vec<[u8; 32]>,
}

impl<const DEPTH: usize> MerkleTree<DEPTH> {
    pub fn empty() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn insert(&mut self, leaf: &[u8; 32]) {
        self.leaves.push(*leaf);
    }

    /// Check membership (test mode: linear scan).
    pub fn member(&self, leaf: &[u8; 32]) -> bool {
        self.leaves.contains(leaf)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

impl<const DEPTH: usize> LedgerType for MerkleTree<DEPTH> {
    fn requires_init() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_tree_basics() {
        let mut tree = MerkleTree::<32>::empty();
        let leaf = [1u8; 32];
        assert!(!tree.member(&leaf));
        tree.insert(&leaf);
        assert!(tree.member(&leaf));
        assert!(!tree.member(&[2u8; 32]));
    }
}
