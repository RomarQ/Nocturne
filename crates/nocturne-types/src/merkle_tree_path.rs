use crate::{Boolean, MerkleTreeDigest, ZkType};
use std::fmt;

/// One step of a Merkle inclusion path. Mirrors Compact's stdlib
/// `MerkleTreePathEntry { sibling: MerkleTreeDigest; goes_left: Boolean; }`.
///
/// `sibling` is the digest of the node we ignore at this level; `goes_left`
/// is `true` when the accumulator goes on the LEFT and the sibling on the
/// RIGHT for this level's transient_hash combine — matching upstream
/// `MerklePath::root()` semantics (`transient-crypto/src/merkle_tree.rs:142`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MerkleTreePathEntry {
    pub sibling: MerkleTreeDigest,
    pub goes_left: Boolean,
}

impl MerkleTreePathEntry {
    pub fn new(sibling: MerkleTreeDigest, goes_left: Boolean) -> Self {
        Self { sibling, goes_left }
    }
}

impl fmt::Debug for MerkleTreePathEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MerkleTreePathEntry {{ sibling: {:?}, goes_left: {} }}",
            self.sibling,
            self.goes_left.value()
        )
    }
}

impl ZkType for MerkleTreePathEntry {
    fn field_count() -> usize {
        // 1 Fr per sibling (Field) + 1 Fr per goes_left (Boolean).
        2
    }
}

/// A Merkle inclusion path: the leaf and `HEIGHT` sibling/direction pairs
/// to compute the root from the leaf upward.
///
/// Mirrors Compact's stdlib `MerkleTreePath<#n, T> { leaf: T; path:
/// Vector<n, MerkleTreePathEntry>; }`. The on-chain circuit primitive
/// [`merkle_tree_path_root`](crate::merkle_tree_path_root) computes the
/// root from a path; off-chain `root()` does the same in plain Rust.
///
/// `T` is the leaf type — currently only `Bytes<N>` is supported on-chain
/// (see the IR codegen for `merkle_tree_path_root`); off-chain anything
/// implementing the `MerkleLeaf` trait works.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MerkleTreePath<const HEIGHT: usize, T> {
    pub leaf: T,
    pub path: [MerkleTreePathEntry; HEIGHT],
}

impl<const HEIGHT: usize, T> MerkleTreePath<HEIGHT, T> {
    pub fn new(leaf: T, path: [MerkleTreePathEntry; HEIGHT]) -> Self {
        Self { leaf, path }
    }
}
