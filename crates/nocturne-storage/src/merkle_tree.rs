use crate::LedgerType;
use midnight_transient_crypto::merkle_tree::{
    self as upstream, MerkleTreeDigest as UpstreamDigest,
};
use nocturne_types::{Boolean, Bytes, MerkleTreeDigest, MerkleTreePath, MerkleTreePathEntry};
use std::marker::PhantomData;

/// Marker trait for types that can be hashed as Merkle tree leaves.
///
/// Implementors expose a byte slice, which is what the upstream
/// `leaf_hash` (with the `"mdn:lh"` domain separator) consumes. Locally
/// defined so we can implement it for both raw `[u8; N]` and our
/// `Bytes<N>` newtype — `BinaryHashRepr` lives in `midnight-base-crypto`
/// and adding the impl directly would be an orphan-rule violation.
pub trait MerkleLeaf {
    fn leaf_bytes(&self) -> &[u8];
}

impl<const N: usize> MerkleLeaf for [u8; N] {
    fn leaf_bytes(&self) -> &[u8] {
        self
    }
}

impl<const N: usize> MerkleLeaf for Bytes<N> {
    fn leaf_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Append-only Merkle tree on the ledger.
///
/// User-facing type matching Compact's `MerkleTree<#n, T>` (where `n` is
/// the height and `T` is the leaf type). On-chain this maps to a
/// 2-element `StateValue::Array` of `[BoundedMerkleTree<()>,
/// Cell<u64>]` — the tree stores leaf hashes at u64 indices, and the
/// Cell tracks the next insertion slot. See
/// [`merkle-tree-encoding`](../../../memories/merkle-tree-encoding.md)
/// for the full on-chain encoding and the staged implementation plan.
///
/// `HEIGHT` is the tree height (must be `1..=32` per the on-chain VM
/// invariant on `BoundedMerkleTree`).
///
/// Off-chain, this wraps the upstream
/// `midnight_transient_crypto::merkle_tree::MerkleTree<()>` so `root()`
/// returns the same `MerkleTreeDigest` the on-chain `Root` opcode
/// computes. Insertion is `O(1)` against the wrapped tree; rehashing
/// happens lazily when `root()` or `check_root()` is called.
#[derive(Debug, Clone)]
pub struct MerkleTree<const HEIGHT: usize, T> {
    /// Always kept in a rehashed state so `root()` can be a `&self`
    /// operation. The on-chain `Root` opcode requires a rehashed tree
    /// (`onchain-vm/src/vm.rs:562-577`); we mirror that invariant by
    /// rehashing eagerly after every `insert`.
    inner: upstream::MerkleTree<()>,
    next_index: u64,
    _phantom: PhantomData<T>,
}

impl<const HEIGHT: usize, T> MerkleTree<HEIGHT, T> {
    /// Build a fresh, empty tree of height `HEIGHT`. Mirrors compactc's
    /// initial state for a `MerkleTree<#HEIGHT, T>` field — a blank
    /// `BoundedMerkleTree(HEIGHT)` paired with a `next_index = 0`. The
    /// blank tree is already rehashed (no leaves), so `root()` works
    /// immediately.
    pub fn empty() -> Self {
        // Compile-time bound check: the on-chain VM's BoundedMerkleTree
        // only accepts heights 1..=32, and `insert`'s fullness check
        // computes `1u64 << HEIGHT`.
        const {
            assert!(
                HEIGHT >= 1 && HEIGHT <= 32,
                "MerkleTree HEIGHT must be in 1..=32"
            )
        }
        let inner = upstream::MerkleTree::blank(HEIGHT as u8).rehash();
        Self {
            inner,
            next_index: 0,
            _phantom: PhantomData,
        }
    }

    /// The number of leaves inserted so far. This is the on-chain
    /// `next_index` slot, also the index that the next `insert` will use.
    pub fn len(&self) -> u64 {
        self.next_index
    }

    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    /// The current root of the tree as a [`MerkleTreeDigest`]. Always
    /// available because we rehash eagerly after every `insert`.
    pub fn root(&self) -> MerkleTreeDigest {
        let upstream_root: UpstreamDigest = self
            .inner
            .root()
            .expect("MerkleTree is kept rehashed; root() should always succeed");
        upstream_digest_to_user(upstream_root)
    }

    /// Compare `digest` against the current tree root. Reserved as the
    /// on-chain `checkRoot` semantics — Phase C compiles this directly
    /// to the VM's `Root + Eq + Popeq` shape, so this method's return
    /// value is what the transcript builder bakes into the Popeq result.
    pub fn check_root(&self, digest: &MerkleTreeDigest) -> bool {
        self.root() == *digest
    }
}

impl<const HEIGHT: usize, T: MerkleLeaf> MerkleTree<HEIGHT, T> {
    /// Insert `leaf` at the next free slot. The slot index increments by
    /// one. The leaf is hashed with the on-chain leafHash domain
    /// separator (`"mdn:lh"`, encoded as `0x6D646E3A6C68`) so the off-chain
    /// tree's root matches what the on-chain `Root` opcode computes after
    /// the same insertion sequence.
    ///
    /// Rehashes eagerly so subsequent `root()` / `check_root()` calls are
    /// `&self`. The cost is O(n+h) per insert vs. O(1) amortized — fine
    /// for the small trees the test suite exercises and avoids interior
    /// mutability in the storage type.
    ///
    /// Panics when the tree is full (`2^HEIGHT` leaves already inserted).
    pub fn insert(&mut self, leaf: &T) {
        assert!(
            self.next_index < (1u64 << HEIGHT),
            "MerkleTree<{HEIGHT}> is full (2^{HEIGHT} leaves)"
        );
        let leaf_hash = upstream::leaf_hash(leaf.leaf_bytes());
        self.inner = self
            .inner
            .try_update_hash(self.next_index, leaf_hash, ())
            .expect("insert: next_index always in range for the configured HEIGHT")
            .rehash();
        self.next_index += 1;
    }
}

impl<const HEIGHT: usize, T: MerkleLeaf + Clone> MerkleTree<HEIGHT, T> {
    /// Produce a Merkle inclusion path for the leaf at `index`. The
    /// returned [`MerkleTreePath`] has exactly `HEIGHT` entries, ordered
    /// from leaf upward, with sibling digests carrying the full Fr
    /// representation (the same form the on-chain Root opcode produces).
    /// Pair this with [`merkle_tree_path_root`](crate::merkle_tree_path_root)
    /// off-chain or use it directly as a witness in a circuit that
    /// calls the on-chain `merkle_tree_path_root` primitive.
    ///
    /// Panics if `index` is out of bounds for `HEIGHT`. The caller must
    /// have inserted at least `index + 1` leaves before requesting a
    /// path for index `index`.
    pub fn path_for_leaf(&self, index: u64, leaf: T) -> MerkleTreePath<HEIGHT, T> {
        let bytes = leaf.leaf_bytes().to_vec();
        let upstream_path = self
            .inner
            .path_for_leaf(index, LeafBytes(&bytes))
            .expect("path_for_leaf: index out of range");
        assert_eq!(
            upstream_path.path.len(),
            HEIGHT,
            "path_for_leaf: upstream path length must match HEIGHT"
        );

        let mut entries: Vec<MerkleTreePathEntry> = Vec::with_capacity(HEIGHT);
        for entry in upstream_path.path {
            let mut sibling_bytes = [0u8; 32];
            let le = entry.sibling.0.as_le_bytes();
            let n = le.len().min(32);
            sibling_bytes[..n].copy_from_slice(&le[..n]);
            entries.push(MerkleTreePathEntry::new(
                MerkleTreeDigest::from_le_bytes(sibling_bytes),
                Boolean::from(entry.goes_left),
            ));
        }
        let path_arr: [MerkleTreePathEntry; HEIGHT] = entries
            .try_into()
            .map_err(|v: Vec<_>| v.len())
            .expect("path_for_leaf: length already asserted");
        MerkleTreePath::new(leaf, path_arr)
    }
}

/// Adapter that lets `upstream::MerkleTree::path_for_leaf` accept an
/// owned slice without requiring the leaf type to be `[u8; N]`. Upstream
/// only impls `BinaryHashRepr` for `[u8]` and `[u8; N]`, so this thin
/// newtype lets us pass a `Vec<u8>` borrowed as a slice.
struct LeafBytes<'a>(&'a [u8]);

impl<'a> midnight_base_crypto::repr::BinaryHashRepr for LeafBytes<'a> {
    fn binary_repr<W: midnight_base_crypto::repr::MemWrite<u8>>(&self, writer: &mut W) {
        writer.write(self.0);
    }
    fn binary_len(&self) -> usize {
        self.0.len()
    }
}

impl<const HEIGHT: usize, T> LedgerType for MerkleTree<HEIGHT, T> {
    /// MerkleTree is the first ledger primitive that requires explicit
    /// constructor emission — its initial state is a non-Null Array, not
    /// a default-Null cell. See the staged plan in
    /// `memories/merkle-tree-encoding.md` (Phase B notes the requirement
    /// here; Phase D will emit the constructor IR).
    fn requires_init() -> bool {
        true
    }
}

/// Convert the upstream `MerkleTreeDigest(Fr)` to our user-facing
/// `MerkleTreeDigest`. We preserve the full 32-byte LE Fr representation
/// so chained computations (`merkle_tree_path_root` + `check_root`,
/// digest-as-witness) round-trip through the on-chain `Root` opcode.
fn upstream_digest_to_user(upstream: UpstreamDigest) -> MerkleTreeDigest {
    let mut buf = [0u8; 32];
    let le = upstream.0.as_le_bytes();
    let n = le.len().min(32);
    buf[..n].copy_from_slice(&le[..n]);
    MerkleTreeDigest::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nocturne_types::Field;

    #[test]
    fn empty_tree_has_consistent_root() {
        let t1 = MerkleTree::<10, [u8; 32]>::empty();
        let t2 = MerkleTree::<10, [u8; 32]>::empty();
        assert_eq!(t1.root(), t2.root(), "blank trees must have the same root");
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = MerkleTree::<10, [u8; 32]>::empty();
        let r0 = tree.root();
        tree.insert(&[0xAAu8; 32]);
        let r1 = tree.root();
        assert_ne!(r0, r1, "inserting a leaf must change the root");
    }

    #[test]
    fn check_root_round_trips() {
        let mut tree = MerkleTree::<10, [u8; 32]>::empty();
        tree.insert(&[0xAAu8; 32]);
        let r = tree.root();
        assert!(tree.check_root(&r));
        let wrong = MerkleTreeDigest::new(Field::from(0xDEADu64));
        assert!(!tree.check_root(&wrong));
    }

    #[test]
    fn bytes_n_leaves_work_via_merkle_leaf_adapter() {
        // The `Bytes<N>` newtype from nocturne-types is the typical user
        // leaf type (matching Compact's `MerkleTree<#H, Bytes<32>>`). The
        // local `MerkleLeaf` impl forwards to its underlying [u8; N].
        let mut tree = MerkleTree::<10, Bytes<32>>::empty();
        let leaf_a = Bytes::<32>::from([0x11u8; 32]);
        let leaf_b = Bytes::<32>::from([0x22u8; 32]);
        tree.insert(&leaf_a);
        let r1 = tree.root();
        tree.insert(&leaf_b);
        let r2 = tree.root();
        assert_ne!(r1, r2, "inserting a second leaf must change the root");
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn insert_up_to_capacity_succeeds() {
        // HEIGHT = 1 means exactly 2 leaf slots.
        let mut tree = MerkleTree::<1, [u8; 32]>::empty();
        tree.insert(&[0x01u8; 32]);
        tree.insert(&[0x02u8; 32]);
        assert_eq!(tree.len(), 2);
    }

    #[test]
    #[should_panic(expected = "MerkleTree<1> is full (2^1 leaves)")]
    fn insert_into_full_tree_panics() {
        let mut tree = MerkleTree::<1, [u8; 32]>::empty();
        tree.insert(&[0x01u8; 32]);
        tree.insert(&[0x02u8; 32]);
        tree.insert(&[0x03u8; 32]); // 2^1 = 2 slots; third insert must panic
    }

    #[test]
    fn height_bounds_compile_for_valid_heights() {
        // The const block in `empty()` must not fire for the boundary
        // heights the on-chain VM accepts (1..=32).
        let _ = MerkleTree::<1, [u8; 32]>::empty();
        let _ = MerkleTree::<32, [u8; 32]>::empty();
    }

    #[test]
    fn requires_init_is_true() {
        // MerkleTree is the first primitive whose initial state can't be
        // represented as StateValue::Null — it needs an explicit
        // constructor emission (deferred to Phase D).
        assert!(MerkleTree::<10, [u8; 32]>::requires_init());
    }
}
