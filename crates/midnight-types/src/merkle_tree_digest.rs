use crate::{Field, ZkType};
use std::fmt;

/// A Merkle-tree root digest. Mirrors Compact's `MerkleTreeDigest { field: Field }`
/// (from `standard-library.compact:50`) — a single field element representing
/// the root hash.
///
/// **Canonical representation**: 32 little-endian bytes of the upstream
/// `Fr` (matches `transient_crypto::curve::Fr::as_le_bytes`). The
/// `field()` accessor returns the low 128 bits as our `Field` newtype,
/// for ergonomic equality/comparison against `Field::from(literal)`
/// in tests; it is *not* the canonical form.
///
/// On-chain this is `AlignedValue` with `AlignmentAtom::Field` alignment;
/// the full 254-bit Fr must be transmitted to the verifier or proofs
/// chained through this digest break (see `merkle_tree_path_root`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MerkleTreeDigest {
    bytes: [u8; 32],
}

impl MerkleTreeDigest {
    /// Construct a digest from a `Field`. The low 128 bits are populated
    /// from the field; the upper 128 bits are zero. Sufficient for
    /// synthetic test digests; for real Merkle roots use
    /// [`from_le_bytes`](Self::from_le_bytes).
    pub fn new(field: Field) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&field.value().to_le_bytes());
        Self { bytes }
    }

    /// Construct from raw 32 little-endian Fr bytes. Used by storage
    /// helpers that produce real Merkle roots (`MerkleTree::root`,
    /// `merkle_tree_path_root`) where the full Fr must round-trip.
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// The low 128 bits of the digest as a `Field`. Lossy for real
    /// Merkle roots; intended for tests and equality against small
    /// `Field::from(literal)` values.
    pub fn field(&self) -> Field {
        let mut low = [0u8; 16];
        low.copy_from_slice(&self.bytes[..16]);
        Field::from(u128::from_le_bytes(low))
    }

    /// The canonical 32-byte little-endian Fr representation. Use this
    /// to reconstruct the full `Fr` (via
    /// `transient_crypto::curve::Fr::from_le_bytes`) when pushing the
    /// digest into the circuit / private transcript.
    pub fn as_le_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

impl Default for MerkleTreeDigest {
    fn default() -> Self {
        Self::from_le_bytes([0u8; 32])
    }
}

impl From<Field> for MerkleTreeDigest {
    fn from(field: Field) -> Self {
        Self::new(field)
    }
}

impl From<MerkleTreeDigest> for Field {
    fn from(d: MerkleTreeDigest) -> Self {
        d.field()
    }
}

impl fmt::Debug for MerkleTreeDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleTreeDigest(0x")?;
        for b in self.bytes.iter().rev() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

impl ZkType for MerkleTreeDigest {
    fn field_count() -> usize {
        1
    }
}
