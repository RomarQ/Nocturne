use crate::{Field, ZkType};
use std::fmt;

/// A Merkle-tree root digest. Mirrors Compact's `MerkleTreeDigest { field: Field }`
/// (from `standard-library.compact:50`) — a single field element representing
/// the root hash.
///
/// On-chain this is `AlignedValue` with `AlignmentAtom::Field` alignment;
/// see [`field-alignment-encoding`] for the encoding work that landed in
/// Phase A and that this type depends on.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MerkleTreeDigest {
    pub field: Field,
}

impl MerkleTreeDigest {
    pub fn new(field: Field) -> Self {
        Self { field }
    }

    pub fn field(&self) -> Field {
        self.field
    }
}

impl From<Field> for MerkleTreeDigest {
    fn from(field: Field) -> Self {
        Self { field }
    }
}

impl From<MerkleTreeDigest> for Field {
    fn from(d: MerkleTreeDigest) -> Self {
        d.field
    }
}

impl fmt::Debug for MerkleTreeDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleTreeDigest({:?})", self.field)
    }
}

impl ZkType for MerkleTreeDigest {
    fn field_count() -> usize {
        1
    }
}
