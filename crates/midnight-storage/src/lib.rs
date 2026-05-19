//! Ledger storage abstractions for midnight-edsl contracts.
//!
//! These types map to midnight-ledger's `StateValue` variants at the VM level.
//! In test mode they use simple Rust backing stores.

mod cell;
mod counter;
mod map;
mod merkle_tree;
mod merkle_tree_path;
mod set;

pub use cell::Cell;
pub use counter::Counter;
pub use map::Map;
pub use merkle_tree::{MerkleLeaf, MerkleTree};
pub use merkle_tree_path::merkle_tree_path_root;
pub use set::Set;

/// Marker trait for types that can live in ledger (on-chain) state.
pub trait LedgerType: Sized {
    /// Whether this type requires initialization at deploy time.
    fn requires_init() -> bool;
}
