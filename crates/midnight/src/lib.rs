//! midnight-edsl: A Rust eDSL for writing Midnight smart contracts.
//!
//! This is the umbrella crate that re-exports all public API items.

pub use midnight_macro::contract;
pub use midnight_macro::test;

/// Re-exports of all types used in contract definitions.
pub mod types {
    pub use midnight_storage::*;
    pub use midnight_types::*;
}

/// Re-exports of midnight-ledger runtime types for transcript construction.
pub mod runtime {
    pub use midnight_base_crypto as base_crypto;
    pub use midnight_ledger_storage as storage;
    pub use midnight_onchain_state as onchain_state;
    pub use midnight_onchain_vm as onchain_vm;
    pub use midnight_transient_crypto as transient_crypto;
    pub use midnight_zkir as zkir;
}
