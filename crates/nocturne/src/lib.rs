//! nocturne: A Rust eDSL for writing Midnight smart contracts.
//!
//! This is the umbrella crate that re-exports all public API items.

pub use nocturne_macro::contract;
pub use nocturne_macro::test;

/// Off-chain identity function for the `nocturne::disclose(_)` syntax.
///
/// The IR parser already detects this call by path and lowers it to
/// `ExprIR::Disclose` — the ZKIR emitter then emits the matching
/// `DeclarePubInput` + `PiSkip`. At plain Rust evaluation (e.g. the
/// user's transcript-builder call sites or `#[nocturne::test]`
/// helpers), the call has no on-chain semantics; it just yields the
/// value verbatim so the surrounding code type-checks.
#[inline]
pub fn disclose<T>(value: T) -> T {
    value
}

/// Re-exports of all types used in contract definitions.
pub mod types {
    pub use nocturne_storage::*;
    pub use nocturne_types::*;
}

/// Re-exports of midnight-ledger runtime types for transcript construction.
pub mod runtime {
    pub use midnight_base_crypto as base_crypto;
    pub use midnight_storage as storage;
    pub use midnight_onchain_state as onchain_state;
    pub use midnight_onchain_vm as onchain_vm;
    pub use midnight_transient_crypto as transient_crypto;
    pub use midnight_zkir as zkir;
}
