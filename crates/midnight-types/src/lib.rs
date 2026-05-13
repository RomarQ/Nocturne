//! Primitive ZK-compatible types for midnight-edsl contracts.
//!
//! Provides `Field`, `Boolean`, `Bytes<N>`, and `Uint<N>`.
//!
//! In test mode these behave as normal Rust values.
//! During codegen they serve as type-level markers for ZKIR instruction selection.

mod boolean;
mod bytes;
mod field;
mod uint;

pub use boolean::Boolean;
pub use bytes::Bytes;
pub use field::Field;
pub use uint::Uint;

/// Marker trait for types that can be represented in a ZK circuit.
pub trait ZkType: Sized {
    /// Number of field elements needed to represent this type.
    fn field_count() -> usize;
}
