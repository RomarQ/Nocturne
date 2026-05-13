//! Intermediate representation for midnight-edsl contracts.
//!
//! This crate parses Rust token streams annotated with midnight attributes
//! into a structured IR, and validates the contract structure.

mod attrs;
mod contract;
mod error;
pub mod expr;
mod parse;
#[cfg(test)]
mod parse_tests;

pub use contract::*;
pub use error::{MidnightError, MidnightResult};
pub use expr::ExprIR;
pub use parse::parse_contract;
