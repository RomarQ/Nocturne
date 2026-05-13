//! Code generation for midnight-edsl.
//!
//! The primary output is ZKIR (one `IrSource` per circuit). The ZKIR encodes
//! transcript VM operations as public inputs -- the proof demonstrates that
//! the prover's private computation is consistent with the public transcript.

pub mod bundle;
pub mod codegen;
pub mod deploy_codegen;
pub mod transcript_codegen;
pub mod zkir_emitter;

#[cfg(test)]
mod zkir_check_tests;
#[cfg(test)]
mod zkir_tests;
