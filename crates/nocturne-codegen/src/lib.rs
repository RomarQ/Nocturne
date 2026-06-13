//! Code generation for nocturne.
//!
//! The primary output is ZKIR (one `IrSource` per circuit). The ZKIR encodes
//! transcript VM operations as public inputs -- the proof demonstrates that
//! the prover's private computation is consistent with the public transcript.

mod aligned;
pub mod codegen;
pub mod deploy_codegen;
pub mod enum_helpers;
mod nocturne_type;
mod private_events;
pub mod transcript_codegen;
mod typing;
pub mod zkir_emitter;

#[cfg(test)]
mod private_events_tests;
#[cfg(test)]
mod transcript_tests;
#[cfg(test)]
mod zkir_check_tests;
#[cfg(test)]
mod zkir_tests;
