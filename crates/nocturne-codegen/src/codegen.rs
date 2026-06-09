//! Top-level code generation orchestrator.

use crate::zkir_emitter::{self, ContractZkirOutput};
use nocturne_ir::ContractIR;

/// All generated artifacts for a single contract.
pub struct ContractArtifacts {
    /// ZKIR circuits (one per circuit function).
    pub zkir: ContractZkirOutput,
    /// Contract metadata JSON.
    pub contract_info_json: String,
}

/// Generate all artifacts for a contract.
///
/// Returns `Err` with the collected emission errors when any circuit
/// contains a construct the ZKIR emitter cannot lower soundly. Callers
/// (the proc macro) MUST fail compilation on `Err` — writing artifacts
/// for a circuit with silently dropped constructs would let a proof
/// verify while enforcing less than the contract source.
pub fn generate_artifacts(contract: &ContractIR) -> Result<ContractArtifacts, Vec<String>> {
    let zkir = zkir_emitter::emit_contract(contract);
    if !zkir.errors.is_empty() {
        return Err(zkir.errors);
    }

    let contract_info = nocturne_metadata::generate_contract_info(contract);
    let contract_info_json =
        serde_json::to_string_pretty(&contract_info).expect("failed to serialize contract info");

    Ok(ContractArtifacts {
        zkir,
        contract_info_json,
    })
}
