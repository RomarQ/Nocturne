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
pub fn generate_artifacts(contract: &ContractIR) -> ContractArtifacts {
    let zkir = zkir_emitter::emit_contract(contract);

    let contract_info = nocturne_metadata::generate_contract_info(contract);
    let contract_info_json =
        serde_json::to_string_pretty(&contract_info).expect("failed to serialize contract info");

    ContractArtifacts {
        zkir,
        contract_info_json,
    }
}
