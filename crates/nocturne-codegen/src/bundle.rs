//! Contract bundle: packages all artifacts needed for deployment.
//!
//! A bundle contains everything a deployment tool (e.g., midnight-rs)
//! needs to deploy a contract and call its circuits:
//!
//! - Initial state (StateValue)
//! - ZKIR per circuit (IrSource, serializable to JSON)
//! - Contract metadata (contract-info.json)
//! - Entry point names
//!
//! The bundle does NOT construct `ContractDeploy` or `ContractCall`
//! directly, as those require the full `midnight-ledger` crate.
//! Instead, it provides the data in a format that deployment tools
//! can consume.

use midnight_zkir::IrSource;
use nocturne_ir::ContractIR;
use std::collections::HashMap;

/// A compiled contract bundle ready for deployment.
pub struct ContractBundle {
    /// Contract name.
    pub name: String,
    /// ZKIR circuit per entry point.
    pub circuits: HashMap<String, IrSource>,
    /// Contract metadata JSON.
    pub contract_info_json: String,
    /// Entry point names (circuit function names).
    pub entry_points: Vec<String>,
}

/// Build a ContractBundle from a ContractIR.
pub fn build_bundle(contract: &ContractIR) -> ContractBundle {
    let codegen = crate::codegen::generate_artifacts(contract);

    let circuits: HashMap<String, IrSource> = codegen
        .zkir
        .circuits
        .into_iter()
        .map(|c| (c.circuit_name, c.ir_source))
        .collect();

    let entry_points: Vec<String> = contract
        .circuits
        .iter()
        .map(|c| c.name.to_string())
        .collect();

    ContractBundle {
        name: contract.name.to_string(),
        circuits,
        contract_info_json: codegen.contract_info_json,
        entry_points,
    }
}
