//! Contract metadata serialization for midnight-edsl.
//!
//! Generates `contract-info.json` compatible with the Midnight ecosystem.

use midnight_ir::ContractIR;
use serde::{Deserialize, Serialize};

/// Contract metadata matching Midnight's contract-info.json schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ContractInfo {
    pub compiler_version: String,
    pub language_version: String,
    pub runtime_version: String,
    pub circuits: Vec<CircuitInfo>,
    pub witnesses: Vec<WitnessInfo>,
    #[serde(default)]
    pub contracts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CircuitInfo {
    pub name: String,
    pub pure: bool,
    pub proof: bool,
    pub arguments: Vec<ArgumentInfo>,
    pub result_type: TypeDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WitnessInfo {
    pub name: String,
    pub arguments: Vec<ArgumentInfo>,
    pub result_type: TypeDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgumentInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TypeDescriptor {
    pub type_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<TypeDescriptor>>,
}

impl TypeDescriptor {
    pub fn void() -> Self {
        Self {
            type_name: "Tuple".to_string(),
            length: None,
            types: Some(vec![]),
        }
    }

    pub fn field() -> Self {
        Self {
            type_name: "Field".to_string(),
            length: None,
            types: None,
        }
    }

    pub fn boolean() -> Self {
        Self {
            type_name: "Boolean".to_string(),
            length: None,
            types: None,
        }
    }

    pub fn from_type_str(s: &str) -> Self {
        match s {
            "Field" => Self::field(),
            "Boolean" => Self::boolean(),
            _ => Self {
                type_name: s.to_string(),
                length: None,
                types: None,
            },
        }
    }
}

/// Extract a type name string from a syn::Type.
fn type_to_string(ty: &syn::Type) -> String {
    use quote::ToTokens;
    ty.to_token_stream().to_string().replace(' ', "")
}

/// Generate contract-info.json from a ContractIR.
pub fn generate_contract_info(contract: &ContractIR) -> ContractInfo {
    let circuits = contract
        .circuits
        .iter()
        .map(|c| {
            let arguments = c
                .params
                .iter()
                .map(|p| ArgumentInfo {
                    name: p.name.to_string(),
                    ty: TypeDescriptor::from_type_str(&type_to_string(&p.ty)),
                })
                .collect();

            CircuitInfo {
                name: c.name.to_string(),
                pure: !c.mutates_ledger,
                proof: true,
                arguments,
                result_type: match &c.return_type {
                    Some(ty) => TypeDescriptor::from_type_str(&type_to_string(ty)),
                    None => TypeDescriptor::void(),
                },
            }
        })
        .collect();

    let witnesses = if let Some(w) = &contract.witnesses {
        w.fields
            .iter()
            .map(|f| {
                let type_name = type_to_string(&f.ty);
                WitnessInfo {
                    name: format!("private${}", f.name),
                    arguments: vec![],
                    result_type: TypeDescriptor::from_type_str(&type_name),
                }
            })
            .collect()
    } else {
        vec![]
    };

    ContractInfo {
        compiler_version: format!("midnight-edsl {}", env!("CARGO_PKG_VERSION")),
        language_version: "1.0".to_string(),
        runtime_version: "1.0".to_string(),
        circuits,
        witnesses,
        contracts: vec![],
    }
}
