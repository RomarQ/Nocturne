//! Contract metadata serialization for nocturne.
//!
//! Generates `contract-info.json` compatible with the Midnight ecosystem.

use nocturne_ir::ContractIR;
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
    /// One entry per `#[nocturne(ledger)]` struct field, in declaration
    /// order. Mirrors compactc's `ledger[]` so downstream tooling
    /// (indexers, off-chain readers, type-binding generators) can
    /// discover which state slots are queryable and where they live.
    #[serde(default)]
    pub ledger: Vec<LedgerFieldInfo>,
    #[serde(default)]
    pub contracts: Vec<String>,
}

/// One entry in `contract-info.json`'s `ledger[]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LedgerFieldInfo {
    pub name: String,
    /// Declaration-order index of the field in the ledger struct.
    /// Same as the implicit slot index the on-chain VM uses.
    pub index: u32,
    /// Whether downstream tools should advertise this field as
    /// queryable. Defaults to `true`; opt out per field with
    /// `#[nocturne(private)]`.
    pub exported: bool,
    #[serde(rename = "type")]
    pub ty: TypeDescriptor,
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
        // Static witness fields come first (no arguments, type is the
        // field's type). Parametric witness methods follow, carrying
        // their declared parameter list. Compactc's schema treats both
        // shapes uniformly under `witnesses[]`.
        let mut out: Vec<WitnessInfo> = w
            .fields
            .iter()
            .map(|f| {
                let type_name = type_to_string(&f.ty);
                WitnessInfo {
                    name: format!("private${}", f.name),
                    arguments: vec![],
                    result_type: TypeDescriptor::from_type_str(&type_name),
                }
            })
            .collect();
        for m in &w.methods {
            let arguments = m
                .params
                .iter()
                .map(|p| ArgumentInfo {
                    name: p.name.to_string(),
                    ty: TypeDescriptor::from_type_str(&type_to_string(&p.ty)),
                })
                .collect();
            out.push(WitnessInfo {
                name: format!("private${}", m.name),
                arguments,
                result_type: TypeDescriptor::from_type_str(&type_to_string(&m.return_type)),
            });
        }
        out
    } else {
        vec![]
    };

    let ledger = contract
        .ledger
        .fields
        .iter()
        .enumerate()
        .map(|(i, f)| LedgerFieldInfo {
            name: f.name.to_string(),
            index: i as u32,
            exported: f.exported,
            ty: TypeDescriptor::from_type_str(&type_to_string(&f.ty)),
        })
        .collect();

    ContractInfo {
        compiler_version: format!("nocturne {}", env!("CARGO_PKG_VERSION")),
        language_version: "1.0".to_string(),
        runtime_version: "1.0".to_string(),
        circuits,
        witnesses,
        ledger,
        contracts: vec![],
    }
}
