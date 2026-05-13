use proc_macro2::{Ident, Span};
use syn::Type;

use crate::expr::ExprIR;

/// Root IR node representing an entire midnight contract.
#[derive(Debug)]
pub struct ContractIR {
    /// The module name.
    pub name: Ident,
    /// The module span (for error reporting).
    pub span: Span,
    /// Public on-chain ledger state.
    pub ledger: LedgerIR,
    /// Private off-chain witness state (optional).
    pub witnesses: Option<WitnessIR>,
    /// Constructor function(s).
    pub constructors: Vec<ConstructorIR>,
    /// Circuit (transition) functions.
    pub circuits: Vec<CircuitIR>,
    /// Read-only query functions.
    pub queries: Vec<QueryIR>,
    /// All other items in the module (passed through unchanged).
    pub other_items: Vec<syn::Item>,
}

/// IR for the `#[midnight(ledger)]` struct.
#[derive(Debug)]
pub struct LedgerIR {
    pub span: Span,
    pub name: Ident,
    pub fields: Vec<LedgerFieldIR>,
}

/// A single field in the ledger struct.
#[derive(Debug)]
pub struct LedgerFieldIR {
    pub span: Span,
    pub name: Ident,
    pub ty: Type,
    /// The outer type name (e.g., "Counter", "Cell", "Map", "MerkleTree").
    pub type_kind: LedgerTypeKind,
}

/// Classification of ledger field types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerTypeKind {
    Counter,
    Cell,
    Map,
    MerkleTree,
    Array,
    Set,
    /// Unknown/unresolved -- will produce an error during validation.
    Unknown(String),
}

impl LedgerTypeKind {
    pub fn from_type_name(name: &str) -> Self {
        match name {
            "Counter" => Self::Counter,
            "Cell" => Self::Cell,
            "Map" => Self::Map,
            "MerkleTree" => Self::MerkleTree,
            "Array" => Self::Array,
            "Set" => Self::Set,
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// IR for the `#[midnight(witnesses)]` struct.
#[derive(Debug)]
pub struct WitnessIR {
    pub span: Span,
    pub name: Ident,
    pub fields: Vec<WitnessFieldIR>,
}

/// A single field in the witnesses struct.
#[derive(Debug)]
pub struct WitnessFieldIR {
    pub span: Span,
    pub name: Ident,
    pub ty: Type,
}

/// IR for a `#[midnight(constructor)]` function.
#[derive(Debug)]
pub struct ConstructorIR {
    pub span: Span,
    pub name: Ident,
    pub params: Vec<ParamIR>,
    pub body: Vec<ExprIR>,
}

/// IR for a `#[midnight(circuit)]` function.
#[derive(Debug)]
pub struct CircuitIR {
    pub span: Span,
    pub name: Ident,
    /// Non-witness parameters (public circuit inputs).
    pub params: Vec<ParamIR>,
    /// Whether this circuit takes a witnesses parameter.
    pub takes_witnesses: bool,
    /// The name of the witnesses parameter (e.g., "witnesses").
    pub witnesses_param_name: Option<Ident>,
    /// Whether this circuit mutates ledger state (&mut self vs &self).
    pub mutates_ledger: bool,
    /// The circuit body as an expression tree.
    pub body: Vec<ExprIR>,
    /// Return type (None = unit).
    pub return_type: Option<Type>,
}

/// IR for a `#[midnight(query)]` function.
#[derive(Debug)]
pub struct QueryIR {
    pub span: Span,
    pub name: Ident,
    pub params: Vec<ParamIR>,
    pub return_type: Option<Type>,
    pub body: Vec<ExprIR>,
}

/// A function parameter.
#[derive(Debug)]
pub struct ParamIR {
    pub span: Span,
    pub name: Ident,
    pub ty: Type,
}
