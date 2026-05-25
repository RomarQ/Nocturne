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
    /// User-defined `struct` items in the contract module that don't
    /// carry a `#[nocturne(...)]` annotation. Indexed by the struct's
    /// outer ident; each entry is the named-field list in declaration
    /// order. Used by codegen to layout user structs as Map/Set keys
    /// (treats them like a named tuple of their fields).
    pub user_structs: std::collections::HashMap<String, Vec<UserStructField>>,
    /// User-defined `enum` items in the contract module. Today only
    /// unit-variant enums are recognized (no payloads). The on-chain
    /// encoding is `Bytes<1>` carrying the variant discriminant (0,
    /// 1, ...). Codegen uses this to lay out enums as Cell/Map values
    /// and to lower `match` arms to discriminant comparisons.
    pub user_enums: std::collections::HashMap<String, Vec<UserEnumVariant>>,
}

/// One field of a user-defined struct usable as a Map/Set key.
#[derive(Debug, Clone)]
pub struct UserStructField {
    pub name: Ident,
    pub ty: Type,
}

/// One variant of a user-defined enum. The discriminant is the
/// variant's index in declaration order. `payload` is `Some(T)` when
/// the variant carries a single unnamed field, `None` for unit
/// variants. Enums must be homogeneous — either all unit or all
/// payload-carrying with the same `T` — so the wire encoding is
/// statically a `(Bytes<1>, T)` tuple (or just `Bytes<1>` for the
/// unit case).
#[derive(Debug, Clone)]
pub struct UserEnumVariant {
    pub name: Ident,
    pub payload: Option<Type>,
}

/// IR for the `#[nocturne(ledger)]` struct.
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

/// IR for the `#[nocturne(witnesses)]` struct.
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

/// IR for a `#[nocturne(constructor)]` function.
#[derive(Debug)]
pub struct ConstructorIR {
    pub span: Span,
    pub name: Ident,
    pub params: Vec<ParamIR>,
    pub body: Vec<ExprIR>,
}

/// IR for a `#[nocturne(circuit)]` function.
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

/// IR for a `#[nocturne(query)]` function.
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
