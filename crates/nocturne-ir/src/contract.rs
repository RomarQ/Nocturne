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
    /// Free `fn` items in the contract module that are eligible to be
    /// inlined into circuit bodies at ZKIR emit time. Mirrors compactc's
    /// model where a non-export `circuit` is purely a compile-time
    /// macro: every call site gets the body spliced in.
    ///
    /// At parse time the body is recorded on `HelperIR.body` but the
    /// original `fn` item also stays in `other_items` so the user's
    /// Rust code keeps compiling — the transcript-side codegen calls
    /// the helper as a regular Rust function via the path-preserving
    /// `FnCall` arm.
    pub helpers: Vec<HelperIR>,
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
    /// Whether the field is advertised as queryable in
    /// `contract-info.json`. Defaults to `true`; opt out by tagging the
    /// field with `#[nocturne(private)]`. Mirrors compactc's per-field
    /// `exported: bool` so indexers / off-chain readers can discover
    /// which fields are publicly readable.
    pub exported: bool,
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
    /// Parametric witness methods declared in an `impl <WitnessName>`
    /// block in the user's contract module. Each method becomes a
    /// `WitnessCall` site at the IR layer — at runtime the transcript
    /// builder invokes the user-supplied method to compute the witness
    /// value (vs `WitnessFieldIR` which reads a pre-supplied field).
    /// The method's body stays in user code; the proc macro only
    /// records its signature.
    pub methods: Vec<WitnessMethodIR>,
}

/// A single field in the witnesses struct.
#[derive(Debug)]
pub struct WitnessFieldIR {
    pub span: Span,
    pub name: Ident,
    pub ty: Type,
}

/// A parametric witness method (e.g. `fn salted_hash(&self, salt:
/// Bytes<32>) -> Bytes<32>`). The method's body stays in the user's
/// `impl` block; the IR carries only the signature so codegen knows
/// how many PrivateInputs to allocate (return type's wire layout) and
/// how to invoke the method at transcript-build time.
#[derive(Debug)]
pub struct WitnessMethodIR {
    pub span: Span,
    pub name: Ident,
    pub params: Vec<ParamIR>,
    pub return_type: Type,
}

/// A free `fn` item declared inside the contract module that's
/// eligible for inlining at ZKIR emit time. The body is parsed into
/// `ExprIR` exactly like a circuit body; the ZKIR emitter splices it
/// into call sites with arg substitution and alpha-renaming. The
/// transcript codegen does NOT consume this — it keeps calling the
/// user's Rust `fn` directly via the path-preserving FnCall arm, and
/// the two views agree because both execute the same body.
#[derive(Debug)]
pub struct HelperIR {
    pub span: Span,
    pub name: Ident,
    pub params: Vec<ParamIR>,
    pub return_type: Type,
    pub body: Vec<ExprIR>,
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
