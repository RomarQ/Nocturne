use proc_macro2::{Ident, Span};
use syn::{BinOp, Lit, UnOp};

/// Expression IR for circuit/constructor/query function bodies.
///
/// This is the key divergence from ink!: we must deeply analyze function
/// bodies to emit ZKIR instructions and VM bytecode. ink! passes bodies
/// through verbatim to the Wasm compiler.
#[derive(Debug, Clone)]
pub enum ExprIR {
    /// Access a ledger field's method: `self.field.method(args)`.
    LedgerAccess {
        span: Span,
        field: Ident,
        method: Ident,
        args: Vec<ExprIR>,
    },

    /// Read a witness field: `witnesses.field`.
    WitnessAccess { span: Span, field: Ident },

    /// Binary operation: `a + b`, `a * b`, `a == b`, etc.
    BinaryOp {
        span: Span,
        op: BinOp,
        lhs: Box<ExprIR>,
        rhs: Box<ExprIR>,
    },

    /// Unary operation: `-a`, `!a`.
    UnaryOp {
        span: Span,
        op: UnOp,
        expr: Box<ExprIR>,
    },

    /// Function call: `persistent_hash(&x)`, `Uint::<64>::from(0u64)`, etc.
    ///
    /// `name` is the last segment of the callee path (used by codegen
    /// dispatch to recognise builtins by short name like `persistent_hash`).
    /// `path` is the full callee path including generic arguments, used
    /// to reconstruct the call verbatim in transcript-side codegen when
    /// the callee isn't a recognised builtin (e.g. `Uint::<64>::from`).
    FnCall {
        span: Span,
        name: Ident,
        path: syn::Path,
        args: Vec<ExprIR>,
    },

    /// Method call on a non-self value: `value.into()`.
    MethodCall {
        span: Span,
        receiver: Box<ExprIR>,
        method: Ident,
        args: Vec<ExprIR>,
    },

    /// Let binding: `let x = expr`.
    Let {
        span: Span,
        name: Ident,
        value: Box<ExprIR>,
    },

    /// If/else: `if cond { then } else { otherwise }`.
    If {
        span: Span,
        cond: Box<ExprIR>,
        then_branch: Vec<ExprIR>,
        else_branch: Option<Vec<ExprIR>>,
    },

    /// `assert!(cond)` or `assert_eq!(a, b)`.
    Assert { span: Span, kind: AssertKind },

    /// `nocturne::disclose(value)`.
    Disclose { span: Span, value: Box<ExprIR> },

    /// A literal value: integer, bool, string, bytes.
    Literal { span: Span, value: LiteralIR },

    /// A local variable reference.
    Var { span: Span, name: Ident },

    /// A multi-segment path expression, e.g. `Status::Open` or
    /// `Self::CONST`. Stored as a `syn::Path` so codegen can emit it
    /// verbatim — unlike `Var`, the path may contain `::` and is not a
    /// valid single `Ident`.
    Path { span: Span, path: syn::Path },

    /// Projection of the payload out of a homogeneous-payload enum
    /// value. Lowered by `match` arm parsing: `match a { V(x) => … }`
    /// prepends `let x = EnumPayload { scrutinee: a, enum_name: "V's enum" }`
    /// to the arm body. Codegen specialises both sides:
    ///
    /// - ZKIR: returns the scrutinee's wire shifted by the
    ///   discriminant width (1 wire today), pointing at the payload's
    ///   first PrivateInput.
    /// - Runtime: emits a Rust `match` over `scrutinee` that binds
    ///   the inner payload from every variant arm (all arms bind the
    ///   same name since the payload type is homogeneous).
    EnumPayload {
        span: Span,
        scrutinee: Box<ExprIR>,
        enum_name: Ident,
    },

    /// `arr[index]` where `arr` is a fixed-size `[T; N]` value and
    /// `index` is a compile-time constant (always literal after
    /// `parse_const_for_loop` substitution). At the ZKIR layer this
    /// lowers to `array.first + index * layout_len(T)`; at the
    /// transcript layer it stays as Rust `arr[index]`.
    Index {
        span: Span,
        array: Box<ExprIR>,
        index: u32,
    },

    /// A block of statements.
    Block { span: Span, stmts: Vec<ExprIR> },

    /// Struct construction: `Self { field: value, ... }`.
    StructInit {
        span: Span,
        name: Ident,
        fields: Vec<(Ident, ExprIR)>,
    },

    /// A return expression.
    Return {
        span: Span,
        value: Option<Box<ExprIR>>,
    },

    /// Tuple expression: `(a, b)`.
    Tuple { span: Span, elements: Vec<ExprIR> },

    /// A reference: `&expr`.
    Reference { span: Span, expr: Box<ExprIR> },

    /// Expression we couldn't parse -- stored for error reporting.
    Unsupported { span: Span, description: String },
}

/// Classification of assert expressions.
#[derive(Debug, Clone)]
pub enum AssertKind {
    /// `assert!(cond)`
    Assert(Box<ExprIR>),
    /// `assert_eq!(a, b)`
    AssertEq(Box<ExprIR>, Box<ExprIR>),
}

/// Literal values in the IR.
#[derive(Debug, Clone)]
pub enum LiteralIR {
    Int(u128),
    Bool(bool),
    Str(String),
}

impl LiteralIR {
    pub fn from_lit(lit: &Lit) -> Option<Self> {
        match lit {
            Lit::Int(i) => i.base10_parse::<u128>().ok().map(Self::Int),
            Lit::Bool(b) => Some(Self::Bool(b.value)),
            Lit::Str(s) => Some(Self::Str(s.value())),
            _ => None,
        }
    }
}
