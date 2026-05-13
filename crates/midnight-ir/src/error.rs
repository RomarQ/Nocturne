use proc_macro2::Span;

/// Result type for midnight IR operations.
pub type MidnightResult<T> = Result<T, MidnightError>;

/// An error encountered during contract parsing or validation.
#[derive(Debug)]
pub struct MidnightError {
    pub span: Span,
    pub code: ErrorCode,
    pub message: String,
}

impl MidnightError {
    pub fn new(span: Span, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            span,
            code,
            message: message.into(),
        }
    }

    /// Convert to a compile error token stream.
    pub fn to_compile_error(&self) -> proc_macro2::TokenStream {
        let msg = format!("[{}] {}", self.code.as_str(), self.message);
        syn::Error::new(self.span, msg).to_compile_error()
    }
}

/// Categorized error codes per SPEC section 14.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // MIDNIGHT-0xx: Type system violations
    InvalidType,
    NonZkType,

    // MIDNIGHT-1xx: Contract structure violations
    MissingLedger,
    DuplicateLedger,
    DuplicateWitnesses,
    MissingCircuit,
    InvalidConstructorReturn,
    QueryMustBeImmutable,

    // MIDNIGHT-2xx: Privacy model violations
    WitnessTypeMismatch,

    // MIDNIGHT-3xx: Circuit constraint violations
    UnsupportedExpression,
    UnsupportedLoop,
    UnsupportedRecursion,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidType => "MIDNIGHT-001",
            Self::NonZkType => "MIDNIGHT-002",
            Self::MissingLedger => "MIDNIGHT-100",
            Self::DuplicateLedger => "MIDNIGHT-101",
            Self::DuplicateWitnesses => "MIDNIGHT-102",
            Self::MissingCircuit => "MIDNIGHT-103",
            Self::InvalidConstructorReturn => "MIDNIGHT-104",
            Self::QueryMustBeImmutable => "MIDNIGHT-105",
            Self::WitnessTypeMismatch => "MIDNIGHT-200",
            Self::UnsupportedExpression => "MIDNIGHT-300",
            Self::UnsupportedLoop => "MIDNIGHT-301",
            Self::UnsupportedRecursion => "MIDNIGHT-302",
        }
    }
}

/// Collect multiple errors and emit them all as a combined compile_error.
pub struct Diagnostics {
    errors: Vec<MidnightError>,
}

impl Diagnostics {
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    pub fn push(&mut self, error: MidnightError) {
        self.errors.push(error);
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    #[allow(dead_code)]
    pub fn to_compile_errors(&self) -> proc_macro2::TokenStream {
        let errors = self.errors.iter().map(|e| e.to_compile_error());
        quote::quote! { #(#errors)* }
    }

    pub fn into_first_error(mut self) -> MidnightError {
        self.errors.remove(0)
    }
}
