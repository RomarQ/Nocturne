use proc_macro2::Span;
use syn::{Attribute, Meta};

/// Classification of midnight item-level attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidnightAttr {
    Ledger,
    Witnesses,
    Circuit,
    Constructor,
    Query,
    Event,
    StateType,
    /// Field-level marker: this ledger field is internal and should
    /// not be advertised in `contract-info.json` as queryable.
    /// Default for a ledger field is `exported = true`.
    Private,
}

impl MidnightAttr {
    /// Try to parse a midnight attribute from a `#[nocturne(...)]` attribute.
    pub fn from_attribute(attr: &Attribute) -> Option<Self> {
        if !is_midnight_attr(attr) {
            return None;
        }
        match &attr.meta {
            Meta::List(list) => {
                let tokens = list.tokens.to_string();
                let ident = tokens.trim();
                Self::from_str(ident)
            }
            _ => None,
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "ledger" => Some(Self::Ledger),
            "witnesses" => Some(Self::Witnesses),
            "circuit" => Some(Self::Circuit),
            "constructor" => Some(Self::Constructor),
            "query" => Some(Self::Query),
            "event" => Some(Self::Event),
            "state_type" => Some(Self::StateType),
            "private" => Some(Self::Private),
            _ => None,
        }
    }
}

/// Check if an attribute's path is `midnight`.
fn is_midnight_attr(attr: &Attribute) -> bool {
    attr.path().is_ident("nocturne")
}

/// Extract the first midnight attribute from a list of attributes.
/// Returns the attribute kind and its span.
pub fn find_midnight_attr(attrs: &[Attribute]) -> Option<(MidnightAttr, Span)> {
    for attr in attrs {
        if let Some(kind) = MidnightAttr::from_attribute(attr) {
            return Some((kind, attr.bracket_token.span.join()));
        }
    }
    None
}

/// Remove midnight attributes from a list, returning the cleaned attrs.
#[allow(dead_code)]
pub fn strip_midnight_attrs(attrs: &[Attribute]) -> Vec<Attribute> {
    attrs
        .iter()
        .filter(|a| !is_midnight_attr(a))
        .cloned()
        .collect()
}
