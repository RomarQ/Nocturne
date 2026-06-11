use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::{Attribute, Meta};

use crate::error::{ErrorCode, MidnightError, MidnightResult};

/// Classification of midnight item-level attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidnightAttr {
    Ledger,
    Witnesses,
    Circuit,
    Constructor,
    Query,
    Event,
    /// Field-level marker: this ledger field is internal and should
    /// not be advertised in `contract-info.json` as queryable.
    /// Default for a ledger field is `exported = true`.
    Private,
}

const KNOWN_ATTRS: &str = "ledger, witnesses, circuit, constructor, query, event, private";

impl MidnightAttr {
    /// Try to parse a midnight attribute from a `#[nocturne(...)]`
    /// attribute. `Ok(None)` means "not a nocturne attribute at all";
    /// a nocturne attribute with malformed or unknown contents is an
    /// error, never silently ignored.
    pub fn from_attribute(attr: &Attribute) -> MidnightResult<Option<Self>> {
        if !is_midnight_attr(attr) {
            return Ok(None);
        }
        match &attr.meta {
            Meta::List(_) => {
                // Exactly one ident, with an optional trailing comma.
                let ident: syn::Ident = attr
                    .parse_args_with(|input: syn::parse::ParseStream| {
                        let ident: syn::Ident = input.parse()?;
                        let _trailing: Option<syn::Token![,]> = input.parse()?;
                        if !input.is_empty() {
                            return Err(input.error("expected a single attribute argument"));
                        }
                        Ok(ident)
                    })
                    .map_err(|e| {
                        MidnightError::new(
                            e.span(),
                            ErrorCode::InvalidAttribute,
                            format!(
                                "malformed #[nocturne(...)] attribute ({e}); expected one of: \
                                 {KNOWN_ATTRS}"
                            ),
                        )
                    })?;
                match Self::from_str(&ident.to_string()) {
                    Some(kind) => Ok(Some(kind)),
                    None => Err(MidnightError::new(
                        ident.span(),
                        ErrorCode::InvalidAttribute,
                        format!(
                            "unknown nocturne attribute `{ident}`, expected one of: {KNOWN_ATTRS}"
                        ),
                    )),
                }
            }
            other => Err(MidnightError::new(
                other.span(),
                ErrorCode::InvalidAttribute,
                format!(
                    "the nocturne attribute takes exactly one argument: #[nocturne(<kind>)] \
                     with <kind> one of: {KNOWN_ATTRS}"
                ),
            )),
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
            "private" => Some(Self::Private),
            _ => None,
        }
    }
}

/// Check if an attribute's path is `nocturne`.
fn is_midnight_attr(attr: &Attribute) -> bool {
    attr.path().is_ident("nocturne")
}

/// Extract the midnight attribute from a list of attributes, returning
/// the attribute kind and its span. More than one `#[nocturne(...)]`
/// attribute on the same item is an error (first-wins would silently
/// drop the user's second annotation).
pub fn find_midnight_attr(attrs: &[Attribute]) -> MidnightResult<Option<(MidnightAttr, Span)>> {
    let mut found: Option<(MidnightAttr, Span)> = None;
    for attr in attrs {
        let Some(kind) = MidnightAttr::from_attribute(attr)? else {
            continue;
        };
        let span = attr.bracket_token.span.join();
        if found.is_some() {
            return Err(MidnightError::new(
                span,
                ErrorCode::InvalidAttribute,
                "duplicate #[nocturne(...)] attribute on the same item; \
                 an item takes exactly one nocturne attribute",
            ));
        }
        found = Some((kind, span));
    }
    Ok(found)
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
