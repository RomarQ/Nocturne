//! A resolved, type-only view of a contract value type.
//!
//! The ZKIR emitter computes two things from a `syn::Type` that MUST
//! agree: the on-chain `AlignedValue` shape (`alignment_atoms` +
//! `value_field_count`) and the per-Fr constraint layout (`FrLayout`).
//! Historically each was its own recursion over `syn::Type` with the
//! same precedence (Option, enum, tuple, array, struct, primitives)
//! duplicated by hand, and when they disagreed on a composite type's Fr
//! count the verifier's public-input window shifted (the H4 bug class
//! from the 2026-06 review).
//!
//! `resolve` walks a `syn::Type` once into a `NocturneType`; the encoding
//! computations are then methods over the resolved enum, so the value
//! field count and the Fr-layout length are derived from a single source
//! and cannot drift.
//!
//! Witness-only types (`MerkleTreePath<H, T>`, `MerkleTreePathEntry`)
//! never become an on-chain `AlignedValue`, so they are deliberately NOT
//! part of this enum; `witness_fr_layout` keeps handling them directly.

use std::collections::HashMap;

use crate::typing::parse_uint_type;

/// Bytes that fit in one Fr's field representation (mirrors
/// `transient_crypto::curve::FR_BYTES_STORED` = `FR_BYTES - 1`).
pub(crate) const FR_BYTES_STORED: u32 = 31;

/// Per-Fr constraint kind for one input/read Fr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrLayout {
    /// Apply `ConstrainBits { var, bits }`.
    Bits(u32),
    /// Apply `ConstrainToBoolean { var }`.
    Boolean,
    /// No constraint (native field element: `Field`, `MerkleTreeDigest`).
    Field,
}

/// On-chain `AlignedValue` shape for a resolved type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlignedEncoding {
    /// Signed Fr atoms. `[0]` is the segment/atom count; the rest are
    /// `Bytes{N}` lengths (positive) or `-2` for `AlignmentAtom::Field`.
    pub alignment_atoms: Vec<i32>,
    /// Number of Frs the value occupies.
    pub value_field_count: usize,
}

/// The registry of user-declared ADTs needed to resolve named types.
pub(crate) struct TypeCtx<'a> {
    pub structs: &'a HashMap<String, Vec<nocturne_ir::UserStructField>>,
    pub enums: &'a HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
}

impl<'a> TypeCtx<'a> {
    pub(crate) fn new(
        structs: &'a HashMap<String, Vec<nocturne_ir::UserStructField>>,
        enums: &'a HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
    ) -> Self {
        Self { structs, enums }
    }
}

/// A resolved contract value type. Covers exactly the types that have an
/// on-chain `AlignedValue` encoding (the shared domain of the two
/// computations that must agree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NocturneType {
    /// `Boolean` / `bool` — encoded as `Bytes<1>`.
    Bool,
    /// `Field` — native Fr, `AlignmentAtom::Field`.
    Field,
    /// `MerkleTreeDigest` — Field-aligned newtype, same wire shape as `Field`.
    MerkleTreeDigest,
    /// `Uint<N>` / `uN` — `Bytes<ceil(N/8)>`; `N` is the bit width.
    Uint(u32),
    /// `Bytes<N>`.
    Bytes(u32),
    /// `Option<T>` — `(Bytes<1>, T)`.
    Option(Box<NocturneType>),
    /// Tuple — flat concatenation of component encodings.
    Tuple(Vec<NocturneType>),
    /// `[T; N]` — N-tuple of `T`.
    Array(Box<NocturneType>, u32),
    /// User struct — encoded as a tuple of its field types.
    Struct(Vec<NocturneType>),
    /// User enum, all-unit variants — `Bytes<1>` discriminant only.
    EnumUnit,
    /// User enum, homogeneous payload — `(Bytes<1>, T)`.
    EnumPayload(Box<NocturneType>),
}

/// Walk a `syn::Type` into a `NocturneType`, or `None` for types outside
/// the aligned-value domain (witness-only `MerkleTreePath`, unsupported
/// types). The precedence mirrors the historical `aligned_value_encoding`
/// exactly: Option, then user enum, then tuple, then array, then user
/// struct, then the primitive string match.
pub(crate) fn resolve(ty: &syn::Type, ctx: &TypeCtx) -> Option<NocturneType> {
    // `Option<T>` before the generic path match (it is a path too).
    if let Some(payload) = option_payload_type(ty) {
        return Some(NocturneType::Option(Box::new(resolve(&payload, ctx)?)));
    }

    // User enum, matched by the last path segment's ident.
    if let syn::Type::Path(tp) = ty
        && tp.qself.is_none()
        && let Some(seg) = tp.path.segments.last()
        && let Some(variants) = ctx.enums.get(&seg.ident.to_string())
    {
        return match variants.first().and_then(|v| v.payload.clone()) {
            None => Some(NocturneType::EnumUnit),
            Some(p) => Some(NocturneType::EnumPayload(Box::new(resolve(&p, ctx)?))),
        };
    }

    if let syn::Type::Tuple(tt) = ty {
        let comps = tt
            .elems
            .iter()
            .map(|e| resolve(e, ctx))
            .collect::<Option<Vec<_>>>()?;
        return Some(NocturneType::Tuple(comps));
    }

    if let syn::Type::Array(arr) = ty
        && let Some(n) = array_len(arr)
    {
        return Some(NocturneType::Array(Box::new(resolve(&arr.elem, ctx)?), n));
    }

    // User struct, matched by the last path segment's ident. Encoded
    // identically to a tuple of its field types.
    if let syn::Type::Path(tp) = ty
        && tp.qself.is_none()
        && let Some(seg) = tp.path.segments.last()
        && let Some(fields) = ctx.structs.get(&seg.ident.to_string())
    {
        let comps = fields
            .iter()
            .map(|f| resolve(&f.ty, ctx))
            .collect::<Option<Vec<_>>>()?;
        return Some(NocturneType::Struct(comps));
    }

    // Primitives, by canonical space-stripped string.
    let s = quote::quote!(#ty).to_string().replace(' ', "");
    if s == "Boolean" || s == "bool" {
        return Some(NocturneType::Bool);
    }
    if s == "Field" {
        return Some(NocturneType::Field);
    }
    if s == "MerkleTreeDigest" {
        return Some(NocturneType::MerkleTreeDigest);
    }
    if let Some(bits) = parse_uint_type(&s) {
        return Some(NocturneType::Uint(bits));
    }
    if let Some(n) = s
        .strip_prefix("Bytes<")
        .and_then(|x| x.strip_suffix('>'))
        .and_then(|x| x.parse::<u32>().ok())
        .filter(|n| *n > 0)
    {
        return Some(NocturneType::Bytes(n));
    }

    None
}

impl NocturneType {
    /// The on-chain `AlignedValue` shape. `None` only for `Uint` widths
    /// above the ~253-bit single-Fr limit (preserving the historical
    /// `aligned_value_encoding` guard).
    pub(crate) fn aligned_encoding(&self) -> Option<AlignedEncoding> {
        match self {
            NocturneType::Bool => Some(AlignedEncoding {
                alignment_atoms: vec![1, 1],
                value_field_count: 1,
            }),
            NocturneType::Field | NocturneType::MerkleTreeDigest => Some(AlignedEncoding {
                alignment_atoms: vec![1, -2],
                value_field_count: 1,
            }),
            NocturneType::Uint(bits) => {
                let bytes = bits.div_ceil(8);
                if *bits > 0 && *bits <= 253 {
                    Some(AlignedEncoding {
                        alignment_atoms: vec![1, bytes as i32],
                        value_field_count: 1,
                    })
                } else {
                    None
                }
            }
            NocturneType::Bytes(n) => Some(AlignedEncoding {
                alignment_atoms: vec![1, *n as i32],
                value_field_count: n.div_ceil(FR_BYTES_STORED) as usize,
            }),
            // `Option<T>` and homogeneous-payload enums share the
            // `(Bytes<1>, T)` shape: the discriminant's lone atom prefixed
            // onto T's atoms, with the segment count bumped accordingly.
            NocturneType::Option(inner) | NocturneType::EnumPayload(inner) => {
                let enc = inner.aligned_encoding()?;
                let mut atoms = vec![1 + (enc.alignment_atoms.len() as i32 - 1)];
                atoms.push(1);
                atoms.extend(enc.alignment_atoms.iter().skip(1));
                Some(AlignedEncoding {
                    alignment_atoms: atoms,
                    value_field_count: 1 + enc.value_field_count,
                })
            }
            NocturneType::EnumUnit => Some(AlignedEncoding {
                alignment_atoms: vec![1, 1],
                value_field_count: 1,
            }),
            NocturneType::Tuple(comps) | NocturneType::Struct(comps) => compose(comps),
            NocturneType::Array(elem, n) => {
                let comps = std::iter::repeat_n((**elem).clone(), *n as usize).collect::<Vec<_>>();
                compose(&comps)
            }
        }
    }

    /// Per-Fr constraint layout, in `value_only_field_repr` order. Its
    /// length equals `aligned_encoding().value_field_count` by
    /// construction (the property H4 violated).
    pub(crate) fn fr_layout(&self) -> Vec<FrLayout> {
        match self {
            NocturneType::Bool => vec![FrLayout::Boolean],
            NocturneType::Field | NocturneType::MerkleTreeDigest => vec![FrLayout::Field],
            NocturneType::Uint(bits) => vec![FrLayout::Bits(*bits)],
            NocturneType::Bytes(n) => bytes_n_layout(*n),
            // Discriminant is an 8-bit constrained Fr, then the payload.
            NocturneType::Option(inner) | NocturneType::EnumPayload(inner) => {
                let mut layout = vec![FrLayout::Bits(8)];
                layout.extend(inner.fr_layout());
                layout
            }
            NocturneType::EnumUnit => vec![FrLayout::Bits(8)],
            NocturneType::Tuple(comps) | NocturneType::Struct(comps) => {
                comps.iter().flat_map(|c| c.fr_layout()).collect()
            }
            NocturneType::Array(elem, n) => {
                let elem_layout = elem.fr_layout();
                let mut layout = Vec::with_capacity(elem_layout.len() * *n as usize);
                for _ in 0..*n {
                    layout.extend(elem_layout.iter().copied());
                }
                layout
            }
        }
    }
}

/// Flat encoding of an ordered component list, mirroring upstream
/// `Aligned for (T1, ..., Tn)`. Shared by tuples, structs, and arrays.
fn compose(comps: &[NocturneType]) -> Option<AlignedEncoding> {
    let mut atoms: Vec<i32> = Vec::new();
    let mut count = 0usize;
    for c in comps {
        let enc = c.aligned_encoding()?;
        atoms.extend(enc.alignment_atoms.iter().skip(1));
        count += enc.value_field_count;
    }
    let total = atoms.len() as i32;
    let mut alignment_atoms = vec![total];
    alignment_atoms.extend(atoms);
    Some(AlignedEncoding {
        alignment_atoms,
        value_field_count: count,
    })
}

/// Multi-Fr layout for a `Bytes<N>` value: `ceil(N/31)` chunks, the first
/// carrying the remainder bytes.
pub(crate) fn bytes_n_layout(n: u32) -> Vec<FrLayout> {
    let chunks = n.div_ceil(FR_BYTES_STORED);
    let first = n % FR_BYTES_STORED;
    let first = if first == 0 { FR_BYTES_STORED } else { first };
    let mut layout = vec![FrLayout::Bits(first * 8)];
    for _ in 1..chunks {
        layout.push(FrLayout::Bits(FR_BYTES_STORED * 8));
    }
    layout
}

/// If `ty` is stdlib `Option<T>` (any path ending in `Option`), return `T`.
fn option_payload_type(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(tp) = ty else {
        return None;
    };
    if tp.qself.is_some() {
        return None;
    }
    let seg = tp.path.segments.last()?;
    if seg.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    match args.args.first()? {
        syn::GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    }
}

fn array_len(arr: &syn::TypeArray) -> Option<u32> {
    let syn::Expr::Lit(lit) = &arr.len else {
        return None;
    };
    let syn::Lit::Int(int) = &lit.lit else {
        return None;
    };
    int.base10_parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_ctx() -> (
        HashMap<String, Vec<nocturne_ir::UserStructField>>,
        HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
    ) {
        (HashMap::new(), HashMap::new())
    }

    fn resolved(ty: syn::Type) -> NocturneType {
        let (s, e) = empty_ctx();
        resolve(&ty, &TypeCtx::new(&s, &e)).expect("resolves")
    }

    #[test]
    fn primitives_resolve() {
        assert_eq!(resolved(syn::parse_quote!(bool)), NocturneType::Bool);
        assert_eq!(resolved(syn::parse_quote!(Boolean)), NocturneType::Bool);
        assert_eq!(resolved(syn::parse_quote!(Field)), NocturneType::Field);
        assert_eq!(
            resolved(syn::parse_quote!(MerkleTreeDigest)),
            NocturneType::MerkleTreeDigest
        );
        assert_eq!(resolved(syn::parse_quote!(u64)), NocturneType::Uint(64));
        assert_eq!(
            resolved(syn::parse_quote!(Uint<32>)),
            NocturneType::Uint(32)
        );
        assert_eq!(
            resolved(syn::parse_quote!(Bytes<32>)),
            NocturneType::Bytes(32)
        );
    }

    #[test]
    fn composites_resolve() {
        assert_eq!(
            resolved(syn::parse_quote!(Option<u64>)),
            NocturneType::Option(Box::new(NocturneType::Uint(64)))
        );
        assert_eq!(
            resolved(syn::parse_quote!((u64, Bytes<32>))),
            NocturneType::Tuple(vec![NocturneType::Uint(64), NocturneType::Bytes(32)])
        );
        assert_eq!(
            resolved(syn::parse_quote!([u8; 3])),
            NocturneType::Array(Box::new(NocturneType::Uint(8)), 3)
        );
    }

    #[test]
    fn user_struct_resolves_to_field_tuple() {
        let mut structs = HashMap::new();
        structs.insert(
            "MyKey".to_string(),
            vec![
                nocturne_ir::UserStructField {
                    name: syn::parse_quote!(a),
                    ty: syn::parse_quote!(u64),
                },
                nocturne_ir::UserStructField {
                    name: syn::parse_quote!(b),
                    ty: syn::parse_quote!(Bytes<32>),
                },
            ],
        );
        let enums = HashMap::new();
        let t = resolve(&syn::parse_quote!(MyKey), &TypeCtx::new(&structs, &enums)).unwrap();
        assert_eq!(
            t,
            NocturneType::Struct(vec![NocturneType::Uint(64), NocturneType::Bytes(32)])
        );
    }

    #[test]
    fn unit_and_payload_enums_resolve() {
        let structs = HashMap::new();
        let mut enums = HashMap::new();
        enums.insert(
            "Phase".to_string(),
            vec![
                nocturne_ir::UserEnumVariant {
                    name: syn::parse_quote!(A),
                    payload: None,
                },
                nocturne_ir::UserEnumVariant {
                    name: syn::parse_quote!(B),
                    payload: None,
                },
            ],
        );
        enums.insert(
            "Wrapped".to_string(),
            vec![nocturne_ir::UserEnumVariant {
                name: syn::parse_quote!(V),
                payload: Some(syn::parse_quote!(u64)),
            }],
        );
        let ctx = TypeCtx::new(&structs, &enums);
        assert_eq!(
            resolve(&syn::parse_quote!(Phase), &ctx).unwrap(),
            NocturneType::EnumUnit
        );
        assert_eq!(
            resolve(&syn::parse_quote!(Wrapped), &ctx).unwrap(),
            NocturneType::EnumPayload(Box::new(NocturneType::Uint(64)))
        );
    }

    #[test]
    fn witness_only_and_unknown_types_do_not_resolve() {
        let (s, e) = empty_ctx();
        let ctx = TypeCtx::new(&s, &e);
        assert!(resolve(&syn::parse_quote!(MerkleTreePath<8, Bytes<32>>), &ctx).is_none());
        assert!(resolve(&syn::parse_quote!(MerkleTreePathEntry), &ctx).is_none());
        assert!(resolve(&syn::parse_quote!(SomethingUnknown), &ctx).is_none());
    }

    /// The H4 invariant: for every resolvable type, the Fr-layout length
    /// equals the aligned encoding's value_field_count.
    #[test]
    fn fr_layout_len_matches_value_field_count() {
        let (s, e) = empty_ctx();
        let ctx = TypeCtx::new(&s, &e);
        let cases: Vec<syn::Type> = vec![
            syn::parse_quote!(bool),
            syn::parse_quote!(Field),
            syn::parse_quote!(u64),
            syn::parse_quote!(Uint<128>),
            syn::parse_quote!(Bytes<32>),
            syn::parse_quote!(Bytes<64>),
            syn::parse_quote!(Option<u64>),
            syn::parse_quote!(Option<Bytes<32>>),
            syn::parse_quote!((u64, u64)),
            syn::parse_quote!((u64, Bytes<48>, bool)),
            syn::parse_quote!([u8; 3]),
            syn::parse_quote!([Bytes<32>; 2]),
        ];
        for ty in cases {
            let t = resolve(&ty, &ctx).unwrap();
            if let Some(enc) = t.aligned_encoding() {
                assert_eq!(
                    t.fr_layout().len(),
                    enc.value_field_count,
                    "fr_layout/value_field_count disagree for {}",
                    quote::quote!(#ty)
                );
            }
        }
    }
}
