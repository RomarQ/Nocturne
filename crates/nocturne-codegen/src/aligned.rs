//! Shared accessor → `AlignedValue::from(_)` argument construction.
//!
//! Given a declared Rust type and a token accessor for a runtime value of
//! that type (e.g. `__state.field.get()` or `witnesses.secret`), build the
//! expression that `AlignedValue::from(_)` accepts and that produces the
//! same wire shape the ZKIR emitter declares for the type. One recursion,
//! shared by the deploy codegen (Cell initializers) and the transcript
//! codegen (private-transcript witness pushes) so the two sides can't
//! drift apart.

use std::collections::HashMap;

use nocturne_ir::{UserEnumVariant, UserStructField};
use proc_macro2::TokenStream;
use quote::quote;

/// Build the expression passed to `AlignedValue::from(_)` for a value of
/// type `ty` reachable through `accessor`. Returns a token that, when
/// wrapped in `AlignedValue::from(_)`, produces the same wire shape the
/// runtime `Cell::set` / witness push paths produce.
pub(crate) fn accessor_aligned_value_expr(
    inner: Option<&syn::Type>,
    accessor: &TokenStream,
    user_enums: &HashMap<String, Vec<UserEnumVariant>>,
    user_structs: &HashMap<String, Vec<UserStructField>>,
) -> TokenStream {
    let Some(t) = inner else {
        return quote! { (#accessor) };
    };
    let s = quote!(#t).to_string().replace(' ', "");
    if s.starts_with("Bytes<") {
        return quote! { *(#accessor).as_bytes() };
    }
    if s == "Field" {
        return quote! { nocturne::runtime::transient_crypto::curve::Fr::from((#accessor).value()) };
    }
    if s == "MerkleTreeDigest" {
        return quote! {
            nocturne::runtime::transient_crypto::curve::Fr::from_le_bytes(&(#accessor).as_le_bytes())
                .expect("MerkleTreeDigest bytes round-trip through Fr")
        };
    }
    if s == "Boolean" {
        return quote! { (#accessor).value() };
    }
    if s == "bool" {
        return quote! { (#accessor) };
    }
    // Stdlib `Option<T>` — same wire shape as a homogeneous-payload
    // enum. The None case synthesizes `<T as Default>::default()` so
    // the AlignedValue's payload slot is well-formed.
    if let Some(payload_ty) = option_payload_type(t) {
        let payload_repr = accessor_aligned_value_expr(
            Some(&payload_ty),
            &quote! { __payload },
            user_enums,
            user_structs,
        );
        return quote! {
            {
                let __e = #accessor;
                let __payload = match __e {
                    ::core::option::Option::Some(__p) => __p,
                    ::core::option::Option::None =>
                        <#payload_ty as ::core::default::Default>::default(),
                };
                let __disc: u8 = match __e {
                    ::core::option::Option::Some(_) => 1,
                    ::core::option::Option::None => 0,
                };
                (__disc, #payload_repr)
            }
        };
    }
    // User enum:
    //   - Unit-only variants → just the u8 discriminant.
    //   - Homogeneous payload `enum E { V(T) }` → the `(Bytes<1>, T)`
    //     tuple `AlignedValue::from(_)` accepts via the upstream
    //     `Aligned for (A, B)` impl. The payload is extracted via an
    //     inline `match` over the enum value — same shape the
    //     transcript codegen uses elsewhere; no synthetic accessor.
    if let syn::Type::Path(tp) = t
        && tp.qself.is_none()
        && let Some(seg) = tp.path.segments.last()
        && let Some(variants) = user_enums.get(&seg.ident.to_string())
    {
        let payload_ty = variants.first().and_then(|v| v.payload.clone());
        return match payload_ty {
            None => quote! { (#accessor).discriminant() },
            Some(p) => {
                let enum_ident = seg.ident.clone();
                let arms: Vec<TokenStream> = variants
                    .iter()
                    .map(|v| {
                        let v_ident = v.name.clone();
                        quote! { #enum_ident::#v_ident(__p) => __p }
                    })
                    .collect();
                // Recurse to get the payload's per-type representation
                // (Uint<N> needs `.value() as u<N>`, Bytes<N> needs
                // `*as_bytes()`, …) — same encoding the runtime side
                // would produce for a `Cell<T>::set(payload)`.
                let payload_repr = accessor_aligned_value_expr(
                    Some(&p),
                    &quote! { __payload },
                    user_enums,
                    user_structs,
                );
                quote! {
                    {
                        let __e = #accessor;
                        let __payload = match __e.clone() {
                            #(#arms),*
                        };
                        (__e.discriminant(), #payload_repr)
                    }
                }
            }
        };
    }
    // User-defined named struct: same tuple-of-fields shape upstream's
    // `Aligned for (T1, ..., Tn)` impl produces. Each field is converted
    // through the same recursion so a struct of `Uint<N>`/`Bytes<M>`/
    // nested structs all serialise consistently.
    if let syn::Type::Path(tp) = t
        && tp.qself.is_none()
        && let Some(seg) = tp.path.segments.last()
        && let Some(struct_fields) = user_structs.get(&seg.ident.to_string())
    {
        let comps: Vec<TokenStream> = struct_fields
            .iter()
            .map(|f| {
                let fname = f.name.clone();
                accessor_aligned_value_expr(
                    Some(&f.ty),
                    &quote! { __s.#fname },
                    user_enums,
                    user_structs,
                )
            })
            .collect();
        let trailing = if struct_fields.len() == 1 {
            quote! { , }
        } else {
            quote! {}
        };
        return quote! {
            {
                let __s = #accessor;
                (#(#comps),* #trailing)
            }
        };
    }
    // Tuple `(T1, ..., Tn)`: project each component by position and
    // convert it through the same recursion. Mirrors the user-struct
    // arm — the wire shape is the upstream tuple `Aligned` impl either
    // way.
    if let syn::Type::Tuple(tt) = t {
        let comps: Vec<TokenStream> = tt
            .elems
            .iter()
            .enumerate()
            .map(|(i, elem)| {
                let idx = syn::Index::from(i);
                accessor_aligned_value_expr(
                    Some(elem),
                    &quote! { __t.#idx },
                    user_enums,
                    user_structs,
                )
            })
            .collect();
        let trailing = if tt.elems.len() == 1 {
            quote! { , }
        } else {
            quote! {}
        };
        return quote! {
            {
                let __t = #accessor;
                (#(#comps),* #trailing)
            }
        };
    }
    // `Uint<N>` is a wrapper exposing `.value()`; raw `u*` primitives don't
    // have `.value()`. Branch on which we're looking at so the cast applies
    // to the right base expression.
    if s.starts_with("Uint<") {
        if let Some(cast) = primitive_cast_for_type(t) {
            return quote! { ((#accessor).value() #cast) };
        }
        return quote! { (#accessor).value() };
    }
    if matches!(s.as_str(), "u8" | "u16" | "u32" | "u64" | "u128") {
        if let Some(cast) = primitive_cast_for_type(t) {
            return quote! { ((#accessor) #cast) };
        }
        return quote! { (#accessor) };
    }
    // Fixed-size array `[U; N]`: same N-tuple shape the runtime side uses
    // for Cell::set(_)/Cell::get(_). Lets `Cell::new([a, b, c])` round-trip
    // through deploy time and stay byte-compatible with subsequent
    // set/get operations.
    if let syn::Type::Array(arr) = t
        && let syn::Expr::Lit(lit) = &arr.len
        && let syn::Lit::Int(int) = &lit.lit
        && let Ok(n) = int.base10_parse::<u32>()
    {
        let elem_ty = (*arr.elem).clone();
        let comps: Vec<TokenStream> = (0..n as usize)
            .map(|i| {
                let idx = syn::Index::from(i);
                accessor_aligned_value_expr(
                    Some(&elem_ty),
                    &quote! { __a[#idx] },
                    user_enums,
                    user_structs,
                )
            })
            .collect();
        let trailing = if n == 1 {
            quote! { , }
        } else {
            quote! {}
        };
        return quote! {
            {
                let __a = #accessor;
                (#(#comps),* #trailing)
            }
        };
    }
    quote! { (#accessor) }
}

/// Pick the `as u<N>` cast appropriate for fixed-width integer types so
/// the emitted `AlignedValue::from(_)` chooses the matching `Bytes<N>` atom
/// width.
pub(crate) fn primitive_cast_for_type(ty: &syn::Type) -> Option<TokenStream> {
    let s = quote!(#ty).to_string().replace(' ', "");
    if let Some(bits) = s.strip_prefix("Uint<").and_then(|t| t.strip_suffix(">")) {
        let bits: u32 = bits.parse().ok()?;
        return Some(match bits {
            1..=8 => quote! { as u8 },
            9..=16 => quote! { as u16 },
            17..=32 => quote! { as u32 },
            33..=64 => quote! { as u64 },
            // 65..=128 → `as u128`; matches the upstream `Aligned for u128`
            // impl that picks Bytes<16> alignment. Without this branch a
            // `Cell<Uint<128>>::new(witness)` initializer would silently
            // truncate to u64 at the AlignedValue::from call site.
            _ => quote! { as u128 },
        });
    }
    match s.as_str() {
        "u8" => Some(quote! { as u8 }),
        "u16" => Some(quote! { as u16 }),
        "u32" => Some(quote! { as u32 }),
        "u64" => Some(quote! { as u64 }),
        "u128" => Some(quote! { as u128 }),
        _ => None,
    }
}

/// If `ty` is stdlib `Option<T>`, return `T`.
pub(crate) fn option_payload_type(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(tp) = ty else { return None };
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
