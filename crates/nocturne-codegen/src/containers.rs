//! Structural `syn::Type` unwrappers for the ledger container types
//! (`Cell<T>`, `Map<K, V>`, `Set<T>`, `MerkleTree<H, T>`, `[T; N]`).
//!
//! These peel one layer off a `syn::Type` to recover the contained value
//! type(s). They are distinct from `crate::nocturne_type::resolve`, which
//! resolves a *value* type into its on-chain encoding: a `Cell<T>` is not
//! itself an `AlignedValue`, but its `T` is. The ZKIR emitter, the
//! transcript codegen, and the deploy codegen all need the same
//! structural peel, so the single copy lives here.

/// If `ty` is `Cell<T>`, return `T`. Otherwise `None`.
pub(crate) fn extract_cell_inner_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "Cell"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
    {
        return Some(inner.clone());
    }
    None
}

/// If `ty` is `Map<K, V>`, return `(K, V)`. Otherwise `None`.
pub(crate) fn extract_map_kv_types(ty: &syn::Type) -> Option<(syn::Type, syn::Type)> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "Map"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
    {
        let mut type_args = args.args.iter().filter_map(|a| {
            if let syn::GenericArgument::Type(t) = a {
                Some(t.clone())
            } else {
                None
            }
        });
        let k = type_args.next()?;
        let v = type_args.next()?;
        return Some((k, v));
    }
    None
}

/// If `ty` is `Set<T>`, return `T`. Otherwise `None`.
pub(crate) fn extract_set_inner_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "Set"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
    {
        return Some(inner.clone());
    }
    None
}

/// If `ty` is `MerkleTree<H, T>`, return `T` (the leaf type). The height
/// `H` is encoded into the storage type's const generic and doesn't
/// affect the IR emission — checkRoot's on-chain ops are independent of
/// `H` because the height lives inside the upstream `BoundedMerkleTree`
/// value itself. Returns `Some(_)` so callers know the field is a
/// MerkleTree even when they don't need the leaf type.
pub(crate) fn extract_merkle_tree_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "MerkleTree"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
    {
        // Skip the const-generic height; pick the first type-position arg.
        for a in &args.args {
            if let syn::GenericArgument::Type(t) = a {
                return Some(t.clone());
            }
        }
    }
    None
}

/// If `ty` is `[T; N]` with an integer-literal length, return `(T, N)`.
/// Const-generic lengths (`[T; N]` where `N` is a const param) are not
/// handled.
pub(crate) fn extract_array_type(ty: &syn::Type) -> Option<(syn::Type, u32)> {
    if let syn::Type::Array(arr) = ty
        && let syn::Expr::Lit(lit) = &arr.len
        && let syn::Lit::Int(int) = &lit.lit
        && let Ok(n) = int.base10_parse::<u32>()
    {
        return Some(((*arr.elem).clone(), n));
    }
    None
}
