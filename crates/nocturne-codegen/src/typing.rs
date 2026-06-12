//! Typing rules shared between the ZKIR emitter and the transcript
//! codegen.
//!
//! Both passes must agree on (a) which type strings are integer-like and
//! how wide they are, and (b) which method calls are transparent
//! wrappers around their receiver. Keeping each rule in one place stops
//! the passes from drifting: a divergent width table would make the
//! circuit range-constrain a different range than the runtime checks,
//! and a divergent transparency rule would make a `.value()`-wrapped
//! literal type-check in one pass and not the other.

/// Bit width of an integer-like type string: the primitives `u8`..`u128`
/// and the eDSL's `Uint<N>`. Expects the canonical space-stripped form
/// (`quote!(#ty).to_string().replace(' ', "")`). `None` for everything
/// else (`Field`, `Bytes<N>`, booleans, user ADTs).
pub(crate) fn parse_uint_type(ty_str: &str) -> Option<u32> {
    if let Some(n) = ty_str
        .strip_prefix("Uint<")
        .and_then(|s| s.strip_suffix('>'))
    {
        return n.parse::<u32>().ok();
    }
    match ty_str {
        "u8" => Some(8),
        "u16" => Some(16),
        "u32" => Some(32),
        "u64" => Some(64),
        "u128" => Some(128),
        _ => None,
    }
}

/// Maximum value an `N`-bit unsigned integer can hold, saturating at
/// `u128::MAX` for `N >= 128`.
pub(crate) fn uint_max_value(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

/// True when `method` is a transparent wrapper call: `.into()` and
/// `.value()` change the Rust-level type but not the value the circuit
/// and transcript carry, so analyses (literal extraction, comparison
/// widths, runtime-expression lowering) forward to the receiver.
pub(crate) fn is_transparent_wrapper(method: &str) -> bool {
    method == "into" || method == "value"
}
