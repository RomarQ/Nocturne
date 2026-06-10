#[cfg(test)]
mod tests {
    use crate::transcript_codegen::generate_transcript_module;
    use nocturne_ir::parse_contract;

    /// Parse a contract module and render the generated transcript
    /// module to a token string for content assertions.
    fn transcript_tokens(input: proc_macro2::TokenStream) -> String {
        let module: syn::ItemMod = syn::parse2(input).expect("parse module");
        let contract = parse_contract(module).expect("parse contract");
        generate_transcript_module(&contract).to_string()
    }

    /// Task 2.5: a literal exceeding the target type's range must fail
    /// at compile time. Without the check, the circuit's LoadImm
    /// carries the full literal while the runtime transcript builder
    /// truncates through `as u32` — a prove-time mismatch at best, a
    /// silently-wrong on-chain write at worst.
    #[test]
    fn over_range_cell_set_literal_emits_compile_error() {
        let tokens = transcript_tokens(quote::quote! {
            mod over_range {
                #[nocturne(ledger)]
                pub struct State { limit: Cell<Uint<32>> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { limit: Cell::new(Uint::<32>::from(0u32)) } }
                    #[nocturne(circuit)]
                    pub fn set_limit(&mut self) {
                        self.limit.set(5_000_000_000u64);
                    }
                }
            }
        });
        assert!(
            tokens.contains("compile_error"),
            "over-range Cell::set literal must generate a compile_error, got: {tokens}"
        );
        assert!(
            tokens.contains("literal 5000000000 exceeds Uint<32> range"),
            "compile_error message must name the literal and the target type, got: {tokens}"
        );
    }

    /// Same check at Map key and value positions: both flow through the
    /// `aligned_value_arg_expr` chokepoint.
    #[test]
    fn over_range_map_insert_literals_emit_compile_error() {
        let tokens = transcript_tokens(quote::quote! {
            mod over_range_map {
                #[nocturne(ledger)]
                pub struct State { scores: Map<Uint<8>, Uint<16>> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { scores: Map::empty() } }
                    #[nocturne(circuit)]
                    pub fn seed(&mut self) {
                        self.scores.insert(300u64, 70_000u64);
                    }
                }
            }
        });
        assert!(
            tokens.contains("literal 300 exceeds Uint<8> range"),
            "over-range Map key literal must generate a compile_error, got: {tokens}"
        );
        assert!(
            tokens.contains("literal 70000 exceeds Uint<16> range"),
            "over-range Map value literal must generate a compile_error, got: {tokens}"
        );
    }

    /// Negative case: in-range literals stay clean. The boundary value
    /// (`u32::MAX` for `Uint<32>`) must NOT trip the check.
    #[test]
    fn in_range_literals_do_not_emit_compile_error() {
        let tokens = transcript_tokens(quote::quote! {
            mod in_range {
                #[nocturne(ledger)]
                pub struct State { limit: Cell<Uint<32>>, scores: Map<Uint<8>, Uint<16>> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { limit: Cell::new(Uint::<32>::from(0u32)), scores: Map::empty() }
                    }
                    #[nocturne(circuit)]
                    pub fn set_limit(&mut self) {
                        self.limit.set(4_294_967_295u64);
                    }
                    #[nocturne(circuit)]
                    pub fn seed(&mut self) {
                        self.scores.insert(255u64, 65_535u64);
                    }
                }
            }
        });
        assert!(
            !tokens.contains("compile_error"),
            "in-range literals must not generate a compile_error, got: {tokens}"
        );
    }

    /// Task 3.1: the generated transcript fn's parameter is ALWAYS named
    /// `witnesses`, regardless of the user's circuit param name — every
    /// helper emits `witnesses.<field>` accessors.
    #[test]
    fn witnesses_param_name_is_normalized() {
        let tokens = transcript_tokens(quote::quote! {
            mod renamed_param {
                #[nocturne(ledger)]
                pub struct State { value: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { pub v: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { value: Cell::new(Uint::<64>::from(0u64)) } }
                    #[nocturne(circuit)]
                    pub fn store(&mut self, my_witnesses: &W) {
                        self.value.set(my_witnesses.v);
                    }
                }
            }
        });
        assert!(
            tokens.contains("witnesses : & W"),
            "generated fn must take a param named `witnesses`, got: {tokens}"
        );
        assert!(
            !tokens.contains("my_witnesses"),
            "the user's param name must not leak into the generated builder, got: {tokens}"
        );
    }

    /// Task 3.6: generated locals use reserved `__nocturne_*` idents so
    /// user `let` bindings can't shadow them.
    #[test]
    fn generated_internals_use_reserved_idents() {
        let tokens = transcript_tokens(quote::quote! {
            mod internals {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn bump(&mut self) { self.count.increment(); }
                }
            }
        });
        assert!(
            tokens.contains("__nocturne_ops"),
            "generated op vec must be named __nocturne_ops, got: {tokens}"
        );
        assert!(
            tokens.contains("__nocturne_private_transcript"),
            "generated private transcript vec must use the reserved ident, got: {tokens}"
        );
    }
}
