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
}
