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

    /// An `if` whose VALUE flows into a surrounding expression
    /// (`self.x.set(if c { a } else { b })`) must be rejected at compile
    /// time: the event walk would push BOTH branches' private-transcript
    /// entries while the circuit's guarded `PrivateInput`s consume only
    /// the active branch's slot at prove time ("Transcripts not fully
    /// consumed"). See `find_expression_position_if`.
    #[test]
    fn expression_position_if_emits_compile_error() {
        let tokens = transcript_tokens(quote::quote! {
            mod expr_if {
                #[nocturne(ledger)]
                pub struct State { value: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { pub flag: Boolean, pub a: Uint<64>, pub b: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { value: Cell::new(Uint::<64>::from(0u64)) } }
                    #[nocturne(circuit)]
                    pub fn pick(&mut self, witnesses: &W) {
                        self.value.set(
                            if witnesses.flag.value() { witnesses.a } else { witnesses.b }
                        );
                    }
                }
            }
        });
        assert!(
            tokens.contains("compile_error"),
            "expression-position `if` must generate a compile_error, got: {tokens}"
        );
        assert!(
            tokens.contains("not supported in expression position"),
            "compile_error must explain the expression-position rejection, got: {tokens}"
        );
    }

    /// Negative cases for the expression-position-`if` rejection: a
    /// STATEMENT-position `if` and a `let`-RHS `if` are both handled by
    /// `generate_op_stmt` (cond events before the runtime `if`,
    /// branch-body events inside it) and must stay clean.
    #[test]
    fn statement_and_let_rhs_if_do_not_emit_compile_error() {
        let tokens = transcript_tokens(quote::quote! {
            mod stmt_if {
                #[nocturne(ledger)]
                pub struct State { value: Cell<Uint<64>>, other: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { pub flag: Boolean, pub a: Uint<64>, pub b: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self {
                            value: Cell::new(Uint::<64>::from(0u64)),
                            other: Cell::new(Uint::<64>::from(0u64)),
                        }
                    }
                    #[nocturne(circuit)]
                    pub fn pick_stmt(&mut self, witnesses: &W) {
                        if witnesses.flag.value() {
                            self.value.set(witnesses.a);
                        } else {
                            self.value.set(witnesses.b);
                        }
                    }
                    #[nocturne(circuit)]
                    pub fn pick_let(&mut self, witnesses: &W) {
                        let v = if witnesses.flag.value() { witnesses.a } else { witnesses.b };
                        self.other.set(v);
                    }
                }
            }
        });
        assert!(
            !tokens.contains("compile_error"),
            "statement-position and let-RHS `if` must not generate a compile_error, got: {tokens}"
        );
        // Placement sanity: the branch-body pushes land INSIDE the runtime
        // `if` (after the cond's own push + the `if` keyword), not before it.
        let if_pos = tokens
            .find("if witnesses . flag . value ()")
            .expect("runtime if must be present");
        let a_push = tokens
            .find("witnesses . a . clone ()")
            .expect("then-branch witness push must be present");
        assert!(
            a_push > if_pos,
            "branch-body witness push must be emitted inside the runtime if, got: {tokens}"
        );
    }

    /// Revert-sensitive coverage for the key bind-once fix (keyed-container
    /// key expressions evaluate exactly once): the generated Map contains
    /// block must derive the op's Push value from the bound `__key`, not
    /// re-evaluate the key expression. A parametric witness call is the
    /// observable case — re-evaluation would invoke the user's method twice
    /// (or three times counting the private-transcript push).
    #[test]
    fn map_contains_key_binds_once_and_push_derives_from_key() {
        let tokens = transcript_tokens(quote::quote! {
            mod wc_key {
                #[nocturne(ledger)]
                pub struct State { scores: Map<Uint<64>, Uint<64>>, hits: Counter }
                #[nocturne(witnesses)]
                pub struct W;
                impl W {
                    pub fn pick(&self) -> Uint<64> { Uint::<64>::from(7u64) }
                }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { scores: Map::empty(), hits: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn gate(&mut self, witnesses: &W) {
                        if self.scores.contains(&witnesses.pick()) {
                            self.hits.increment();
                        }
                    }
                }
            }
        });
        // Exactly two invocations: one for the private-transcript push
        // (`let __wc = witnesses.pick()`), one for the `__key` binding.
        // Re-evaluating the key inside the op's AlignedValue would add a
        // third.
        assert_eq!(
            tokens.matches("witnesses . pick ()").count(),
            2,
            "key expression must be evaluated exactly once in the contains block \
             (plus once for the private push), got: {tokens}"
        );
        assert!(
            tokens.contains("let __key = witnesses . pick ()"),
            "contains block must bind the key once as __key, got: {tokens}"
        );
        // The Push's AlignedValue derives from the bound __key.
        assert!(
            tokens.contains("AlignedValue :: from (((__key . clone ()) . value () as u64))"),
            "the contains Push value must derive from the bound __key, got: {tokens}"
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
