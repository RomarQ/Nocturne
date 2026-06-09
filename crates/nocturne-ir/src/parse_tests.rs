#[cfg(test)]
mod tests {
    use crate::contract::*;
    use crate::expr::*;
    use crate::parse::parse_contract;

    fn parse(input: proc_macro2::TokenStream) -> crate::MidnightResult<ContractIR> {
        let module: syn::ItemMod = syn::parse2(input).expect("failed to parse module");
        parse_contract(module)
    }

    #[test]
    fn parse_counter_contract() {
        let ir = parse(quote::quote! {
            mod counter {
                use nocturne::types::*;

                #[nocturne(ledger)]
                pub struct CounterState {
                    count: Counter,
                }

                impl CounterState {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { count: Counter::zero() }
                    }

                    #[nocturne(circuit)]
                    pub fn increment(&mut self) {
                        self.count.increment();
                    }
                }
            }
        })
        .expect("failed to parse counter contract");

        assert_eq!(ir.name.to_string(), "counter");

        // Ledger
        assert_eq!(ir.ledger.name.to_string(), "CounterState");
        assert_eq!(ir.ledger.fields.len(), 1);
        assert_eq!(ir.ledger.fields[0].name.to_string(), "count");
        assert_eq!(ir.ledger.fields[0].type_kind, LedgerTypeKind::Counter);

        // No witnesses
        assert!(ir.witnesses.is_none());

        // Constructor
        assert_eq!(ir.constructors.len(), 1);
        assert_eq!(ir.constructors[0].name.to_string(), "new");

        // Circuit
        assert_eq!(ir.circuits.len(), 1);
        assert_eq!(ir.circuits[0].name.to_string(), "increment");
        assert!(ir.circuits[0].mutates_ledger);
        assert!(!ir.circuits[0].takes_witnesses);

        // Circuit body should have a LedgerAccess for self.count.increment()
        assert_eq!(ir.circuits[0].body.len(), 1);
        match &ir.circuits[0].body[0] {
            ExprIR::LedgerAccess { field, method, .. } => {
                assert_eq!(field.to_string(), "count");
                assert_eq!(method.to_string(), "increment");
            }
            other => panic!("expected LedgerAccess, got: {other:?}"),
        }
    }

    #[test]
    fn parse_voting_contract_with_witnesses() {
        let ir = parse(quote::quote! {
            mod ballot {
                use nocturne::types::*;

                #[nocturne(ledger)]
                pub struct Ballot {
                    votes_for: Counter,
                    votes_against: Counter,
                    merkle_voters: MerkleTree,
                }

                #[nocturne(witnesses)]
                pub struct BallotWitnesses {
                    voter_secret: Field,
                    vote_choice: Boolean,
                }

                impl Ballot {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self {
                            votes_for: Counter::zero(),
                            votes_against: Counter::zero(),
                            merkle_voters: MerkleTree::empty(),
                        }
                    }

                    #[nocturne(circuit)]
                    pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
                        let commitment = persistent_hash(&witnesses.voter_secret);
                        if witnesses.vote_choice.into() {
                            self.votes_for.increment();
                        } else {
                            self.votes_against.increment();
                        }
                    }

                    #[nocturne(query)]
                    pub fn get_tally(&self) -> (u64, u64) {
                        (self.votes_for.value(), self.votes_against.value())
                    }
                }
            }
        })
        .expect("failed to parse voting contract");

        assert_eq!(ir.name.to_string(), "ballot");

        // Ledger
        assert_eq!(ir.ledger.fields.len(), 3);
        assert_eq!(ir.ledger.fields[0].type_kind, LedgerTypeKind::Counter);
        assert_eq!(ir.ledger.fields[2].type_kind, LedgerTypeKind::MerkleTree);

        // Witnesses
        let witnesses = ir.witnesses.as_ref().expect("should have witnesses");
        assert_eq!(witnesses.name.to_string(), "BallotWitnesses");
        assert_eq!(witnesses.fields.len(), 2);
        assert_eq!(witnesses.fields[0].name.to_string(), "voter_secret");
        assert_eq!(witnesses.fields[1].name.to_string(), "vote_choice");

        // Circuit with witnesses
        assert_eq!(ir.circuits.len(), 1);
        let circuit = &ir.circuits[0];
        assert_eq!(circuit.name.to_string(), "cast_vote");
        assert!(circuit.takes_witnesses);
        assert!(circuit.mutates_ledger);

        // Body: let, if/else with ledger access
        assert!(circuit.body.len() >= 2);

        // First statement: let commitment = ...
        match &circuit.body[0] {
            ExprIR::Let { name, value, .. } => {
                assert_eq!(name.to_string(), "commitment");
                match &**value {
                    ExprIR::FnCall { name, .. } => {
                        assert_eq!(name.to_string(), "persistent_hash");
                    }
                    other => panic!("expected FnCall, got: {other:?}"),
                }
            }
            other => panic!("expected Let, got: {other:?}"),
        }

        // Second statement: if/else
        match &circuit.body[1] {
            ExprIR::If {
                then_branch,
                else_branch,
                ..
            } => {
                assert!(!then_branch.is_empty());
                assert!(else_branch.is_some());
            }
            other => panic!("expected If, got: {other:?}"),
        }

        // Query
        assert_eq!(ir.queries.len(), 1);
        assert_eq!(ir.queries[0].name.to_string(), "get_tally");
    }

    #[test]
    fn missing_ledger_is_error() {
        let result = parse(quote::quote! {
            mod bad {
                impl Foo {
                    #[nocturne(circuit)]
                    pub fn do_thing(&mut self) {}
                }
            }
        });

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, crate::error::ErrorCode::MissingLedger);
    }

    #[test]
    fn query_with_mut_self_is_error() {
        let result = parse(quote::quote! {
            mod bad {
                #[nocturne(ledger)]
                pub struct State {
                    x: Counter,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { x: Counter::zero() }
                    }

                    #[nocturne(query)]
                    pub fn bad_query(&mut self) -> u64 {
                        0
                    }
                }
            }
        });

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, crate::error::ErrorCode::QueryMustBeImmutable);
    }

    #[test]
    fn parse_assert_expressions() {
        let ir = parse(quote::quote! {
            mod asserting {
                #[nocturne(ledger)]
                pub struct State {
                    x: Counter,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { x: Counter::zero() }
                    }

                    #[nocturne(circuit)]
                    pub fn check(&mut self) {
                        assert!(self.x.value() > 0);
                        assert_eq!(self.x.value(), 42);
                    }
                }
            }
        })
        .expect("failed to parse");

        let circuit = &ir.circuits[0];
        assert_eq!(circuit.body.len(), 2);

        match &circuit.body[0] {
            ExprIR::Assert {
                kind: AssertKind::Assert(_),
                ..
            } => {}
            other => panic!("expected Assert, got: {other:?}"),
        }

        match &circuit.body[1] {
            ExprIR::Assert {
                kind: AssertKind::AssertEq(_, _),
                ..
            } => {}
            other => panic!("expected AssertEq, got: {other:?}"),
        }
    }

    #[test]
    fn parse_disclose_expression() {
        let ir = parse(quote::quote! {
            mod disclosing {
                #[nocturne(ledger)]
                pub struct State {
                    threshold: Cell,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { threshold: Cell::new(0) }
                    }

                    #[nocturne(circuit)]
                    pub fn reveal(&mut self) {
                        self.threshold.set(nocturne::disclose(42));
                    }
                }
            }
        })
        .expect("failed to parse");

        let circuit = &ir.circuits[0];
        // self.threshold.set(nocturne::disclose(42)) -> LedgerAccess with set method
        assert_eq!(circuit.body.len(), 1);
        match &circuit.body[0] {
            ExprIR::LedgerAccess {
                field,
                method,
                args,
                ..
            } => {
                assert_eq!(field.to_string(), "threshold");
                assert_eq!(method.to_string(), "set");
                assert_eq!(args.len(), 1);
                match &args[0] {
                    ExprIR::Disclose { .. } => {}
                    other => panic!("expected Disclose, got: {other:?}"),
                }
            }
            other => panic!("expected LedgerAccess, got: {other:?}"),
        }
    }

    #[test]
    fn parse_multiple_ledger_types() {
        let ir = parse(quote::quote! {
            mod complex {
                #[nocturne(ledger)]
                pub struct State {
                    counter: Counter,
                    data: Cell,
                    store: Map,
                    tree: MerkleTree,
                    items: Array,
                    members: Set,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self {
                            counter: Counter::zero(),
                            data: Cell::new(0),
                            store: Map::empty(),
                            tree: MerkleTree::empty(),
                            items: Array::new(),
                            members: Set::empty(),
                        }
                    }

                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
            }
        })
        .expect("failed to parse");

        let fields = &ir.ledger.fields;
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].type_kind, LedgerTypeKind::Counter);
        assert_eq!(fields[1].type_kind, LedgerTypeKind::Cell);
        assert_eq!(fields[2].type_kind, LedgerTypeKind::Map);
        assert_eq!(fields[3].type_kind, LedgerTypeKind::MerkleTree);
        assert_eq!(fields[4].type_kind, LedgerTypeKind::Array);
        assert_eq!(fields[5].type_kind, LedgerTypeKind::Set);
    }

    #[test]
    fn payload_enum_surfaces_diagnostic_at_offending_variant() {
        let err = parse(quote::quote! {
            mod bad {
                #[derive(Clone)]
                pub enum Action {
                    Mint,
                    Burn(u64),
                }

                #[nocturne(ledger)]
                pub struct State {
                    seen: Counter,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { seen: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
            }
        })
        .expect_err("payload-carrying enum variant must produce a parse error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Burn") && msg.contains("payload"),
            "diagnostic must name the offending variant + cite payload as the reason; got: {msg}"
        );
    }

    #[test]
    fn free_fn_with_primitive_params_registers_as_helper() {
        let ir = parse(quote::quote! {
            mod with_helper {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
                pub fn double(x: u64) -> u64 { x + x }
            }
        })
        .expect("contract with a helper must parse");
        assert_eq!(ir.helpers.len(), 1, "exactly one helper expected");
        assert_eq!(ir.helpers[0].name.to_string(), "double");
        assert_eq!(ir.helpers[0].params.len(), 1);
        assert_eq!(ir.helpers[0].params[0].name.to_string(), "x");
        assert!(!ir.helpers[0].body.is_empty(), "body must be parsed");
    }

    #[test]
    fn free_fn_with_reference_param_is_not_a_helper() {
        let ir = parse(quote::quote! {
            mod rejected_helper {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
                // `&u64` arg → not inlinable in v1; should fall
                // through to other_items without errors.
                pub fn peek(_x: &u64) -> u64 { 0 }
            }
        })
        .expect("non-inlinable free fns must NOT error the parse");
        assert!(
            ir.helpers.is_empty(),
            "ref-taking fn must NOT be registered"
        );
    }

    #[test]
    fn free_fn_shadowing_builtin_is_not_a_helper() {
        let ir = parse(quote::quote! {
            mod shadowing {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
                pub fn persistent_hash(x: u64) -> u64 { x }
            }
        })
        .expect("builtin-named fn must NOT error the parse");
        assert!(
            ir.helpers.is_empty(),
            "fn shadowing a builtin name must NOT be registered"
        );
    }

    #[test]
    fn recursive_helper_is_rejected() {
        let err = parse(quote::quote! {
            mod recursive {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
                pub fn loops(x: u64) -> u64 { loops(x) }
            }
        })
        .expect_err("self-recursive helper must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("recursive helper") && msg.contains("loops"),
            "diagnostic must name the offending helper; got: {msg}"
        );
    }

    #[test]
    fn mutually_recursive_helpers_are_rejected() {
        let err = parse(quote::quote! {
            mod mutual_recursion {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
                pub fn a(x: u64) -> u64 { b(x) }
                pub fn b(x: u64) -> u64 { a(x) }
            }
        })
        .expect_err("a → b → a must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("recursive helper") && msg.contains("a") && msg.contains("b"),
            "diagnostic must name the cycle; got: {msg}"
        );
    }
}
