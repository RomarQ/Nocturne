#[cfg(test)]
mod tests {
    use crate::contract::*;
    use crate::expr::*;
    use crate::parse::parse_contract;

    fn parse(input: proc_macro2::TokenStream) -> Result<ContractIR, crate::Diagnostics> {
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
        let err = result.unwrap_err().into_first_error();
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
        let err = result.unwrap_err().into_first_error();
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

    // -----------------------------------------------------------------
    // Witness identification by resolved type (review H1, M7)
    // -----------------------------------------------------------------

    #[test]
    fn witness_param_with_custom_name_is_detected_by_type() {
        let ir = parse(quote::quote! {
            mod custom_name {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                #[nocturne(witnesses)]
                pub struct BallotWitnesses {
                    voter_secret: Field,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn cast(&mut self, w: &BallotWitnesses) {
                        let commitment = persistent_hash(&w.voter_secret);
                        self.count.increment();
                    }
                }
            }
        })
        .expect("param `w: &BallotWitnesses` must parse");

        let circuit = &ir.circuits[0];
        assert!(circuit.takes_witnesses, "must detect witnesses by type");
        assert_eq!(
            circuit.witnesses_param_name.as_ref().unwrap().to_string(),
            "w"
        );
        assert!(
            circuit.params.is_empty(),
            "witness param must not be public"
        );
        // `w.voter_secret` must parse as a WitnessAccess, not a plain
        // method/field chain on a regular variable.
        match &circuit.body[0] {
            ExprIR::Let { value, .. } => match &**value {
                ExprIR::FnCall { args, .. } => match &args[0] {
                    ExprIR::Reference { expr, .. } => match &**expr {
                        ExprIR::WitnessAccess { field, .. } => {
                            assert_eq!(field.to_string(), "voter_secret");
                        }
                        other => panic!("expected WitnessAccess, got: {other:?}"),
                    },
                    other => panic!("expected Reference, got: {other:?}"),
                },
                other => panic!("expected FnCall, got: {other:?}"),
            },
            other => panic!("expected Let, got: {other:?}"),
        }
    }

    #[test]
    fn param_named_num_witnesses_is_a_public_param() {
        let ir = parse(quote::quote! {
            mod misleading_name {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn bump(&mut self, num_witnesses: u64) {
                        self.count.increment();
                    }
                }
            }
        })
        .expect("u64 param named num_witnesses must parse");

        let circuit = &ir.circuits[0];
        assert!(!circuit.takes_witnesses);
        assert_eq!(circuit.params.len(), 1, "num_witnesses must stay public");
        assert_eq!(circuit.params[0].name.to_string(), "num_witnesses");
    }

    #[test]
    fn local_var_named_eyewitnesses_is_not_a_witness_receiver() {
        let ir = parse(quote::quote! {
            mod local_name {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                #[nocturne(witnesses)]
                pub struct W { secret: Field }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, witnesses: &W) {
                        let eyewitnesses = 1u64;
                        let y = eyewitnesses.wrapping_add(2);
                        self.count.increment();
                    }
                }
            }
        })
        .expect("local named eyewitnesses must parse");

        let circuit = &ir.circuits[0];
        match &circuit.body[1] {
            ExprIR::Let { value, .. } => match &**value {
                ExprIR::MethodCall { method, .. } => {
                    assert_eq!(method.to_string(), "wrapping_add");
                }
                other => {
                    panic!("expected MethodCall (not WitnessCall) on local var, got: {other:?}")
                }
            },
            other => panic!("expected Let, got: {other:?}"),
        }
    }

    #[test]
    fn impl_before_witnesses_struct_registers_methods() {
        let ir = parse(quote::quote! {
            mod impl_first {
                #[nocturne(ledger)]
                pub struct State { stored: Cell<Field> }

                // Declared BEFORE the witnesses struct — two-pass item
                // processing must still register the method.
                impl W {
                    pub fn derive(&self) -> Field {
                        Field::default()
                    }
                }

                #[nocturne(witnesses)]
                pub struct W;

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { stored: Cell::new(Field::default()) } }

                    #[nocturne(circuit)]
                    pub fn store(&mut self, witnesses: &W) {
                        self.stored.set(witnesses.derive());
                    }
                }
            }
        })
        .expect("impl-before-struct must parse");

        let w = ir.witnesses.as_ref().expect("witnesses registered");
        assert_eq!(w.methods.len(), 1, "method from impl-before-struct");
        assert_eq!(w.methods[0].name.to_string(), "derive");
        match &ir.circuits[0].body[0] {
            ExprIR::LedgerAccess { args, .. } => match &args[0] {
                ExprIR::WitnessCall { name, .. } => {
                    assert_eq!(name.to_string(), "derive");
                }
                other => panic!("expected WitnessCall, got: {other:?}"),
            },
            other => panic!("expected LedgerAccess, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Post-parse witness resolution validation (M7, L3)
    // -----------------------------------------------------------------

    #[test]
    fn unknown_witness_field_is_rejected() {
        let err = parse(quote::quote! {
            mod typo_field {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                #[nocturne(witnesses)]
                pub struct W { secret: Field }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, witnesses: &W) {
                        let x = witnesses.sekret;
                        self.count.increment();
                    }
                }
            }
        })
        .expect_err("typo'd witness field must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("sekret"),
            "diagnostic must name the unknown field; got: {msg}"
        );
    }

    #[test]
    fn unknown_witness_method_is_rejected() {
        let err = parse(quote::quote! {
            mod typo_method {
                #[nocturne(ledger)]
                pub struct State { stored: Cell<Field> }

                #[nocturne(witnesses)]
                pub struct W;

                impl W {
                    pub fn derive(&self) -> Field { Field::default() }
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { stored: Cell::new(Field::default()) } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, witnesses: &W) {
                        self.stored.set(witnesses.derve());
                    }
                }
            }
        })
        .expect_err("typo'd witness method must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("derve"),
            "diagnostic must name the unknown method; got: {msg}"
        );
    }

    #[test]
    fn non_registered_method_on_witnesses_receiver_is_rejected() {
        let err = parse(quote::quote! {
            mod clone_call {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                #[nocturne(witnesses)]
                pub struct W { secret: Field }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, witnesses: &W) {
                        let w2 = witnesses.clone();
                        self.count.increment();
                    }
                }
            }
        })
        .expect_err("witnesses.clone() must error, not become a WitnessCall");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("clone"),
            "diagnostic must name the method; got: {msg}"
        );
    }

    // -----------------------------------------------------------------
    // Attribute parsing diagnostics (M2, L4)
    // -----------------------------------------------------------------

    #[test]
    fn misspelled_nocturne_attr_is_rejected() {
        let err = parse(quote::quote! {
            mod typo_attr {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circut)]
                    pub fn bump(&mut self) {
                        self.count.increment();
                    }
                }
            }
        })
        .expect_err("#[nocturne(circut)] must be a spanned error, not silently ignored");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("circut") && msg.contains("circuit"),
            "diagnostic must name the typo and list valid attrs; got: {msg}"
        );
    }

    #[test]
    fn bare_nocturne_attr_is_rejected() {
        let err = parse(quote::quote! {
            mod bare_attr {
                #[nocturne]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
            }
        })
        .expect_err("#[nocturne] without arguments must error");
        // Must be the dedicated attribute diagnostic — a message
        // substring check would also pass on the old behavior's
        // MissingLedger fallback (whose text mentions "nocturne" too).
        let err = err.into_first_error();
        assert_eq!(err.code, crate::error::ErrorCode::InvalidAttribute);
    }

    #[test]
    fn duplicate_nocturne_attrs_on_one_item_are_rejected() {
        let err = parse(quote::quote! {
            mod dup_attr {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    #[nocturne(query)]
                    pub fn confused(&mut self) {
                        self.count.increment();
                    }
                }
            }
        })
        .expect_err("two #[nocturne(...)] attrs on one item must error, not first-wins");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("duplicate"),
            "diagnostic must say duplicate; got: {msg}"
        );
    }

    #[test]
    fn trailing_comma_in_nocturne_attr_is_tolerated() {
        let ir = parse(quote::quote! {
            mod trailing_comma {
                #[nocturne(ledger,)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit,)]
                    pub fn bump(&mut self) {
                        self.count.increment();
                    }
                }
            }
        })
        .expect("trailing comma in attr args must parse");
        assert_eq!(ir.circuits.len(), 1);
    }

    // -----------------------------------------------------------------
    // Multi-error emission (M6)
    // -----------------------------------------------------------------

    #[test]
    fn multiple_errors_are_all_collected() {
        let err = parse(quote::quote! {
            mod two_bad {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                #[nocturne(witnesses)]
                pub struct W { secret: Field }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn a(&mut self, witnesses: &W) {
                        let x = witnesses.sekret;
                        self.count.increment();
                    }

                    #[nocturne(circuit)]
                    pub fn b(&mut self, witnesses: &W) {
                        let y = witnesses.also_wrong;
                        self.count.increment();
                    }
                }
            }
        })
        .expect_err("both bad circuits must error");
        assert_eq!(
            err.errors().len(),
            2,
            "both errors must be collected, not just the first; got: {err:?}"
        );
        let msg = format!("{err:?}");
        assert!(msg.contains("sekret") && msg.contains("also_wrong"));
    }

    // -----------------------------------------------------------------
    // Match scrutinee bound once (H2)
    // -----------------------------------------------------------------

    fn count_witness_calls(body: &[ExprIR]) -> usize {
        let mut n = 0;
        for stmt in body {
            crate::parse::for_each_expr(stmt, &mut |e| {
                if matches!(e, ExprIR::WitnessCall { .. }) {
                    n += 1;
                }
            });
        }
        n
    }

    #[test]
    fn match_on_witness_call_scrutinee_draws_once() {
        let ir = parse(quote::quote! {
            mod scrutinee_once {
                pub enum Vote { For, Against, Abstain }

                #[nocturne(ledger)]
                pub struct State { a: Counter, b: Counter }

                #[nocturne(witnesses)]
                pub struct W;

                impl W {
                    pub fn choice(&self) -> Vote { Vote::For }
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { a: Counter::zero(), b: Counter::zero() }
                    }

                    #[nocturne(circuit)]
                    pub fn cast(&mut self, witnesses: &W) {
                        // Two qualified arms + wildcard: without the
                        // bind-once fix the scrutinee is cloned into
                        // each arm's comparison (two witness draws).
                        match witnesses.choice() {
                            Vote::For => { self.a.increment(); }
                            Vote::Against => { self.b.increment(); }
                            _ => { self.a.increment(); }
                        }
                    }
                }
            }
        })
        .expect("match on a WitnessCall scrutinee must parse");

        let body = &ir.circuits[0].body;
        assert_eq!(
            count_witness_calls(body),
            1,
            "an effectful scrutinee must be drawn exactly once, not once per arm; body: {body:?}"
        );
    }

    // -----------------------------------------------------------------
    // Exact-match disclose (H4)
    // -----------------------------------------------------------------

    #[test]
    fn helper_named_disclose_amount_is_not_hijacked() {
        let ir = parse(quote::quote! {
            mod not_disclose {
                #[nocturne(ledger)]
                pub struct State { total: Cell<u64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { total: Cell::new(0) } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, a: u64, b: u64) {
                        self.total.set(disclose_amount(a, b));
                    }
                }

                pub fn disclose_amount(a: u64, b: u64) -> u64 { a + b }
            }
        })
        .expect("disclose_amount must parse as a regular helper call");

        match &ir.circuits[0].body[0] {
            ExprIR::LedgerAccess { args, .. } => match &args[0] {
                ExprIR::FnCall { name, args, .. } => {
                    assert_eq!(name.to_string(), "disclose_amount");
                    assert_eq!(args.len(), 2, "both args must be preserved");
                }
                other => panic!("expected FnCall, got: {other:?}"),
            },
            other => panic!("expected LedgerAccess, got: {other:?}"),
        }
    }

    #[test]
    fn disclose_with_two_args_is_rejected() {
        let err = parse(quote::quote! {
            mod bad_disclose {
                #[nocturne(ledger)]
                pub struct State { total: Cell<u64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { total: Cell::new(0) } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, a: u64, b: u64) {
                        self.total.set(nocturne::disclose(a, b));
                    }
                }
            }
        })
        .expect_err("disclose with two args must error");
        let msg = format!("{err:?}");
        assert!(msg.contains("disclose"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // Loop unroll cap (H5)
    // -----------------------------------------------------------------

    #[test]
    fn for_loop_over_unroll_cap_is_rejected() {
        let err = parse(quote::quote! {
            mod big_loop {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self) {
                        for _i in 0..2000 {
                            self.count.increment();
                        }
                    }
                }
            }
        })
        .expect_err("2000-iteration unroll must be rejected");
        let err = err.into_first_error();
        assert_eq!(err.code, crate::error::ErrorCode::UnsupportedLoop);
        assert!(
            err.message.contains("2000") && err.message.contains("1024"),
            "message must include the count and the cap; got: {}",
            err.message
        );
    }

    #[test]
    fn for_loop_at_unroll_cap_parses() {
        let ir = parse(quote::quote! {
            mod max_loop {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self) {
                        for _i in 0..1024 {
                            self.count.increment();
                        }
                    }
                }
            }
        })
        .expect("1024 iterations is exactly at the cap and must parse");
        assert_eq!(ir.circuits.len(), 1);
    }

    // -----------------------------------------------------------------
    // `as` casts: transparent only when provably non-narrowing (M3)
    // -----------------------------------------------------------------

    #[test]
    fn width_equal_witness_cast_keeps_parsing() {
        // The `witnesses.target.value() as u64` pattern with a Uint<64>
        // witness (ledger_integration_test.rs counter_set contract).
        let ir = parse(quote::quote! {
            mod counter_set {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                #[nocturne(witnesses)]
                pub struct W { pub target: Uint<64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn assign(&mut self, witnesses: &W) {
                        self.count.set(witnesses.target.value() as u64);
                    }
                }
            }
        })
        .expect("width-equal cast must keep parsing");
        // Cast stays transparent: the arg is the inner MethodCall.
        match &ir.circuits[0].body[0] {
            ExprIR::LedgerAccess { args, .. } => match &args[0] {
                ExprIR::MethodCall { method, .. } => {
                    assert_eq!(method.to_string(), "value");
                }
                other => panic!("expected MethodCall, got: {other:?}"),
            },
            other => panic!("expected LedgerAccess, got: {other:?}"),
        }
    }

    #[test]
    fn narrowing_witness_cast_is_rejected() {
        let err = parse(quote::quote! {
            mod narrows {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                #[nocturne(witnesses)]
                pub struct W { pub target: Uint<64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }

                    #[nocturne(circuit)]
                    pub fn assign(&mut self, witnesses: &W) {
                        self.count.set(witnesses.target.value() as u32);
                    }
                }
            }
        })
        .expect_err("Uint<64> -> u32 cast must be rejected as narrowing");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("narrow"),
            "diagnostic must explain narrowing; got: {msg}"
        );
    }

    #[test]
    fn widening_param_cast_parses_and_narrowing_param_cast_errors() {
        let ok = parse(quote::quote! {
            mod widens {
                #[nocturne(ledger)]
                pub struct State { total: Cell<u64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { total: Cell::new(0) } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, x: u32) {
                        self.total.set(x as u64);
                    }
                }
            }
        });
        assert!(ok.is_ok(), "u32 -> u64 param cast must parse: {ok:?}");

        let err = parse(quote::quote! {
            mod narrows_param {
                #[nocturne(ledger)]
                pub struct State { total: Cell<u64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { total: Cell::new(0) } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, x: u64) {
                        self.total.set(x as u32);
                    }
                }
            }
        });
        assert!(err.is_err(), "u64 -> u32 param cast must be rejected");
    }

    #[test]
    fn let_shadowing_a_param_blocks_param_width_inference() {
        // `let x = ...` rebinds the u32 param `x` to a width-unknown
        // value; resolving the later `x as u32` against the PARAM type
        // would wrongly prove the cast non-narrowing. The shadowed
        // ident must infer as width-unknown, so the cast errors.
        let err = parse(quote::quote! {
            mod shadows {
                #[nocturne(ledger)]
                pub struct State { big: Cell<u64>, total: Cell<u64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { big: Cell::new(0), total: Cell::new(0) }
                    }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, x: u32) {
                        let x = self.big.get();
                        self.total.set(x as u32);
                    }
                }
            }
        })
        .expect_err("cast of a let-shadowed param must not use the param's width");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("not inferable"),
            "diagnostic must say the width is not inferable; got: {msg}"
        );
    }

    #[test]
    fn uninferable_cast_to_u128_is_allowed() {
        let ir = parse(quote::quote! {
            mod widest {
                #[nocturne(ledger)]
                pub struct State { total: Cell<u128> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { total: Cell::new(0) } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self) {
                        let v = self.total.get();
                        self.total.set(v as u128);
                    }
                }
            }
        })
        .expect("cast to u128 can never narrow and must parse");
        assert_eq!(ir.circuits.len(), 1);
    }

    // -----------------------------------------------------------------
    // Compound assignment + non-ident params (M4, M1)
    // -----------------------------------------------------------------

    #[test]
    fn compound_assignment_is_rejected() {
        let err = parse(quote::quote! {
            mod plus_eq {
                #[nocturne(ledger)]
                pub struct State { total: Cell<u64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { total: Cell::new(0) } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, x: u64) {
                        let mut acc = 1u64;
                        acc += x;
                        self.total.set(acc);
                    }
                }
            }
        })
        .expect_err("+= must be a hard error, not a silent miscompile");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("let"),
            "diagnostic must suggest rebinding; got: {msg}"
        );
    }

    #[test]
    fn tuple_pattern_param_is_rejected() {
        let err = parse(quote::quote! {
            mod tuple_param {
                #[nocturne(ledger)]
                pub struct State { total: Cell<u64> }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { total: Cell::new(0) } }

                    #[nocturne(circuit)]
                    pub fn run(&mut self, (a, b): (u64, u64)) {
                        self.total.set(a + b);
                    }
                }
            }
        })
        .expect_err("tuple-pattern param must be a hard error, not silently dropped");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("identifier"),
            "diagnostic must explain the restriction; got: {msg}"
        );
    }

    // -----------------------------------------------------------------
    // Small parser validations (M8, M9, L1, L6)
    // -----------------------------------------------------------------

    #[test]
    fn constructor_with_wrong_return_type_is_rejected() {
        let err = parse(quote::quote! {
            mod bad_ctor {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> u64 { 0 }

                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
            }
        })
        .expect_err("constructor returning u64 must be rejected");
        let err = err.into_first_error();
        assert_eq!(err.code, crate::error::ErrorCode::InvalidConstructorReturn);
    }

    #[test]
    fn constructor_returning_ledger_name_parses() {
        let ir = parse(quote::quote! {
            mod named_ctor {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> State {
                        State { count: Counter::zero() }
                    }

                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }
            }
        })
        .expect("constructor returning the ledger struct name must parse");
        assert_eq!(ir.constructors.len(), 1);
    }

    #[test]
    fn generic_free_fn_is_not_a_helper() {
        let ir = parse(quote::quote! {
            mod generic_helper {
                #[nocturne(ledger)]
                pub struct State { count: Counter }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn noop(&mut self) {}
                }

                pub fn id<T>(x: T) -> T { x }
            }
        })
        .expect("generic free fn must not error the parse");
        assert!(
            ir.helpers.is_empty(),
            "generic fns can't be inlined and must not register as helpers"
        );
    }

    #[test]
    fn glob_imported_variant_pattern_is_rejected() {
        let err = parse(quote::quote! {
            mod glob_variant {
                pub enum Status { Open, Closed }

                #[nocturne(ledger)]
                pub struct State { a: Counter, b: Counter }

                #[nocturne(witnesses)]
                pub struct W { pub status: Status }

                impl State {
                    #[nocturne(circuit)]
                    pub fn run(&mut self, witnesses: &W) {
                        match witnesses.status {
                            Status::Open => { self.a.increment(); }
                            Closed => { self.b.increment(); }
                        }
                    }

                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { a: Counter::zero(), b: Counter::zero() }
                    }
                }
            }
        })
        .expect_err("bare `Closed` arm silently becomes a wildcard; must error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Closed") && msg.contains("Status"),
            "diagnostic must tell the user to qualify; got: {msg}"
        );
    }

    #[test]
    fn binding_arm_colliding_with_unrelated_enum_variant_is_allowed() {
        // The glob-variant check must only consult enums named by the
        // match's qualified arms (`Status::Open` names `Status`). The
        // catch-all binding `low` here collides with UNRELATED
        // `Levels::low`; rejecting it would be misleading — Rust never
        // resolves it as a variant in a match over `Status`.
        let ir = parse(quote::quote! {
            mod unrelated_collision {
                pub enum Status { Open, Closed }
                pub enum Levels { low, high }

                #[nocturne(ledger)]
                pub struct State { a: Counter, b: Counter }

                #[nocturne(witnesses)]
                pub struct W { pub status: Status }

                impl State {
                    #[nocturne(circuit)]
                    pub fn run(&mut self, witnesses: &W) {
                        match witnesses.status {
                            Status::Open => { self.a.increment(); }
                            low => { self.b.increment(); }
                        }
                    }

                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { a: Counter::zero(), b: Counter::zero() }
                    }
                }
            }
        })
        .expect("binding arm colliding with an unrelated enum's variant must parse");
        assert_eq!(ir.circuits.len(), 1);
    }

    #[test]
    fn mod_without_inline_content_is_rejected() {
        let err = parse(quote::quote! {
            mod external;
        })
        .expect_err("`mod foo;` must get a dedicated error");
        let err = err.into_first_error();
        assert_eq!(err.code, crate::error::ErrorCode::EmptyContractModule);
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
