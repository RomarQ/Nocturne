//! End-to-end ledger application against an in-memory `LedgerState`.
//!
//! The other integration tests stop at prove/verify: they confirm a
//! Nocturne-emitted circuit accepts a ledger-constructed `ProofPreimage`
//! and that the proof verifies with the right public-input layout. They
//! never run the generated transcript ops against live on-chain state.
//!
//! This test closes that gap. It builds a `ContractDeploy` from
//! `deploy::initial_state()`, applies it to a fresh `LedgerState`, then
//! applies a `ContractCall` carrying the generated `increment` transcript
//! and asserts the on-chain counter actually advanced. The apply path runs
//! `QueryContext::run_transcript` over the contract's stored state and
//! writes the result back (midnight-ledger semantics.rs `LedgerState::apply`,
//! the contract-call arm), so a transcript that is subtly wrong, even one
//! that satisfies the verifier PI layout, would diverge here at execution
//! time rather than slipping through.
//!
//! No proving apparatus is needed: `WellFormedStrictness` with
//! `verify_contract_proofs = false` skips proof verification entirely
//! (midnight-ledger verify.rs, the `if strictness.verify_contract_proofs`
//! gate around `proof_verify`), so the transaction carries a
//! `ProofPreimage` marker and applies without keygen or a verifier key.

use std::ops::Deref;

use nocturne::runtime::onchain_state::state::{
    ContractMaintenanceAuthority, ContractState, StateValue,
};
use nocturne::runtime::transient_crypto::curve::Fr;
use nocturne::runtime::transient_crypto::fab::AlignedValueExt;
use nocturne::types::*;

use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::construct::ContractCallPrototype;
use midnight_ledger::structure::{ContractDeploy, Transaction};
use midnight_ledger::test_utilities::{TestState, test_intents};
use midnight_ledger::verify::WellFormedStrictness;
use midnight_onchain_runtime::context::QueryContext;
use midnight_onchain_runtime::ops::Op;
use midnight_onchain_runtime::result_mode::ResultModeVerify;
use midnight_onchain_runtime::state::{ContractOperation, EntryPointBuf};
use midnight_onchain_runtime::transcript::{Transcript, TranscriptVersion};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap;

#[nocturne::contract]
mod counter {
    use super::*;

    #[nocturne(ledger)]
    pub struct CounterState {
        pub count: Counter,
    }

    impl CounterState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[nocturne(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }
    }
}

#[nocturne::contract]
mod vault {
    use super::*;

    #[nocturne(ledger)]
    pub struct VaultState {
        pub balance: Cell<Uint<64>>,
    }

    impl VaultState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                balance: Cell::new(Uint::<64>::from(0u64)),
            }
        }

        #[nocturne(circuit)]
        pub fn deposit(&mut self) {
            self.balance.set(Uint::<64>::from(100u64));
        }
    }
}

/// Strictness that applies a contract transaction without any proving:
/// no balancing, no proof/signature verification, no limits. We are
/// exercising transcript execution against state, not the fee/proof
/// machinery.
fn no_proof_strictness() -> WellFormedStrictness {
    let mut s = WellFormedStrictness::default();
    s.enforce_balancing = false;
    s.verify_native_proofs = false;
    s.verify_contract_proofs = false;
    s.verify_signatures = false;
    s.enforce_limits = false;
    s
}

/// Decode field 0 of the contract's state Array to its field-element
/// representation. Both `Counter` and `Cell<Uint<64>>` are on-chain `Cell`s
/// holding a single u64, so this is one `Fr`.
fn read_cell_field0(state: &TestState<InMemoryDB>, addr: ContractAddress) -> Vec<Fr> {
    let cstate = state
        .ledger
        .index(addr)
        .expect("contract must be deployed at addr");
    let data = cstate.data.get_ref();
    let StateValue::Array(fields) = data else {
        panic!("expected contract state to be a StateValue::Array, got {data:?}");
    };
    let field0 = fields
        .iter()
        .next()
        .expect("contract has at least one field");
    let mut frs = Vec::new();
    match field0.deref() {
        StateValue::Cell(av) => av.deref().value_only_field_repr(&mut frs),
        other => panic!("expected field 0 to be a Cell, got {other:?}"),
    }
    frs
}

/// Deploy a contract whose initial state is `initial_state`, returning its
/// on-chain address. Registers no operations (see the comment in the test).
fn deploy(
    state: &mut TestState<InMemoryDB>,
    rng: &mut (impl rand::Rng + rand::CryptoRng),
    initial_state: StateValue<InMemoryDB>,
) -> ContractAddress {
    let cstate = ContractState::new(
        initial_state,
        HashMap::new(),
        ContractMaintenanceAuthority::new(),
    );
    let deploy = ContractDeploy::new(rng, cstate);
    let addr = deploy.address();
    let tx = Transaction::from_intents(
        "local-test",
        test_intents(rng, Vec::new(), Vec::new(), vec![deploy], state.time),
    );
    state.assert_apply(&tx, no_proof_strictness());
    addr
}

/// Apply a single contract call carrying the generated `ops` for
/// `entry_point`. Declares the transcript's gas and effects by dry-running
/// the program against the contract's current state (what a real prover
/// commits to), then applies the call to the ledger.
fn apply_call(
    state: &mut TestState<InMemoryDB>,
    rng: &mut (impl rand::Rng + rand::CryptoRng),
    addr: ContractAddress,
    entry_point: &str,
    ops: Vec<Op<ResultModeVerify, InMemoryDB>>,
) {
    // apply re-runs the program with `Some(gas)` as the budget and rejects a
    // declared-effects mismatch (semantics.rs), so under-declaring gas is
    // OutOfGas and wrong effects is EffectsMismatch. Declare both exactly.
    let cost_model = &state.ledger.parameters.cost_model.runtime_cost_model;
    let cstate = state.ledger.index(addr).expect("contract deployed");
    let dry_run = QueryContext::new(cstate.data.clone(), addr)
        .query::<ResultModeVerify>(&ops, None, cost_model)
        .expect("transcript must execute against the deployed state");

    let transcript = Transcript {
        gas: dry_run.gas_cost,
        effects: dry_run.context.effects.clone(),
        program: ops.into(),
        version: Some(Sp::new(TranscriptVersion { major: 2, minor: 3 })),
    };

    let prototype: ContractCallPrototype<InMemoryDB> = ContractCallPrototype {
        address: addr,
        entry_point: EntryPointBuf(entry_point.as_bytes().to_vec()),
        op: ContractOperation::new(None),
        guaranteed_public_transcript: Some(transcript),
        fallible_public_transcript: None,
        private_transcript_outputs: Vec::new(),
        input: ().into(),
        output: ().into(),
        communication_commitment_rand: Fr::from(0xc0ffeeu64),
        key_location: midnight_transient_crypto::proofs::KeyLocation(std::borrow::Cow::Borrowed(
            "test::call",
        )),
    };

    let tx = Transaction::from_intents(
        "local-test",
        test_intents(rng, vec![prototype], Vec::new(), Vec::new(), state.time),
    );
    state.assert_apply(&tx, no_proof_strictness());
}

/// Counter: the `Counter::increment()` path lowers to an on-chain `Addi`.
/// Deploy, then apply two increments, asserting the stored counter advances
/// 0 -> 1 -> 2 as the transcript executes against ledger state.
#[test]
fn counter_deploy_and_increment_apply_to_in_memory_ledger() {
    let mut rng = rand::thread_rng();
    let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);

    let addr = deploy(&mut state, &mut rng, counter::deploy::initial_state());
    assert_eq!(
        read_cell_field0(&state, addr),
        vec![Fr::from(0u64)],
        "freshly deployed counter must read 0"
    );

    apply_call(
        &mut state,
        &mut rng,
        addr,
        "increment",
        counter::transcript::build_increment_transcript().ops,
    );
    assert_eq!(
        read_cell_field0(&state, addr),
        vec![Fr::from(1u64)],
        "counter must read 1 after one increment executes on-chain"
    );

    apply_call(
        &mut state,
        &mut rng,
        addr,
        "increment",
        counter::transcript::build_increment_transcript().ops,
    );
    assert_eq!(
        read_cell_field0(&state, addr),
        vec![Fr::from(2u64)],
        "counter must read 2 after a second increment executes on-chain"
    );
}

/// Cell write: `Cell::<Uint<64>>::set(100)` lowers to a `Push` + `Ins`
/// against the field slot, a different execution path than the counter's
/// `Addi`. Deploy reads 0, and after the call the stored cell reads 100.
#[test]
fn cell_set_applies_to_in_memory_ledger() {
    let mut rng = rand::thread_rng();
    let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);

    let addr = deploy(&mut state, &mut rng, vault::deploy::initial_state());
    assert_eq!(
        read_cell_field0(&state, addr),
        vec![Fr::from(0u64)],
        "freshly deployed vault balance must read 0"
    );

    apply_call(
        &mut state,
        &mut rng,
        addr,
        "deposit",
        vault::transcript::build_deposit_transcript().ops,
    );
    assert_eq!(
        read_cell_field0(&state, addr),
        vec![Fr::from(100u64)],
        "vault balance must read 100 after deposit executes on-chain"
    );
}
