//! Integration test against midnight-ledger.
//!
//! Drives Nocturne-emitted circuits through the canonical ledger code path:
//! build a `ContractCallPrototype` → `ProofPreimage::construct_proof` → run
//! the resulting preimage through `IrSource::check` / `prove` / `verify`.
//!
//! This is the highest-fidelity on-chain compatibility check we can run
//! without standing up a Midnight node: if a circuit accepts a `ProofPreimage`
//! built by the same code path the on-chain `ContractCall` pipeline uses,
//! it's structurally compatible with the ledger.

use std::borrow::Cow;

use midnight::runtime::transient_crypto::curve::Fr;
use midnight::runtime::transient_crypto::hash::transient_commit;
use midnight::runtime::transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight::types::*;

use midnight_base_crypto::cost_model::RunningCost;
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::construct::{ContractCallExt, ContractCallPrototype};
use midnight_ledger::structure::ProofPreimageVersioned;
use midnight_ledger_storage::arena::Sp;
use midnight_ledger_storage::db::InMemoryDB;
use midnight_onchain_runtime::context::Effects;
use midnight_onchain_runtime::ops::Op;
use midnight_onchain_runtime::result_mode::ResultModeVerify;
use midnight_onchain_runtime::state::{ContractOperation, EntryPointBuf};
use midnight_onchain_runtime::transcript::{Transcript, TranscriptVersion};

#[midnight::contract]
mod counter {
    use super::*;

    #[midnight(ledger)]
    pub struct CounterState {
        pub count: Counter,
    }

    impl CounterState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }
    }
}

#[midnight::contract]
mod reader {
    use super::*;

    #[midnight(ledger)]
    pub struct ReaderState {
        pub stored: Cell<u64>,
    }

    impl ReaderState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                stored: Cell::new(0u64),
            }
        }

        #[midnight(circuit)]
        pub fn read_stored(&self) {
            let _v = self.stored.get();
        }
    }
}

#[midnight::contract]
mod bytes_witness {
    use super::*;

    #[midnight(ledger)]
    pub struct BytesWitnessState {
        pub count: Counter,
    }

    #[midnight(witnesses)]
    pub struct BytesWitnessWitnesses {
        pub digest: Bytes<32>,
    }

    impl BytesWitnessState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn take_digest(&mut self, witnesses: &BytesWitnessWitnesses) {
            // Reference the witness so PrivateInput + ConstrainBits are
            // emitted. The actual digest isn't pushed on chain in this
            // minimal contract — we're just verifying the multi-Fr witness
            // serialization round-trips through prove+verify.
            let _d = witnesses.digest.clone();
            self.count.increment();
        }
    }
}

#[midnight::contract]
mod counter_reader {
    use super::*;

    #[midnight(ledger)]
    pub struct CounterReaderState {
        pub count: Counter,
    }

    impl CounterReaderState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn read_count(&self) {
            let _v = self.count.value();
        }
    }
}

#[midnight::contract]
mod records {
    use super::*;

    #[midnight(ledger)]
    pub struct RecordsState {
        pub records: Map<Uint<64>, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct RecordsWitnesses {
        pub user_id: Uint<64>,
        pub amount: Uint<64>,
    }

    impl RecordsState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &RecordsWitnesses) {
            self.records.insert(witnesses.user_id, witnesses.amount);
        }

        #[midnight(circuit)]
        pub fn erase(&mut self, witnesses: &RecordsWitnesses) {
            self.records.remove(&witnesses.user_id);
        }

        #[midnight(circuit)]
        pub fn fetch(&self, witnesses: &RecordsWitnesses) {
            let _v = self.records.lookup(&witnesses.user_id);
        }
    }
}

#[midnight::contract]
mod membership {
    use super::*;

    #[midnight(ledger)]
    pub struct MembersState {
        pub members: Map<Uint<64>, Boolean>,
    }

    #[midnight(witnesses)]
    pub struct MembersWitnesses {
        pub user_id: Uint<64>,
    }

    impl MembersState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                members: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn check_member(&self, witnesses: &MembersWitnesses) {
            let _exists = self.members.contains(&witnesses.user_id);
        }
    }
}

#[midnight::contract]
mod flag {
    use super::*;

    #[midnight(ledger)]
    pub struct FlagState {
        pub raised: Cell<bool>,
    }

    impl FlagState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                raised: Cell::new(false),
            }
        }

        #[midnight(circuit)]
        pub fn raise(&mut self) {
            self.raised.set(true);
        }
    }
}

#[midnight::contract]
mod ballot {
    use super::*;

    #[midnight(ledger)]
    pub struct Ballot {
        pub votes_for: Counter,
        pub votes_against: Counter,
    }

    #[midnight(witnesses)]
    pub struct BallotWitnesses {
        pub choice: Boolean,
    }

    impl Ballot {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                votes_for: Counter::zero(),
                votes_against: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
            if witnesses.choice.value() {
                self.votes_for.increment();
            } else {
                self.votes_against.increment();
            }
        }
    }
}

fn build_counter_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod counter {
            #[midnight(ledger)]
            pub struct CounterState { count: Counter }
            impl CounterState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn increment(&mut self) { self.count.increment(); }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output.circuits.into_iter().next().unwrap().ir_source
}

fn build_read_stored_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod reader {
            #[midnight(ledger)]
            pub struct ReaderState { stored: Cell<u64> }
            impl ReaderState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { stored: Cell::new(0u64) } }
                #[midnight(circuit)]
                pub fn read_stored(&self) {
                    let _v = self.stored.get();
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "read_stored")
        .unwrap()
        .ir_source
}

fn build_take_digest_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod bytes_witness {
            #[midnight(ledger)]
            pub struct BytesWitnessState { count: Counter }
            #[midnight(witnesses)]
            pub struct BytesWitnessWitnesses { pub digest: Bytes<32> }
            impl BytesWitnessState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn take_digest(&mut self, witnesses: &BytesWitnessWitnesses) {
                    let _d = witnesses.digest.clone();
                    self.count.increment();
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "take_digest")
        .unwrap()
        .ir_source
}

fn build_read_count_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod counter_reader {
            #[midnight(ledger)]
            pub struct CounterReaderState { count: Counter }
            impl CounterReaderState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn read_count(&self) {
                    let _v = self.count.value();
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "read_count")
        .unwrap()
        .ir_source
}

fn build_records_circuit_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod records {
            #[midnight(ledger)]
            pub struct RecordsState { records: Map<Uint<64>, Uint<64>> }
            #[midnight(witnesses)]
            pub struct RecordsWitnesses { pub user_id: Uint<64>, pub amount: Uint<64> }
            impl RecordsState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &RecordsWitnesses) {
                    self.records.insert(witnesses.user_id, witnesses.amount);
                }
                #[midnight(circuit)]
                pub fn erase(&mut self, witnesses: &RecordsWitnesses) {
                    self.records.remove(&witnesses.user_id);
                }
                #[midnight(circuit)]
                pub fn fetch(&self, witnesses: &RecordsWitnesses) {
                    let _v = self.records.lookup(&witnesses.user_id);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == circuit_name)
        .unwrap()
        .ir_source
}

fn build_record_ir() -> midnight_zkir::IrSource {
    build_records_circuit_ir("record")
}

fn build_erase_ir() -> midnight_zkir::IrSource {
    build_records_circuit_ir("erase")
}

fn build_fetch_ir() -> midnight_zkir::IrSource {
    build_records_circuit_ir("fetch")
}

fn build_check_member_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod membership {
            #[midnight(ledger)]
            pub struct MembersState { members: Map<Uint<64>, Boolean> }
            #[midnight(witnesses)]
            pub struct MembersWitnesses { pub user_id: Uint<64> }
            impl MembersState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { members: Map::empty() } }
                #[midnight(circuit)]
                pub fn check_member(&self, witnesses: &MembersWitnesses) {
                    let _exists = self.members.contains(&witnesses.user_id);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "check_member")
        .unwrap()
        .ir_source
}

fn build_flag_raise_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod flag {
            #[midnight(ledger)]
            pub struct FlagState { raised: Cell<bool> }
            impl FlagState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { raised: Cell::new(false) } }
                #[midnight(circuit)]
                pub fn raise(&mut self) { self.raised.set(true); }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "raise")
        .unwrap()
        .ir_source
}

fn build_cast_vote_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod ballot {
            #[midnight(ledger)]
            pub struct Ballot {
                pub votes_for: Counter,
                pub votes_against: Counter,
            }
            #[midnight(witnesses)]
            pub struct BallotWitnesses { pub choice: Boolean }
            impl Ballot {
                #[midnight(constructor)]
                pub fn new() -> Self {
                    Self { votes_for: Counter::zero(), votes_against: Counter::zero() }
                }
                #[midnight(circuit)]
                pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
                    if witnesses.choice.value() {
                        self.votes_for.increment();
                    } else {
                        self.votes_against.increment();
                    }
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "cast_vote")
        .unwrap()
        .ir_source
}

/// Build a canonical `ProofPreimage` for a given circuit by going through
/// `<ProofPreimage as ContractCallExt>::construct_proof` — the same code
/// path used by `Intent::add_call` when building an on-chain transaction.
fn canonical_preimage(
    ir_circuit_name: &str,
    active_ops: Vec<Op<ResultModeVerify, InMemoryDB>>,
    private_transcript_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue>,
) -> ProofPreimage {
    let rand = Fr::from(0xdeadu64);
    let input = ().into();
    let output = ().into();

    let prototype: ContractCallPrototype<InMemoryDB> = ContractCallPrototype {
        address: ContractAddress(Default::default()),
        entry_point: EntryPointBuf(ir_circuit_name.as_bytes().into()),
        op: ContractOperation::new(None),
        guaranteed_public_transcript: Some(wrap_transcript(active_ops)),
        fallible_public_transcript: None,
        private_transcript_outputs,
        input,
        output,
        communication_commitment_rand: rand,
        key_location: KeyLocation(Cow::Owned(format!("test::{ir_circuit_name}"))),
    };

    use midnight::runtime::transient_crypto::repr::FieldRepr;
    let mut io_repr: Vec<Fr> = Vec::new();
    midnight::runtime::transient_crypto::fab::ValueReprAlignedValue(prototype.input.clone())
        .field_repr(&mut io_repr);
    midnight::runtime::transient_crypto::fab::ValueReprAlignedValue(prototype.output.clone())
        .field_repr(&mut io_repr);
    let comm_comm = transient_commit::<[Fr]>(&io_repr, rand);

    let preimage_v =
        <ProofPreimage as ContractCallExt<InMemoryDB>>::construct_proof(&prototype, comm_comm);
    match preimage_v {
        ProofPreimageVersioned::V2(p) => (*p).clone(),
        _ => panic!("unexpected ProofPreimageVersioned variant"),
    }
}

/// Wrap a vector of Ops in a minimal Transcript usable as
/// `guaranteed_public_transcript`. Gas and effects are defaults — the
/// `construct_proof` path only inspects the program.
fn wrap_transcript(ops: Vec<Op<ResultModeVerify, InMemoryDB>>) -> Transcript<InMemoryDB> {
    Transcript {
        gas: RunningCost::default(),
        effects: Effects::<InMemoryDB>::default(),
        program: ops.into(),
        version: Some(Sp::new(TranscriptVersion { major: 2, minor: 3 })),
    }
}

#[tokio::test]
async fn counter_ledger_constructed_preimage_satisfies_circuit() {
    let ir = build_counter_ir();
    let nocturne_transcript = counter::transcript::build_increment_transcript();
    let preimage = canonical_preimage("increment", nocturne_transcript.ops, vec![]);
    ir.check(&preimage)
        .expect("Nocturne counter circuit must accept a ledger-constructed ProofPreimage");
}

#[tokio::test]
async fn counter_ledger_constructed_preimage_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_counter_ir();
    let nocturne_transcript = counter::transcript::build_increment_transcript();
    let preimage = canonical_preimage("increment", nocturne_transcript.ops, vec![]);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    vk.verify(&PARAMS_VERIFIER, &proof, pis.into_iter())
        .expect("ledger-constructed preimage must verify end-to-end");
}

/// Confirms on-chain compatibility for a conditional circuit (voting cast_vote).
///
/// Reproduces what the ledger does in `ContractCall::prove`
/// (ledger/src/prove.rs:263-289): walk `pi_skips`, splice `Op::Noop { n }`
/// into the transcript at each inactive segment. Then build the verifier
/// PIs the way `ContractCall::public_inputs` does
/// (`[binding_input, comm, ..field_repr(rewritten_transcript)]`) and verify
/// the proof with them.
///
/// For the fix to be correct, the IR must arrange for `DeclarePubInput`
/// values inside an inactive branch to be zero — matching `Op::Noop`'s
/// zero-padding `field_repr`. See
/// `memories/conditional-branch-cond-select-zeroing.md`.
#[tokio::test]
async fn voting_verifies_with_ledger_shape_pis() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_cast_vote_ir();
    let witnesses = ballot::BallotWitnesses {
        choice: Boolean::from(true),
    };
    let nocturne_transcript = ballot::transcript::build_cast_vote_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(true)];
    let preimage = canonical_preimage(
        "cast_vote",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    // Rebuild the on-chain transcript program: interleave Op::Noop { n } per pi_skips.
    let mut on_chain_program: Vec<VmOp<_, _>> = Vec::new();
    let mut skips_iter = skips.iter().peekable();
    for op in &nocturne_transcript.ops {
        while matches!(skips_iter.peek(), Some(Some(_))) {
            if let Some(Some(n)) = skips_iter.next() {
                on_chain_program.push(VmOp::Noop { n: *n as u32 });
            }
        }
        on_chain_program.push(op.clone());
        let _ = skips_iter.next();
    }
    for n in skips_iter.flatten() {
        on_chain_program.push(VmOp::Noop { n: *n as u32 });
    }

    // Build the ledger-shape PIs.
    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    // The two vectors should match exactly: prove returns the values for
    // every DeclarePubInput, and with the cond_select-zeroing fix, inactive
    // slots are zero — exactly what Noop's field_repr produces.
    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs \
         (binding_input + comm + Noop-interleaved transcript field_repr); \
         a mismatch means inactive-branch DeclarePubInputs aren't being zeroed"
    );

    // And verify must accept the ledger-shape PIs.
    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed with ledger-shape PIs");
}

/// Confirms `Cell<bool>::set(true)` produces an on-chain compatible
/// transcript: the IR and the runtime-built transcript agree, the proof
/// constructs through the canonical `ContractCallExt::construct_proof`
/// path, and the verifier accepts ledger-shape PIs built as
/// `[binding_input, comm, ..field_repr(transcript)]`.
///
/// Exercises the Push+Push+Ins encoding for storage writes
/// (see `memories/storage-cell-encoding-gap.md`).
#[tokio::test]
async fn flag_raise_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_flag_raise_ir();
    let nocturne_transcript = flag::transcript::build_raise_transcript();
    let preimage = canonical_preimage("raise", nocturne_transcript.ops.clone(), vec![]);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    // Build ledger-shape PIs: [binding_input, comm, ..field_repr(transcript)].
    // No conditional branches → no Noop interleaving needed.
    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs \
         for a Cell<bool>::set(true) circuit"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Cell::set");
}

/// Confirms `Map<Uint<64>, Boolean>::contains(&k)` produces an on-chain
/// compatible transcript: the IR Dup+Idx+Push+Member+Popeq sequence and
/// the runtime ops match, the bool result is computed off-chain from the
/// live state, the proof constructs through `ContractCallExt::construct_proof`,
/// and the verifier accepts ledger-shape PIs.
///
/// State is an empty `Map`, so the expected result for any key is `false`.
/// On-chain `Member` against an empty `StateValue::Map` returns `false` too,
/// so the off-chain Popeq and the on-chain VM agree.
#[tokio::test]
async fn map_contains_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_check_member_ir();
    let state = membership::MembersState::new();
    let witnesses = membership::MembersWitnesses {
        user_id: Uint::<64>::from(12345u64),
    };
    let nocturne_transcript =
        membership::transcript::build_check_member_transcript(&state, &witnesses);

    // PrivateInput reads from preimage.private_transcript, which is the
    // concatenated value-only field_repr of these AlignedValues. Order
    // matches the order of PrivateInput instructions in the IR (here:
    // the single Uint<64> witness for user_id).
    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> =
        vec![midnight::runtime::base_crypto::fab::AlignedValue::from(
            12345u64,
        )];
    let preimage = canonical_preimage(
        "check_member",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs \
         for a Map<Uint<64>, Boolean>::contains circuit"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map::contains");
}

/// Confirms `Map<Uint<64>, Uint<64>>::insert(k, v)` produces an on-chain
/// compatible transcript: the IR Idx+Push+Push+Ins+Ins sequence and the
/// runtime ops match exactly, the proof constructs through
/// `ContractCallExt::construct_proof`, and the verifier accepts
/// ledger-shape PIs. Inserts return no value, so there's no Popeq.
#[tokio::test]
async fn map_insert_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_record_ir();
    let mut state = records::RecordsState::new();
    let witnesses = records::RecordsWitnesses {
        user_id: Uint::<64>::from(7u64),
        amount: Uint::<64>::from(42u64),
    };
    // record(&mut self, ...) requires &mut state — but the transcript
    // builder for circuits without reads doesn't take state, so we
    // construct the transcript first and then can mutate state if we
    // want (we don't need to here).
    let nocturne_transcript = records::transcript::build_record_transcript(&witnesses);
    let _ = &mut state; // silence unused warning

    // PrivateInput reads in IR order: user_id, then amount.
    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> = vec![
        midnight::runtime::base_crypto::fab::AlignedValue::from(7u64),
        midnight::runtime::base_crypto::fab::AlignedValue::from(42u64),
    ];
    let preimage = canonical_preimage("record", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for Map::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map::insert");
}

/// Confirms `Map<Uint<64>, Uint<64>>::remove(&k)` produces an on-chain
/// compatible transcript: Idx + Push(key) + Rem + Ins matches between IR
/// and runtime ops, proof constructs through `ContractCallExt::construct_proof`,
/// verifier accepts ledger-shape PIs. No Popeq since remove returns no value
/// at the circuit level (Option<V> plumbing waits for Stage 2 / Map::get).
#[tokio::test]
async fn map_remove_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_erase_ir();
    let witnesses = records::RecordsWitnesses {
        user_id: Uint::<64>::from(7u64),
        amount: Uint::<64>::from(42u64),
    };
    let nocturne_transcript = records::transcript::build_erase_transcript(&witnesses);

    // PrivateInput reads only `user_id` for erase. The `amount` witness is
    // never accessed by the circuit, so it's not in the private transcript.
    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> =
        vec![midnight::runtime::base_crypto::fab::AlignedValue::from(
            7u64,
        )];
    let preimage = canonical_preimage("erase", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for Map::remove"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map::remove");
}

/// Confirms `Cell<u64>::get()` produces an on-chain compatible transcript.
/// The full 4-declare Popeq pattern (matches Map::contains' Popeq):
///   Popeq{cached:true, result: AlignedValue<u64>} → [0x0d, 1, 8, value]
///
/// This is the read-path fix — emit_ledger_read previously emitted only the
/// opcode declare, which left the alignment + value out of the IR PIs and
/// made the on-chain verify hash diverge.
#[tokio::test]
async fn cell_get_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_stored_ir();
    let state = reader::ReaderState::new();
    let nocturne_transcript = reader::transcript::build_read_stored_transcript(&state);

    let preimage = canonical_preimage("read_stored", nocturne_transcript.ops.clone(), vec![]);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for Cell::get"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Cell::get");
}

/// Same as `cell_get_proves_and_verifies` but for `Counter::value() -> u64`.
/// Counter shares the same on-chain representation as `Cell<u64>` (both
/// `StateValue::Cell(AlignedValue<Bytes{8}>)`), so the Popeq shape is
/// identical.
#[tokio::test]
async fn counter_value_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_count_ir();
    let state = counter_reader::CounterReaderState::new();
    let nocturne_transcript = counter_reader::transcript::build_read_count_transcript(&state);

    let preimage = canonical_preimage("read_count", nocturne_transcript.ops.clone(), vec![]);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for Counter::value"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Counter::value");
}

/// Confirms `Map<Uint<64>, Uint<64>>::lookup(&k) -> V` produces an on-chain
/// compatible transcript: Dup + Idx(field) + Idx(key) + Popeq(V) matches
/// between IR and runtime ops, the Popeq result is computed off-chain from
/// the populated state, and the proof verifies through the canonical ledger
/// path. Mirrors compactc 0.30.0's `lookup` emission.
///
/// `lookup` is assert-exists, so the test pre-populates the Map before
/// building the transcript. A missing key would fail at construct_proof
/// time when the IR's Popeq verify mismatched the on-chain Null vs. the
/// claimed value.
#[tokio::test]
async fn map_lookup_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_fetch_ir();
    let mut state = records::RecordsState::new();
    // Pre-populate so lookup finds the key.
    state
        .records
        .insert(Uint::<64>::from(7u64), Uint::<64>::from(42u64));

    let witnesses = records::RecordsWitnesses {
        user_id: Uint::<64>::from(7u64),
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript = records::transcript::build_fetch_transcript(&state, &witnesses);

    // PrivateInput reads only `user_id` for fetch.
    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> =
        vec![midnight::runtime::base_crypto::fab::AlignedValue::from(
            7u64,
        )];
    let preimage = canonical_preimage("fetch", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for Map::lookup"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map::lookup");
}

/// Confirms a `Bytes<32>` witness round-trips through prove+verify. The
/// witness expands to two `PrivateInput`s in the IR (the high byte at
/// 8 bits and the low 31-byte chunk at 248 bits), and the transcript
/// builder pushes both via `AlignedValueExt::value_only_field_repr` so
/// the order matches. The circuit body itself only uses Counter so we
/// don't have to thread the Bytes<32> through a Push yet (Cell<Bytes<N>>
/// is the next milestone).
#[tokio::test]
async fn bytes32_witness_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_take_digest_ir();
    let witnesses = bytes_witness::BytesWitnessWitnesses {
        digest: Bytes::<32>::from([0xABu8; 32]),
    };
    let nocturne_transcript = bytes_witness::transcript::build_take_digest_transcript(&witnesses);

    // The witness expands to ceil(32/31) = 2 Frs. Passing the [u8; 32] as
    // a single AlignedValue tells construct_proof to use the same
    // chunk-and-reverse encoding the IR's PrivateInputs expect.
    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> =
        vec![midnight::runtime::base_crypto::fab::AlignedValue::from(
            [0xABu8; 32],
        )];
    let preimage = canonical_preimage(
        "take_digest",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, _skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for the Bytes<32>-witness circuit"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for the Bytes<32>-witness circuit");
}
