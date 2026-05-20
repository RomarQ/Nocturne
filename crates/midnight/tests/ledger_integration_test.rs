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
mod bytes_cell {
    use super::*;

    #[midnight(ledger)]
    pub struct BytesCellState {
        pub digest: Cell<Bytes<32>>,
    }

    #[midnight(witnesses)]
    pub struct BytesCellWitnesses {
        pub new_digest: Bytes<32>,
    }

    impl BytesCellState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                digest: Cell::new(Bytes::<32>::zeroed()),
            }
        }

        #[midnight(circuit)]
        pub fn rotate_digest(&mut self, witnesses: &BytesCellWitnesses) {
            self.digest.set(witnesses.new_digest.clone());
        }

        #[midnight(circuit)]
        pub fn peek_digest(&self) {
            let _d = self.digest.get();
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
mod byte_records {
    use super::*;

    #[midnight(ledger)]
    pub struct ByteRecordsState {
        pub records: Map<Bytes<32>, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct ByteRecordsWitnesses {
        pub digest: Bytes<32>,
        pub amount: Uint<64>,
    }

    impl ByteRecordsState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &ByteRecordsWitnesses) {
            self.records
                .insert(witnesses.digest.clone(), witnesses.amount);
        }

        #[midnight(circuit)]
        pub fn check_member(&self, witnesses: &ByteRecordsWitnesses) {
            let _exists = self.records.contains(&witnesses.digest);
        }

        #[midnight(circuit)]
        pub fn fetch(&self, witnesses: &ByteRecordsWitnesses) {
            let _v = self.records.lookup(&witnesses.digest);
        }

        #[midnight(circuit)]
        pub fn erase(&mut self, witnesses: &ByteRecordsWitnesses) {
            self.records.remove(&witnesses.digest);
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

fn build_bytes_cell_circuit_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod bytes_cell {
            #[midnight(ledger)]
            pub struct BytesCellState { digest: Cell<Bytes<32>> }
            #[midnight(witnesses)]
            pub struct BytesCellWitnesses { pub new_digest: Bytes<32> }
            impl BytesCellState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { digest: Cell::new(Bytes::<32>::zeroed()) } }
                #[midnight(circuit)]
                pub fn rotate_digest(&mut self, witnesses: &BytesCellWitnesses) {
                    self.digest.set(witnesses.new_digest.clone());
                }
                #[midnight(circuit)]
                pub fn peek_digest(&self) {
                    let _d = self.digest.get();
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

fn build_rotate_digest_ir() -> midnight_zkir::IrSource {
    build_bytes_cell_circuit_ir("rotate_digest")
}

fn build_peek_digest_ir() -> midnight_zkir::IrSource {
    build_bytes_cell_circuit_ir("peek_digest")
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

fn build_byte_records_circuit_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod byte_records {
            #[midnight(ledger)]
            pub struct ByteRecordsState { records: Map<Bytes<32>, Uint<64>> }
            #[midnight(witnesses)]
            pub struct ByteRecordsWitnesses { pub digest: Bytes<32>, pub amount: Uint<64> }
            impl ByteRecordsState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &ByteRecordsWitnesses) {
                    self.records.insert(witnesses.digest.clone(), witnesses.amount);
                }
                #[midnight(circuit)]
                pub fn check_member(&self, witnesses: &ByteRecordsWitnesses) {
                    let _exists = self.records.contains(&witnesses.digest);
                }
                #[midnight(circuit)]
                pub fn fetch(&self, witnesses: &ByteRecordsWitnesses) {
                    let _v = self.records.lookup(&witnesses.digest);
                }
                #[midnight(circuit)]
                pub fn erase(&mut self, witnesses: &ByteRecordsWitnesses) {
                    self.records.remove(&witnesses.digest);
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

/// Confirms `Cell<Bytes<32>>::set(v)` produces an on-chain compatible
/// transcript: the value Push declares 2 Fr chunks per the Bytes<32>
/// alignment, matching what the transcript runtime computes via
/// `AlignedValue::from(*v.as_bytes())`.
///
/// Validates multi-Fr Phase B: emit_push_cell now takes the full chunked
/// `value_vars` and emits one DeclarePubInput per Fr the value occupies.
#[tokio::test]
async fn cell_bytes32_set_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_rotate_digest_ir();
    let witnesses = bytes_cell::BytesCellWitnesses {
        new_digest: Bytes::<32>::from([0x77u8; 32]),
    };
    let nocturne_transcript = bytes_cell::transcript::build_rotate_digest_transcript(&witnesses);

    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> =
        vec![midnight::runtime::base_crypto::fab::AlignedValue::from(
            [0x77u8; 32],
        )];
    let preimage = canonical_preimage(
        "rotate_digest",
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
        "prove's PIs must match the on-chain ledger-shape PIs for Cell<Bytes<32>>::set"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Cell<Bytes<32>>::set");
}

/// Confirms `Cell<Bytes<32>>::get()` produces an on-chain compatible
/// transcript: the Popeq emits the full multi-Fr result encoding
/// `[0x0d, 1, 32, fr_high, fr_low]`. The state's stored Bytes<32> is
/// seeded via `Cell::set` off-chain and the transcript builder reads it
/// back through `state.digest.get()` for the Popeq result.
#[tokio::test]
async fn cell_bytes32_get_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_peek_digest_ir();
    let mut state = bytes_cell::BytesCellState::new();
    // Seed the Cell so the read returns a non-trivial value.
    state.digest.set(Bytes::<32>::from([0xCDu8; 32]));
    let nocturne_transcript = bytes_cell::transcript::build_peek_digest_transcript(&state);

    // No witnesses — the read result comes back through
    // public_transcript_outputs, populated automatically from each
    // Op::Popeq's `result` by construct_proof.
    let preimage = canonical_preimage("peek_digest", nocturne_transcript.ops.clone(), vec![]);

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
        "prove's PIs must match the on-chain ledger-shape PIs for Cell<Bytes<32>>::get"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Cell<Bytes<32>>::get");
}

/// Confirms `Map<Bytes<32>, Uint<64>>::insert(k, v)` produces an on-chain
/// compatible transcript with a *multi-Fr key*: the key Push declares 2 Fr
/// chunks per the Bytes<32> alignment, and the value Push declares 1 Fr
/// per Uint<64>. Matches compactc 0.30.0's reference Map<Bytes<32>,
/// Uint<64>> example. This is the multi-Fr K end-to-end test.
#[tokio::test]
async fn map_bytes_insert_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_byte_records_circuit_ir("record");
    let witnesses = byte_records::ByteRecordsWitnesses {
        digest: Bytes::<32>::from([0x5Au8; 32]),
        amount: Uint::<64>::from(99u64),
    };
    let nocturne_transcript = byte_records::transcript::build_record_transcript(&witnesses);

    // Witnesses in IR-emission order: digest (2 Frs), then amount (1 Fr).
    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> = vec![
        midnight::runtime::base_crypto::fab::AlignedValue::from([0x5Au8; 32]),
        midnight::runtime::base_crypto::fab::AlignedValue::from(99u64),
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
        "prove's PIs must match the on-chain ledger-shape PIs for Map<Bytes<32>, Uint<64>>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<32>, Uint<64>>::insert");
}

/// Confirms `Map<Bytes<32>, Uint<64>>::contains(&k)` produces an on-chain
/// compatible transcript with a multi-Fr key: Push declares 2 Fr chunks for
/// the Bytes<32> key. Map is empty, so the Member result is false.
#[tokio::test]
async fn map_bytes_contains_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_byte_records_circuit_ir("check_member");
    let state = byte_records::ByteRecordsState::new();
    let witnesses = byte_records::ByteRecordsWitnesses {
        digest: Bytes::<32>::from([0x33u8; 32]),
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript =
        byte_records::transcript::build_check_member_transcript(&state, &witnesses);

    // Only the `digest` witness is referenced by check_member, so the
    // private transcript contains exactly its 2 Frs.
    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> =
        vec![midnight::runtime::base_crypto::fab::AlignedValue::from(
            [0x33u8; 32],
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
        "prove's PIs must match the on-chain ledger-shape PIs for Map<Bytes<32>, _>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<32>, _>::contains");
}

/// Confirms `Map<Bytes<32>, Uint<64>>::lookup(&k) -> V` produces an
/// on-chain compatible transcript with a multi-Fr key in the Idx path.
/// State is pre-populated, so lookup returns the stored value.
#[tokio::test]
async fn map_bytes_lookup_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_byte_records_circuit_ir("fetch");
    let mut state = byte_records::ByteRecordsState::new();
    let key = Bytes::<32>::from([0x7Eu8; 32]);
    state.records.insert(key.clone(), Uint::<64>::from(1234u64));

    let witnesses = byte_records::ByteRecordsWitnesses {
        digest: key,
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript = byte_records::transcript::build_fetch_transcript(&state, &witnesses);

    // Only `digest` is accessed by `fetch`.
    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> =
        vec![midnight::runtime::base_crypto::fab::AlignedValue::from(
            [0x7Eu8; 32],
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
        "prove's PIs must match the on-chain ledger-shape PIs for Map<Bytes<32>, _>::lookup"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<32>, _>::lookup");
}

/// Confirms `Map<Bytes<32>, Uint<64>>::remove(&k)` produces an on-chain
/// compatible transcript with a multi-Fr key in the Push path.
#[tokio::test]
async fn map_bytes_remove_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_byte_records_circuit_ir("erase");
    let witnesses = byte_records::ByteRecordsWitnesses {
        digest: Bytes::<32>::from([0xC3u8; 32]),
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript = byte_records::transcript::build_erase_transcript(&witnesses);

    let private_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue> =
        vec![midnight::runtime::base_crypto::fab::AlignedValue::from(
            [0xC3u8; 32],
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
        "prove's PIs must match the on-chain ledger-shape PIs for Map<Bytes<32>, _>::remove"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<32>, _>::remove");
}

/// Mirror of `voting_verifies_with_ledger_shape_pis` but with `choice=false`
/// — exercises the **else-active** path of the cast_vote conditional. With
/// cond_select zeroing, the then-branch's DeclarePubInputs should be zero
/// and match the Op::Noop padding the ledger inserts for the inactive
/// (then) branch.
#[tokio::test]
async fn voting_verifies_else_active() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_cast_vote_ir();
    let witnesses = ballot::BallotWitnesses {
        choice: Boolean::from(false),
    };
    let nocturne_transcript = ballot::transcript::build_cast_vote_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(false)];
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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for the else-active path"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for the else-active path");
}

#[midnight::contract]
mod cond_writer {
    use super::*;

    #[midnight(ledger)]
    pub struct CondWriterState {
        pub raised: Cell<bool>,
    }

    #[midnight(witnesses)]
    pub struct CondWriterWitnesses {
        pub do_it: Boolean,
    }

    impl CondWriterState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                raised: Cell::new(false),
            }
        }

        // Conditional write — only one branch's Cell::set ops are in the
        // active transcript; the other branch's IR-declared PIs must zero out
        // via cond_select to match Op::Noop padding.
        #[midnight(circuit)]
        pub fn maybe_raise(&mut self, witnesses: &CondWriterWitnesses) {
            if witnesses.do_it.value() {
                self.raised.set(true);
            } else {
                self.raised.set(false);
            }
        }
    }
}

fn build_maybe_raise_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod cond_writer {
            #[midnight(ledger)]
            pub struct CondWriterState { raised: Cell<bool> }
            #[midnight(witnesses)]
            pub struct CondWriterWitnesses { pub do_it: Boolean }
            impl CondWriterState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { raised: Cell::new(false) } }
                #[midnight(circuit)]
                pub fn maybe_raise(&mut self, witnesses: &CondWriterWitnesses) {
                    if witnesses.do_it.value() {
                        self.raised.set(true);
                    } else {
                        self.raised.set(false);
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
        .find(|c| c.circuit_name == "maybe_raise")
        .unwrap()
        .ir_source
}

/// Confirms a circuit with `Cell::set` inside both arms of an `if-else`
/// proves+verifies through the canonical ledger path. The active branch's
/// Push+Push+Ins ops go into the transcript; the inactive branch's
/// DeclarePubInputs must cond_select to zero to match the Op::Noop padding
/// the ledger inserts for inactive segments.
#[tokio::test]
async fn conditional_cell_set_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_maybe_raise_ir();
    let witnesses = cond_writer::CondWriterWitnesses {
        do_it: Boolean::from(true),
    };
    let nocturne_transcript = cond_writer::transcript::build_maybe_raise_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(true)];
    let preimage = canonical_preimage(
        "maybe_raise",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for conditional Cell::set"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for conditional Cell::set");
}

#[midnight::contract]
mod nested_cond {
    use super::*;

    #[midnight(ledger)]
    pub struct NestedCondState {
        pub a: Counter,
        pub b: Counter,
        pub c: Counter,
    }

    #[midnight(witnesses)]
    pub struct NestedCondWitnesses {
        pub outer: Boolean,
        pub inner: Boolean,
    }

    impl NestedCondState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                a: Counter::zero(),
                b: Counter::zero(),
                c: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn tick(&mut self, witnesses: &NestedCondWitnesses) {
            if witnesses.outer.value() {
                if witnesses.inner.value() {
                    self.a.increment();
                } else {
                    self.b.increment();
                }
            } else {
                self.c.increment();
            }
        }
    }
}

fn build_tick_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod nested_cond {
            #[midnight(ledger)]
            pub struct NestedCondState { a: Counter, b: Counter, c: Counter }
            #[midnight(witnesses)]
            pub struct NestedCondWitnesses { pub outer: Boolean, pub inner: Boolean }
            impl NestedCondState {
                #[midnight(constructor)]
                pub fn new() -> Self {
                    Self { a: Counter::zero(), b: Counter::zero(), c: Counter::zero() }
                }
                #[midnight(circuit)]
                pub fn tick(&mut self, witnesses: &NestedCondWitnesses) {
                    if witnesses.outer.value() {
                        if witnesses.inner.value() {
                            self.a.increment();
                        } else {
                            self.b.increment();
                        }
                    } else {
                        self.c.increment();
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
        .find(|c| c.circuit_name == "tick")
        .unwrap()
        .ir_source
}

/// Nested `if-else`: outer guard composes with inner via cond_select
/// (see `conditional-branch-cond-select-zeroing.md`). Exercise the deepest
/// path (outer=true, inner=true) and verify the prove PIs match the
/// Noop-interleaved transcript field_repr.
#[tokio::test]
async fn nested_conditional_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_tick_ir();
    let witnesses = nested_cond::NestedCondWitnesses {
        outer: Boolean::from(true),
        inner: Boolean::from(true),
    };
    let nocturne_transcript = nested_cond::transcript::build_tick_transcript(&witnesses);

    // IR PrivateInput order matches witness-access order in the body:
    // outer first (the outer guard), then inner.
    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(true), AlignedValue::from(true)];
    let preimage = canonical_preimage("tick", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for nested if-else"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for nested if-else");
}

#[midnight::contract]
mod no_else {
    use super::*;

    #[midnight(ledger)]
    pub struct NoElseState {
        pub count: Counter,
    }

    #[midnight(witnesses)]
    pub struct NoElseWitnesses {
        pub do_it: Boolean,
    }

    impl NoElseState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn maybe_tick(&mut self, witnesses: &NoElseWitnesses) {
            if witnesses.do_it.value() {
                self.count.increment();
            }
        }
    }
}

fn build_maybe_tick_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod no_else {
            #[midnight(ledger)]
            pub struct NoElseState { count: Counter }
            #[midnight(witnesses)]
            pub struct NoElseWitnesses { pub do_it: Boolean }
            impl NoElseState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn maybe_tick(&mut self, witnesses: &NoElseWitnesses) {
                    if witnesses.do_it.value() {
                        self.count.increment();
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
        .find(|c| c.circuit_name == "maybe_tick")
        .unwrap()
        .ir_source
}

/// No-else `if`: only the then-branch emits DeclarePubInputs. When the
/// condition is false, no ops go into the transcript but the IR's
/// DeclarePubInputs still execute — they must cond_select to zero so the
/// Op::Noop padding the ledger inserts matches.
#[tokio::test]
async fn no_else_conditional_false_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_maybe_tick_ir();
    let witnesses = no_else::NoElseWitnesses {
        do_it: Boolean::from(false),
    };
    let nocturne_transcript = no_else::transcript::build_maybe_tick_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(false)];
    let preimage = canonical_preimage(
        "maybe_tick",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for no-else conditional (false)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for no-else conditional (false)");
}

#[midnight::contract]
mod cond_read {
    use super::*;

    #[midnight(ledger)]
    pub struct CondReadState {
        pub members: Map<Uint<64>, Boolean>,
    }

    #[midnight(witnesses)]
    pub struct CondReadWitnesses {
        pub do_check: Boolean,
        pub user_id: Uint<64>,
    }

    impl CondReadState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                members: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn maybe_check(&self, witnesses: &CondReadWitnesses) {
            if witnesses.do_check.value() {
                let _exists = self.members.contains(&witnesses.user_id);
            }
        }
    }
}

fn build_maybe_check_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod cond_read {
            #[midnight(ledger)]
            pub struct CondReadState { members: Map<Uint<64>, Boolean> }
            #[midnight(witnesses)]
            pub struct CondReadWitnesses { pub do_check: Boolean, pub user_id: Uint<64> }
            impl CondReadState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { members: Map::empty() } }
                #[midnight(circuit)]
                pub fn maybe_check(&self, witnesses: &CondReadWitnesses) {
                    if witnesses.do_check.value() {
                        let _exists = self.members.contains(&witnesses.user_id);
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
        .find(|c| c.circuit_name == "maybe_check")
        .unwrap()
        .ir_source
}

/// Conditional Map::contains — the IR emits a PublicInput inside the
/// conditional branch (to read the Member result). When the branch is
/// inactive, the transcript builder omits the Op::Popeq, so the prover's
/// public_transcript_outputs vector has one fewer entry than there are
/// PublicInput ops in the IR. This test exercises the active-branch case
/// (do_check=true) to confirm the basic structure proves and verifies.
#[tokio::test]
async fn conditional_map_contains_active_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_maybe_check_ir();
    let state = cond_read::CondReadState::new();
    let witnesses = cond_read::CondReadWitnesses {
        do_check: Boolean::from(true),
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        cond_read::transcript::build_maybe_check_transcript(&state, &witnesses);

    // do_check first, user_id second — IR-emission order.
    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(true), AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "maybe_check",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for conditional Map::contains (active)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for conditional Map::contains (active)");
}

/// Inactive-branch version of `conditional_map_contains_active`. The IR
/// emits a PublicInput inside the conditional branch (for the Map::contains
/// result), but the transcript builder omits the entire Popeq op when the
/// branch is inactive. This puts the IR's PublicInput count > the
/// transcript's Popeq count — and tests whether prove handles that mismatch
/// or fails.
#[tokio::test]
async fn conditional_map_contains_inactive_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_maybe_check_ir();
    let state = cond_read::CondReadState::new();
    let witnesses = cond_read::CondReadWitnesses {
        do_check: Boolean::from(false),
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        cond_read::transcript::build_maybe_check_transcript(&state, &witnesses);

    // do_check=false → the user_id witness read is gated behind the
    // inactive branch, so its `PrivateInput` consumes nothing (guard=0
    // path in `zkir/src/ir_vm.rs:343`). Only the do_check Fr lands in
    // private_transcript.
    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(false)];
    let preimage = canonical_preimage(
        "maybe_check",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for conditional Map::contains (inactive)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for conditional Map::contains (inactive)");
}

#[midnight::contract]
mod safe_lookup {
    use super::*;

    #[midnight(ledger)]
    pub struct SafeLookupState {
        pub records: Map<Uint<64>, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct SafeLookupWitnesses {
        pub user_id: Uint<64>,
    }

    impl SafeLookupState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        // The canonical `Map::get` expansion: contains-then-lookup. Lookup
        // is gated by the contains result so a missing key never trips the
        // `Popeq.as_cell()` panic on `StateValue::Null`. This is the IR
        // shape that any `Option<V>`-returning `Map::get` sugar will compile
        // to. Tests both branches (present + absent).
        #[midnight(circuit)]
        pub fn safe_get(&self, witnesses: &SafeLookupWitnesses) {
            if self.records.contains(&witnesses.user_id) {
                let _v = self.records.lookup(&witnesses.user_id);
            }
        }
    }
}

fn build_safe_get_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod safe_lookup {
            #[midnight(ledger)]
            pub struct SafeLookupState { records: Map<Uint<64>, Uint<64>> }
            #[midnight(witnesses)]
            pub struct SafeLookupWitnesses { pub user_id: Uint<64> }
            impl SafeLookupState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn safe_get(&self, witnesses: &SafeLookupWitnesses) {
                    if self.records.contains(&witnesses.user_id) {
                        let _v = self.records.lookup(&witnesses.user_id);
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
        .find(|c| c.circuit_name == "safe_get")
        .unwrap()
        .ir_source
}

/// The canonical `Map::get` expansion shape: contains-then-lookup. With
/// the key present in the state, the contains branch is active, the
/// lookup's Popeq value is the stored V, and the proof verifies on-chain.
#[tokio::test]
async fn safe_get_present_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_safe_get_ir();
    let mut state = safe_lookup::SafeLookupState::new();
    state
        .records
        .insert(Uint::<64>::from(7u64), Uint::<64>::from(42u64));
    let witnesses = safe_lookup::SafeLookupWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        safe_lookup::transcript::build_safe_get_transcript(&state, &witnesses);

    // user_id is accessed by both `contains` (in the condition) and
    // `lookup` (inside the branch). The IR caches the WitnessAccess after
    // its first emission (the contains call) — so there's only one
    // PrivateInput for user_id total. Active branch consumes it.
    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "safe_get",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for safe-get (key present)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for safe-get (key present)");
}

/// Safe-get with the key absent: contains returns false, the conditional
/// lookup branch is inactive, and the inactive-branch Popeq's PublicInput
/// does not consume from public_transcript_outputs (guard=0). Proof
/// constructs and verifies through the canonical ledger path.
#[tokio::test]
async fn safe_get_absent_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_safe_get_ir();
    let state = safe_lookup::SafeLookupState::new(); // empty
    let witnesses = safe_lookup::SafeLookupWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        safe_lookup::transcript::build_safe_get_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "safe_get",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for safe-get (key absent)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for safe-get (key absent)");
}

#[midnight::contract]
mod map_get_sugar {
    use super::*;

    #[midnight(ledger)]
    pub struct MapGetSugarState {
        pub records: Map<Uint<64>, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct MapGetSugarWitnesses {
        pub user_id: Uint<64>,
    }

    impl MapGetSugarState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        // Idiomatic Rust `if let Some(v) = map.get(&k)`. The parser rewrites
        // this to the contains+lookup pattern at the IR level. The user's
        // source still type-checks against `Map::get -> Option<V>` because
        // the storage layer keeps the HashMap-style API.
        #[midnight(circuit)]
        pub fn read_if_present(&self, witnesses: &MapGetSugarWitnesses) {
            if let Some(_v) = self.records.get(&witnesses.user_id) {
                let _hold = _v;
            }
        }
    }
}

fn build_read_if_present_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod map_get_sugar {
            #[midnight(ledger)]
            pub struct MapGetSugarState { records: Map<Uint<64>, Uint<64>> }
            #[midnight(witnesses)]
            pub struct MapGetSugarWitnesses { pub user_id: Uint<64> }
            impl MapGetSugarState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn read_if_present(&self, witnesses: &MapGetSugarWitnesses) {
                    if let Some(_v) = self.records.get(&witnesses.user_id) {
                        let _hold = _v;
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
        .find(|c| c.circuit_name == "read_if_present")
        .unwrap()
        .ir_source
}

/// `Map::get -> Option<V>` syntactic sugar. The user writes
/// `if let Some(v) = self.map.get(&k) { use v }`; the parser rewrites it
/// to `if self.map.contains(&k) { let v = self.map.lookup(&k); use v }`,
/// which is the canonical on-chain shape (contains + conditional lookup).
/// Key present → both contains and lookup fire on the active path.
#[tokio::test]
async fn map_get_sugar_present_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_if_present_ir();
    let mut state = map_get_sugar::MapGetSugarState::new();
    state
        .records
        .insert(Uint::<64>::from(7u64), Uint::<64>::from(42u64));
    let witnesses = map_get_sugar::MapGetSugarWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        map_get_sugar::transcript::build_read_if_present_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "read_if_present",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for `if let Some(v) = map.get(&k)` (present)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for `if let Some(v) = map.get(&k)` (present)");
}

/// `Map::get` sugar, key absent: contains returns false, the conditional
/// lookup branch is inactive, no PrivateInput/PublicInput consumption.
#[tokio::test]
async fn map_get_sugar_absent_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_if_present_ir();
    let state = map_get_sugar::MapGetSugarState::new(); // empty
    let witnesses = map_get_sugar::MapGetSugarWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        map_get_sugar::transcript::build_read_if_present_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "read_if_present",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for `if let Some(v) = map.get(&k)` (absent)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for `if let Some(v) = map.get(&k)` (absent)");
}

#[midnight::contract]
mod if_let_else {
    use super::*;

    #[midnight(ledger)]
    pub struct IfLetElseState {
        pub records: Map<Uint<64>, Uint<64>>,
        pub fallback_hits: Counter,
    }

    #[midnight(witnesses)]
    pub struct IfLetElseWitnesses {
        pub user_id: Uint<64>,
    }

    impl IfLetElseState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
                fallback_hits: Counter::zero(),
            }
        }

        // `if let Some(v) = ... { ... } else { ... }`. The else branch
        // increments a counter when the key is absent — exercises both
        // arms of the rewrite (then = lookup, else = preserved verbatim).
        #[midnight(circuit)]
        pub fn read_or_count_miss(&mut self, witnesses: &IfLetElseWitnesses) {
            if let Some(_v) = self.records.get(&witnesses.user_id) {
                let _hold = _v;
            } else {
                self.fallback_hits.increment();
            }
        }
    }
}

fn build_read_or_count_miss_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod if_let_else {
            #[midnight(ledger)]
            pub struct IfLetElseState {
                records: Map<Uint<64>, Uint<64>>,
                fallback_hits: Counter,
            }
            #[midnight(witnesses)]
            pub struct IfLetElseWitnesses { pub user_id: Uint<64> }
            impl IfLetElseState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty(), fallback_hits: Counter::zero() } }
                #[midnight(circuit)]
                pub fn read_or_count_miss(&mut self, witnesses: &IfLetElseWitnesses) {
                    if let Some(_v) = self.records.get(&witnesses.user_id) {
                        let _hold = _v;
                    } else {
                        self.fallback_hits.increment();
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
        .find(|c| c.circuit_name == "read_or_count_miss")
        .unwrap()
        .ir_source
}

/// `if let Some(v) = self.map.get(&k) { ... } else { ... }` — exercises
/// the else branch of the Map::get sugar. Key absent → counter increment
/// runs; the lookup branch is inactive (no Popeq consumption).
#[tokio::test]
async fn if_let_else_absent_runs_else_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_or_count_miss_ir();
    let state = if_let_else::IfLetElseState::new(); // empty
    let witnesses = if_let_else::IfLetElseWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        if_let_else::transcript::build_read_or_count_miss_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "read_or_count_miss",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for if-let-Some-with-else (else-active)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for if-let-Some-with-else (else-active)");
}

#[midnight::contract]
mod match_get {
    use super::*;

    #[midnight(ledger)]
    pub struct MatchGetState {
        pub records: Map<Uint<64>, Uint<64>>,
        pub fallback_hits: Counter,
    }

    #[midnight(witnesses)]
    pub struct MatchGetWitnesses {
        pub user_id: Uint<64>,
    }

    impl MatchGetState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
                fallback_hits: Counter::zero(),
            }
        }

        // `match self.map.get(&k) { Some(v) => ..., None => ... }`. The
        // parser rewrites to the same contains+lookup if-else the if-let
        // sugar produces.
        #[midnight(circuit)]
        pub fn pick(&mut self, witnesses: &MatchGetWitnesses) {
            match self.records.get(&witnesses.user_id) {
                Some(_v) => {
                    let _hold = _v;
                }
                None => {
                    self.fallback_hits.increment();
                }
            }
        }
    }
}

fn build_pick_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod match_get {
            #[midnight(ledger)]
            pub struct MatchGetState {
                records: Map<Uint<64>, Uint<64>>,
                fallback_hits: Counter,
            }
            #[midnight(witnesses)]
            pub struct MatchGetWitnesses { pub user_id: Uint<64> }
            impl MatchGetState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty(), fallback_hits: Counter::zero() } }
                #[midnight(circuit)]
                pub fn pick(&mut self, witnesses: &MatchGetWitnesses) {
                    match self.records.get(&witnesses.user_id) {
                        Some(_v) => { let _hold = _v; }
                        None => { self.fallback_hits.increment(); }
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
        .find(|c| c.circuit_name == "pick")
        .unwrap()
        .ir_source
}

/// `match self.map.get(&k) { Some(v) => ..., None => ... }` rewrites to
/// the contains+lookup if-else, same shape as the if-let-Some sugar. Key
/// present → Some arm fires; lookup runs.
#[tokio::test]
async fn match_get_present_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_pick_ir();
    let mut state = match_get::MatchGetState::new();
    state
        .records
        .insert(Uint::<64>::from(7u64), Uint::<64>::from(42u64));
    let witnesses = match_get::MatchGetWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript = match_get::transcript::build_pick_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "pick",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for `match map.get(&k) {{ Some, None }}` (present)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for `match map.get(&k) { Some, None }` (present)");
}

/// `match self.map.get(&k)` — None arm fires, fallback counter increments.
#[tokio::test]
async fn match_get_absent_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_pick_ir();
    let state = match_get::MatchGetState::new(); // empty
    let witnesses = match_get::MatchGetWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript = match_get::transcript::build_pick_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "pick",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for `match map.get(&k) {{ Some, None }}` (absent)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for `match map.get(&k) { Some, None }` (absent)");
}

#[midnight::contract]
mod match_get_reversed {
    use super::*;

    #[midnight(ledger)]
    pub struct MatchGetReversedState {
        pub records: Map<Uint<64>, Uint<64>>,
        pub fallback_hits: Counter,
    }

    #[midnight(witnesses)]
    pub struct MatchGetReversedWitnesses {
        pub user_id: Uint<64>,
    }

    impl MatchGetReversedState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
                fallback_hits: Counter::zero(),
            }
        }

        // Arms in reverse order — None first, Some second. The match
        // matcher accepts both orderings.
        #[midnight(circuit)]
        pub fn pick_reversed(&mut self, witnesses: &MatchGetReversedWitnesses) {
            match self.records.get(&witnesses.user_id) {
                None => {
                    self.fallback_hits.increment();
                }
                Some(_v) => {
                    let _hold = _v;
                }
            }
        }
    }
}

fn build_pick_reversed_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod match_get_reversed {
            #[midnight(ledger)]
            pub struct MatchGetReversedState {
                records: Map<Uint<64>, Uint<64>>,
                fallback_hits: Counter,
            }
            #[midnight(witnesses)]
            pub struct MatchGetReversedWitnesses { pub user_id: Uint<64> }
            impl MatchGetReversedState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty(), fallback_hits: Counter::zero() } }
                #[midnight(circuit)]
                pub fn pick_reversed(&mut self, witnesses: &MatchGetReversedWitnesses) {
                    match self.records.get(&witnesses.user_id) {
                        None => { self.fallback_hits.increment(); }
                        Some(_v) => { let _hold = _v; }
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
        .find(|c| c.circuit_name == "pick_reversed")
        .unwrap()
        .ir_source
}

/// Reverse arm order (None first, Some second). The match matcher
/// normalizes ordering so both shapes lower to the same IR.
#[tokio::test]
async fn match_get_reversed_arms_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_pick_reversed_ir();
    let mut state = match_get_reversed::MatchGetReversedState::new();
    state
        .records
        .insert(Uint::<64>::from(7u64), Uint::<64>::from(42u64));
    let witnesses = match_get_reversed::MatchGetReversedWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        match_get_reversed::transcript::build_pick_reversed_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "pick_reversed",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for `match` with reversed arms"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for `match` with reversed arms");
}

#[midnight::contract]
mod bytes_get_sugar {
    use super::*;

    #[midnight(ledger)]
    pub struct BytesGetSugarState {
        pub records: Map<Bytes<32>, Uint<64>>,
        pub fallback_hits: Counter,
    }

    #[midnight(witnesses)]
    pub struct BytesGetSugarWitnesses {
        pub digest: Bytes<32>,
    }

    impl BytesGetSugarState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
                fallback_hits: Counter::zero(),
            }
        }

        // Multi-Fr K (`Bytes<32>` = 2 Frs) flowing through the Map::get
        // sugar — exercises the if-let-Some rewrite alongside the multi-Fr
        // contains+lookup paths.
        #[midnight(circuit)]
        pub fn read_digest(&mut self, witnesses: &BytesGetSugarWitnesses) {
            if let Some(_v) = self.records.get(&witnesses.digest) {
                let _hold = _v;
            } else {
                self.fallback_hits.increment();
            }
        }
    }
}

fn build_read_digest_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod bytes_get_sugar {
            #[midnight(ledger)]
            pub struct BytesGetSugarState {
                records: Map<Bytes<32>, Uint<64>>,
                fallback_hits: Counter,
            }
            #[midnight(witnesses)]
            pub struct BytesGetSugarWitnesses { pub digest: Bytes<32> }
            impl BytesGetSugarState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty(), fallback_hits: Counter::zero() } }
                #[midnight(circuit)]
                pub fn read_digest(&mut self, witnesses: &BytesGetSugarWitnesses) {
                    if let Some(_v) = self.records.get(&witnesses.digest) {
                        let _hold = _v;
                    } else {
                        self.fallback_hits.increment();
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
        .find(|c| c.circuit_name == "read_digest")
        .unwrap()
        .ir_source
}

/// `if let Some(v) = self.map.get(&bytes32_key)` over `Map<Bytes<32>,
/// Uint<64>>` — composes multi-Fr K (2 Frs per key) with the Map::get
/// sugar. Key present case: contains+lookup both fire; the second `Idx`
/// in lookup walks 2 Fr key chunks.
#[tokio::test]
async fn bytes_get_sugar_present_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_digest_ir();
    let mut state = bytes_get_sugar::BytesGetSugarState::new();
    let digest = Bytes::<32>::from([0xA1u8; 32]);
    state.records.insert(digest.clone(), Uint::<64>::from(99u64));
    let witnesses = bytes_get_sugar::BytesGetSugarWitnesses { digest };
    let nocturne_transcript =
        bytes_get_sugar::transcript::build_read_digest_transcript(&state, &witnesses);

    // Bytes<32> witness expands to 2 Frs in the private transcript.
    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from([0xA1u8; 32])];
    let preimage = canonical_preimage(
        "read_digest",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for Map<Bytes<32>, _>::get sugar (present)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<32>, _>::get sugar (present)");
}

/// Same as `bytes_get_sugar_present` but with the key absent — the
/// inactive lookup branch's multi-Fr key Push and multi-Fr Popeq result
/// must all guard out without consuming.
#[tokio::test]
async fn bytes_get_sugar_absent_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_digest_ir();
    let state = bytes_get_sugar::BytesGetSugarState::new(); // empty
    let witnesses = bytes_get_sugar::BytesGetSugarWitnesses {
        digest: Bytes::<32>::from([0xB2u8; 32]),
    };
    let nocturne_transcript =
        bytes_get_sugar::transcript::build_read_digest_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from([0xB2u8; 32])];
    let preimage = canonical_preimage(
        "read_digest",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for Map<Bytes<32>, _>::get sugar (absent)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<32>, _>::get sugar (absent)");
}

#[midnight::contract]
mod bytes_v_get_sugar {
    use super::*;

    #[midnight(ledger)]
    pub struct BytesVGetSugarState {
        pub records: Map<Uint<64>, Bytes<32>>,
        pub fallback_hits: Counter,
    }

    #[midnight(witnesses)]
    pub struct BytesVGetSugarWitnesses {
        pub user_id: Uint<64>,
    }

    impl BytesVGetSugarState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
                fallback_hits: Counter::zero(),
            }
        }

        // Multi-Fr V (`Bytes<32>` = 2 Frs in the Popeq result) flowing
        // through the conditional Map::get sugar. The inactive-branch
        // Popeq must guard out both V Fr chunks (each PublicInput carries
        // the branch guard so neither consumes).
        #[midnight(circuit)]
        pub fn read_blob(&mut self, witnesses: &BytesVGetSugarWitnesses) {
            if let Some(_v) = self.records.get(&witnesses.user_id) {
                let _hold = _v;
            } else {
                self.fallback_hits.increment();
            }
        }
    }
}

fn build_read_blob_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod bytes_v_get_sugar {
            #[midnight(ledger)]
            pub struct BytesVGetSugarState {
                records: Map<Uint<64>, Bytes<32>>,
                fallback_hits: Counter,
            }
            #[midnight(witnesses)]
            pub struct BytesVGetSugarWitnesses { pub user_id: Uint<64> }
            impl BytesVGetSugarState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty(), fallback_hits: Counter::zero() } }
                #[midnight(circuit)]
                pub fn read_blob(&mut self, witnesses: &BytesVGetSugarWitnesses) {
                    if let Some(_v) = self.records.get(&witnesses.user_id) {
                        let _hold = _v;
                    } else {
                        self.fallback_hits.increment();
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
        .find(|c| c.circuit_name == "read_blob")
        .unwrap()
        .ir_source
}

/// Map::get sugar with a multi-Fr value (`Bytes<32>` = 2 Frs). Key
/// present → the lookup's multi-Fr Popeq fires on the active branch.
#[tokio::test]
async fn bytes_v_get_sugar_present_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_blob_ir();
    let mut state = bytes_v_get_sugar::BytesVGetSugarState::new();
    state
        .records
        .insert(Uint::<64>::from(7u64), Bytes::<32>::from([0xCDu8; 32]));
    let witnesses = bytes_v_get_sugar::BytesVGetSugarWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        bytes_v_get_sugar::transcript::build_read_blob_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "read_blob",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for Map<_, Bytes<32>>::get sugar (present)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<_, Bytes<32>>::get sugar (present)");
}

/// Multi-Fr V Map::get sugar, key absent — exercises the multi-Fr Popeq
/// guard-out (2 PublicInputs, both inactive).
#[tokio::test]
async fn bytes_v_get_sugar_absent_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_read_blob_ir();
    let state = bytes_v_get_sugar::BytesVGetSugarState::new(); // empty
    let witnesses = bytes_v_get_sugar::BytesVGetSugarWitnesses {
        user_id: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        bytes_v_get_sugar::transcript::build_read_blob_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(7u64)];
    let preimage = canonical_preimage(
        "read_blob",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match on-chain ledger-shape PIs for Map<_, Bytes<32>>::get sugar (absent)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<_, Bytes<32>>::get sugar (absent)");
}

#[midnight::contract]
mod set_contract {
    use super::*;

    #[midnight(ledger)]
    pub struct SetContractState {
        pub members: Set<Bytes<32>>,
    }

    #[midnight(witnesses)]
    pub struct SetContractWitnesses {
        pub digest: Bytes<32>,
    }

    impl SetContractState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                members: Set::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn add(&mut self, witnesses: &SetContractWitnesses) {
            self.members.insert(witnesses.digest.clone());
        }

        #[midnight(circuit)]
        pub fn check(&self, witnesses: &SetContractWitnesses) {
            let _exists = self.members.contains(&witnesses.digest);
        }

        #[midnight(circuit)]
        pub fn erase(&mut self, witnesses: &SetContractWitnesses) {
            self.members.remove(&witnesses.digest);
        }
    }
}

fn build_set_contract_circuit_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod set_contract {
            #[midnight(ledger)]
            pub struct SetContractState { members: Set<Bytes<32>> }
            #[midnight(witnesses)]
            pub struct SetContractWitnesses { pub digest: Bytes<32> }
            impl SetContractState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { members: Set::empty() } }
                #[midnight(circuit)]
                pub fn add(&mut self, witnesses: &SetContractWitnesses) {
                    self.members.insert(witnesses.digest.clone());
                }
                #[midnight(circuit)]
                pub fn check(&self, witnesses: &SetContractWitnesses) {
                    let _exists = self.members.contains(&witnesses.digest);
                }
                #[midnight(circuit)]
                pub fn erase(&mut self, witnesses: &SetContractWitnesses) {
                    self.members.remove(&witnesses.digest);
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

/// `Set<Bytes<32>>::insert(k)` matches compactc 0.22 emission. Unlike
/// `Map::insert`, the value Push is `StateValue::Null` (encoded as
/// `[0x11, 0]` — 2 declares) instead of `Push(Cell(value))`. The full
/// pattern is Idx + Push(Cell(key)) + Push(Null) + Ins + Ins.
#[tokio::test]
async fn set_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_contract_circuit_ir("add");
    let witnesses = set_contract::SetContractWitnesses {
        digest: Bytes::<32>::from([0xA5u8; 32]),
    };
    let nocturne_transcript = set_contract::transcript::build_add_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from([0xA5u8; 32])];
    let preimage = canonical_preimage(
        "add",
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
        "prove's PIs must match on-chain ledger-shape PIs for Set<Bytes<32>>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<Bytes<32>>::insert");
}

/// `Set<Bytes<32>>::contains(&k)`. Same on-chain pattern as `Map::contains`
/// (Member opcode is shared, Set just stores Null values).
#[tokio::test]
async fn set_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_contract_circuit_ir("check");
    let state = set_contract::SetContractState::new();
    let witnesses = set_contract::SetContractWitnesses {
        digest: Bytes::<32>::from([0x55u8; 32]),
    };
    let nocturne_transcript = set_contract::transcript::build_check_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from([0x55u8; 32])];
    let preimage = canonical_preimage(
        "check",
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
        "prove's PIs must match on-chain ledger-shape PIs for Set<Bytes<32>>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<Bytes<32>>::contains");
}

/// `Set<Bytes<32>>::remove(&k)`. Identical to `Map::remove` — Rem + Ins.
#[tokio::test]
async fn set_remove_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_contract_circuit_ir("erase");
    let witnesses = set_contract::SetContractWitnesses {
        digest: Bytes::<32>::from([0xEEu8; 32]),
    };
    let nocturne_transcript = set_contract::transcript::build_erase_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from([0xEEu8; 32])];
    let preimage = canonical_preimage(
        "erase",
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
        "prove's PIs must match on-chain ledger-shape PIs for Set<Bytes<32>>::remove"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<Bytes<32>>::remove");
}

#[midnight::contract]
mod field_cell {
    use super::*;

    #[midnight(ledger)]
    pub struct FieldCellState {
        pub slot: Cell<Field>,
    }

    #[midnight(witnesses)]
    pub struct FieldCellWitnesses {
        pub new_field: Field,
    }

    impl FieldCellState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                slot: Cell::new(Field::zero()),
            }
        }

        #[midnight(circuit)]
        pub fn write_field(&mut self, witnesses: &FieldCellWitnesses) {
            self.slot.set(witnesses.new_field);
        }

        #[midnight(circuit)]
        pub fn read_field(&self) {
            let _v = self.slot.get();
        }
    }
}

fn build_field_cell_circuit_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod field_cell {
            #[midnight(ledger)]
            pub struct FieldCellState { slot: Cell<Field> }
            #[midnight(witnesses)]
            pub struct FieldCellWitnesses { pub new_field: Field }
            impl FieldCellState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { slot: Cell::new(Field::zero()) } }
                #[midnight(circuit)]
                pub fn write_field(&mut self, witnesses: &FieldCellWitnesses) {
                    self.slot.set(witnesses.new_field);
                }
                #[midnight(circuit)]
                pub fn read_field(&self) {
                    let _v = self.slot.get();
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

/// `Cell<Field>::set(v)` — the Push uses `AlignmentAtom::Field` (encoded
/// as `-2` per `transient-crypto/src/fab.rs:605`) instead of `Bytes{N}`,
/// and the value is a single Fr that flows through Fr's Aligned impl on
/// the runtime side. This is the prerequisite alignment for
/// MerkleTree::checkRoot (Phase A of the staged plan).
#[tokio::test]
async fn cell_field_set_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::curve::Fr;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_field_cell_circuit_ir("write_field");
    let witnesses = field_cell::FieldCellWitnesses {
        new_field: Field::from(42u64),
    };
    let nocturne_transcript = field_cell::transcript::build_write_field_transcript(&witnesses);

    // Witness contributes 1 Fr to private_transcript (Field is single-Fr).
    // AlignedValue::from(Fr) builds a Field-aligned AlignedValue whose
    // `value_only_field_repr` flattens to that one Fr.
    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(Fr::from(42u64))];
    let preimage = canonical_preimage(
        "write_field",
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
        "prove's PIs must match on-chain ledger-shape PIs for Cell<Field>::set"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Cell<Field>::set");
}

/// `Cell<Field>::get()` — the Popeq's result is an AlignedValue<Field>
/// whose `value_only_field_repr` is a single Fr (the stored field
/// element). The IR uses `AlignmentAtom::Field` (`-2`) in the Popeq's
/// alignment declares, mirroring the Push side.
#[tokio::test]
async fn cell_field_get_proves_and_verifies() {
    use midnight::runtime::transient_crypto::curve::Fr;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_field_cell_circuit_ir("read_field");
    let mut state = field_cell::FieldCellState::new();
    // Seed the Cell so the read returns a non-trivial Field value.
    state.slot.set(Field::from(0xCAFEu64));
    let nocturne_transcript = field_cell::transcript::build_read_field_transcript(&state);

    let preimage = canonical_preimage("read_field", nocturne_transcript.ops.clone(), vec![]);

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
        "prove's PIs must match on-chain ledger-shape PIs for Cell<Field>::get"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Cell<Field>::get");
}

#[midnight::contract]
mod mt_check {
    use super::*;

    #[midnight(ledger)]
    pub struct MtCheckState {
        pub entries: MerkleTree<10, Bytes<32>>,
    }

    #[midnight(witnesses)]
    pub struct MtCheckWitnesses {
        pub expected_root: MerkleTreeDigest,
    }

    impl MtCheckState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                entries: MerkleTree::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn verify(&self, witnesses: &MtCheckWitnesses) {
            let _ok = self.entries.check_root(&witnesses.expected_root);
        }
    }
}

fn build_mt_verify_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod mt_check {
            #[midnight(ledger)]
            pub struct MtCheckState { entries: MerkleTree<10, Bytes<32>> }
            #[midnight(witnesses)]
            pub struct MtCheckWitnesses { pub expected_root: MerkleTreeDigest }
            impl MtCheckState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { entries: MerkleTree::empty() } }
                #[midnight(circuit)]
                pub fn verify(&self, witnesses: &MtCheckWitnesses) {
                    let _ok = self.entries.check_root(&witnesses.expected_root);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "verify")
        .unwrap()
        .ir_source
}

/// `MerkleTree<10, Bytes<32>>::check_root(&digest)` against an empty
/// tree, with the user-supplied digest equal to the actual empty-tree
/// root — Member result is `true`. Exercises the full 7-op encoding
/// (Dup + Idx + Idx + Root + Push(Cell(Field)) + Eq + Popeq) and the
/// Phase A `AlignmentAtom::Field` work the user-digest Push depends on.
#[tokio::test]
async fn mt_check_root_matches_empty_tree_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::curve::Fr;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_mt_verify_ir();
    let state = mt_check::MtCheckState::new();
    // Use the actual empty-tree root so check_root returns true.
    let expected_root = state.entries.root();
    let witnesses = mt_check::MtCheckWitnesses { expected_root };
    let nocturne_transcript =
        mt_check::transcript::build_verify_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(Fr::from(expected_root.field().value()))];
    let preimage = canonical_preimage("verify", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove's PIs must match on-chain ledger-shape PIs for MerkleTree::check_root (match)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for MerkleTree::check_root (match)");
}

/// Same as above but with a digest that doesn't match the tree root.
/// The Popeq result is `false`; the circuit still proves and verifies
/// — `check_root` is a query, not an assertion.
#[tokio::test]
async fn mt_check_root_mismatch_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::curve::Fr;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_mt_verify_ir();
    let state = mt_check::MtCheckState::new();
    // Bogus digest — doesn't match the empty-tree root.
    let wrong = MerkleTreeDigest::new(Field::from(0xDEADu64));
    let witnesses = mt_check::MtCheckWitnesses {
        expected_root: wrong,
    };
    let nocturne_transcript =
        mt_check::transcript::build_verify_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(Fr::from(wrong.field().value()))];
    let preimage = canonical_preimage("verify", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove's PIs must match on-chain ledger-shape PIs for MerkleTree::check_root (mismatch)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for MerkleTree::check_root (mismatch)");
}

#[midnight::contract]
mod mt_insert {
    use super::*;

    #[midnight(ledger)]
    pub struct MtInsertState {
        pub entries: MerkleTree<10, Bytes<32>>,
    }

    #[midnight(witnesses)]
    pub struct MtInsertWitnesses {
        pub leaf: Bytes<32>,
    }

    impl MtInsertState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                entries: MerkleTree::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn add(&mut self, witnesses: &MtInsertWitnesses) {
            self.entries.insert(&witnesses.leaf);
        }
    }
}

fn build_mt_add_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod mt_insert {
            #[midnight(ledger)]
            pub struct MtInsertState { entries: MerkleTree<10, Bytes<32>> }
            #[midnight(witnesses)]
            pub struct MtInsertWitnesses { pub leaf: Bytes<32> }
            impl MtInsertState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { entries: MerkleTree::empty() } }
                #[midnight(circuit)]
                pub fn add(&mut self, witnesses: &MtInsertWitnesses) {
                    self.entries.insert(&witnesses.leaf);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "add")
        .unwrap()
        .ir_source
}

/// `MerkleTree<10, Bytes<32>>::insert(&leaf)` — the full 10-op
/// append-and-rehash sequence. Exercises:
///
/// - Multi-Fr `Bytes<32>` witness (2 PrivateInputs) flowing into both a
///   PersistentHash (the leafHash with `"mdn:lh"` domain separator) and
///   a Push as the value.
/// - `Dup{n:2}` (new — first use of non-zero n).
/// - `Ins{cached:true, n:2}` (new — multi-level write-back for the
///   counter slot).
/// - Two `Idx{push_path:true}` levels matching the 2-element Array
///   storage shape.
///
/// Insertion has no return value, so there's no Popeq.
#[tokio::test]
async fn mt_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_mt_add_ir();
    let witnesses = mt_insert::MtInsertWitnesses {
        leaf: Bytes::<32>::from([0xA5u8; 32]),
    };
    let nocturne_transcript = mt_insert::transcript::build_add_transcript(&witnesses);

    // Bytes<32> witness expands to 2 Frs in the private transcript.
    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from([0xA5u8; 32])];
    let preimage = canonical_preimage("add", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove's PIs must match on-chain ledger-shape PIs for MerkleTree::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for MerkleTree::insert");
}

// ---------------------------------------------------------------------------
// Phase E.3: `merkle_tree_path_root` as a circuit primitive — chained with
// `check_root` so the verifier sees a single bool publicly committing to
// "the witnessed path is a valid inclusion proof for the on-chain tree
// root". Exercises the full pipeline:
//   - `MerkleTreePath<H, Bytes<32>>` witness expansion (leaf bytes + H
//     entries of (sibling Fr, goes_left Fr))
//   - PersistentHash with the "mdn:lh" domain separator
//   - Unrolled cond_select + transient_hash fold over H entries
//   - The full-Fr digest representation: siblings travel as 32-byte LE
//     Fr through the witness so the in-circuit and on-chain accumulators
//     agree on every chunk.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod mt_verify_path {
    use super::*;

    #[midnight(ledger)]
    pub struct MtVerifyPathState {
        pub entries: MerkleTree<3, Bytes<32>>,
    }

    #[midnight(witnesses)]
    pub struct MtVerifyPathWitnesses {
        pub path: MerkleTreePath<3, Bytes<32>>,
    }

    impl MtVerifyPathState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                entries: MerkleTree::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn verify_path(&self, witnesses: &MtVerifyPathWitnesses) {
            let computed = merkle_tree_path_root(&witnesses.path);
            let _ok = self.entries.check_root(&computed);
        }
    }
}

fn build_mt_verify_path_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod mt_verify_path {
            #[midnight(ledger)]
            pub struct MtVerifyPathState { entries: MerkleTree<3, Bytes<32>> }
            #[midnight(witnesses)]
            pub struct MtVerifyPathWitnesses {
                pub path: MerkleTreePath<3, Bytes<32>>,
            }
            impl MtVerifyPathState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { entries: MerkleTree::empty() } }
                #[midnight(circuit)]
                pub fn verify_path(&self, witnesses: &MtVerifyPathWitnesses) {
                    let computed = merkle_tree_path_root(&witnesses.path);
                    let _ok = self.entries.check_root(&computed);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "verify_path")
        .unwrap()
        .ir_source
}

/// Path verification end-to-end: insert a leaf at index 0, ask the
/// tree for the inclusion path, then prove the witnessed path roots up
/// to the same digest the on-chain `Root` opcode produces. The popeq
/// result is `true`.
#[tokio::test]
async fn mt_verify_path_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_mt_verify_path_ir();

    // Build a tree with one leaf at index 0 and extract its inclusion
    // path. The path's `root()` (off-chain) must equal `tree.root()`
    // (off-chain), and the in-circuit computation must agree with both.
    let mut state = mt_verify_path::MtVerifyPathState::new();
    let leaf = Bytes::<32>::from([0x42u8; 32]);
    state.entries.insert(&leaf);
    let path = state.entries.path_for_leaf(0, leaf.clone());

    // Sanity: off-chain helper agrees with the tree's own root.
    assert_eq!(
        midnight::types::merkle_tree_path_root(&path),
        state.entries.root(),
        "off-chain merkle_tree_path_root must match tree.root() for the inserted leaf",
    );

    let witnesses = mt_verify_path::MtVerifyPathWitnesses {
        path: path.clone(),
    };
    let nocturne_transcript =
        mt_verify_path::transcript::build_verify_path_transcript(&state, &witnesses);

    // The IR consumes the path as PrivateInputs in the same order the
    // transcript builder pushes them: leaf bytes first (Bytes<32> → 2
    // Frs), then for each entry (sibling Fr, goes_left bool). Each
    // AlignedValue is value_only_field_repr'd into preimage.private_transcript
    // by ContractCallPrototype::construct_proof.
    let mut private_outputs: Vec<AlignedValue> = Vec::new();
    private_outputs.push(AlignedValue::from([0x42u8; 32]));
    for entry in path.path.iter() {
        let sibling_fr = Fr::from_le_bytes(&entry.sibling.as_le_bytes())
            .expect("sibling digest bytes round-trip through Fr");
        private_outputs.push(AlignedValue::from(sibling_fr));
        private_outputs.push(AlignedValue::from(entry.goes_left.value()));
    }
    let preimage = canonical_preimage(
        "verify_path",
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
        "prove's PIs must match on-chain ledger-shape PIs for merkle_tree_path_root + check_root"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for merkle_tree_path_root + check_root");
}

// ---------------------------------------------------------------------------
// Wider Map key audit — probe contracts to identify gaps in our Map<K, _>
// support beyond the existing Uint<64> / Bytes<32> coverage.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod map_field_key {
    use super::*;

    #[midnight(ledger)]
    pub struct MapFieldState {
        pub records: Map<Field, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct MapFieldWitnesses {
        pub key: Field,
        pub amount: Uint<64>,
    }

    impl MapFieldState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &MapFieldWitnesses) {
            self.records.insert(witnesses.key, witnesses.amount);
        }

        #[midnight(circuit)]
        pub fn check_member(&self, witnesses: &MapFieldWitnesses) {
            let _exists = self.records.contains(&witnesses.key);
        }
    }
}

fn build_map_field_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod map_field_key {
            #[midnight(ledger)]
            pub struct MapFieldState { records: Map<Field, Uint<64>> }
            #[midnight(witnesses)]
            pub struct MapFieldWitnesses { pub key: Field, pub amount: Uint<64> }
            impl MapFieldState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &MapFieldWitnesses) {
                    self.records.insert(witnesses.key, witnesses.amount);
                }
                #[midnight(circuit)]
                pub fn check_member(&self, witnesses: &MapFieldWitnesses) {
                    let _exists = self.records.contains(&witnesses.key);
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

/// `Map<Field, Uint<64>>::insert(k, v)` end-to-end. Field key uses
/// `AlignmentAtom::Field` (`[1, -2]`), value uses `Bytes<8>` for the
/// 64-bit width — same opcode shape as Map<Uint<64>, Uint<64>> but with
/// a Field-aligned key Push.
#[tokio::test]
async fn map_field_key_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_field_ir("record");
    let key = Field::from(0xC0FFEEu64);
    let witnesses = map_field_key::MapFieldWitnesses {
        key,
        amount: Uint::<64>::from(7u64),
    };
    let nocturne_transcript =
        map_field_key::transcript::build_record_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(Fr::from(key.value())),
        AlignedValue::from(7u64),
    ];
    let preimage =
        canonical_preimage("record", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove PIs must match ledger PIs for Map<Field, _>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Field, _>::insert");
}

/// `Map<Field, Uint<64>>::contains(&k)` end-to-end. Field-keyed lookup
/// matches the on-chain Member opcode against a Field-aligned key Push.
#[tokio::test]
async fn map_field_key_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_field_ir("check_member");
    let state = map_field_key::MapFieldState::new();
    let key = Field::from(0xABCDu64);
    let witnesses = map_field_key::MapFieldWitnesses {
        key,
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript =
        map_field_key::transcript::build_check_member_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(Fr::from(key.value()))];
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
        "prove PIs must match ledger PIs for Map<Field, _>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Field, _>::contains");
}

#[midnight::contract]
mod map_digest_key {
    use super::*;

    #[midnight(ledger)]
    pub struct MapDigestState {
        pub records: Map<MerkleTreeDigest, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct MapDigestWitnesses {
        pub key: MerkleTreeDigest,
        pub amount: Uint<64>,
    }

    impl MapDigestState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &MapDigestWitnesses) {
            self.records.insert(witnesses.key, witnesses.amount);
        }

        #[midnight(circuit)]
        pub fn check_member(&self, witnesses: &MapDigestWitnesses) {
            let _exists = self.records.contains(&witnesses.key);
        }
    }
}

fn build_map_digest_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod map_digest_key {
            #[midnight(ledger)]
            pub struct MapDigestState { records: Map<MerkleTreeDigest, Uint<64>> }
            #[midnight(witnesses)]
            pub struct MapDigestWitnesses {
                pub key: MerkleTreeDigest,
                pub amount: Uint<64>,
            }
            impl MapDigestState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &MapDigestWitnesses) {
                    self.records.insert(witnesses.key, witnesses.amount);
                }
                #[midnight(circuit)]
                pub fn check_member(&self, witnesses: &MapDigestWitnesses) {
                    let _exists = self.records.contains(&witnesses.key);
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

/// `Map<MerkleTreeDigest, Uint<64>>::insert(k, v)` end-to-end. The digest
/// key travels through the IR's Push as a full-Fr Cell(Field(digest_fr)) and
/// through the transcript builder's AlignedValue construction without
/// truncation.
#[tokio::test]
async fn map_digest_key_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_digest_ir("record");
    let key = MerkleTreeDigest::new(Field::from(0xCAFEu64));
    let witnesses = map_digest_key::MapDigestWitnesses {
        key,
        amount: Uint::<64>::from(42u64),
    };
    let nocturne_transcript =
        map_digest_key::transcript::build_record_transcript(&witnesses);

    // Witness layout: 1 Fr (digest as full Fr) + 1 Fr (Uint<64> as u64).
    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(
            Fr::from_le_bytes(&key.as_le_bytes())
                .expect("digest round-trips through Fr"),
        ),
        AlignedValue::from(42u64),
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
        "prove PIs must match ledger PIs for Map<MerkleTreeDigest, _>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<MerkleTreeDigest, _>::insert");
}

/// `Map<MerkleTreeDigest, Uint<64>>::contains(&k)` end-to-end. Popeq result
/// is `false` for an empty map.
#[tokio::test]
async fn map_digest_key_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_digest_ir("check_member");
    let state = map_digest_key::MapDigestState::new();
    let key = MerkleTreeDigest::new(Field::from(0xBEEFu64));
    let witnesses = map_digest_key::MapDigestWitnesses {
        key,
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript =
        map_digest_key::transcript::build_check_member_transcript(&state, &witnesses);

    // The circuit only reads `witnesses.key`, so the IR emits exactly
    // one PrivateInput. Empty map → contains returns false.
    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(
        Fr::from_le_bytes(&key.as_le_bytes())
            .expect("digest round-trips through Fr"),
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
        "prove PIs must match ledger PIs for Map<MerkleTreeDigest, _>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<MerkleTreeDigest, _>::contains");
}

// ---------------------------------------------------------------------------
// Wider Set element types: Set<Field> and Set<MerkleTreeDigest>. Set reuses
// Map's on-chain ops (StateValue::Null as the value slot), so the same
// Field-aligned key handling should apply by construction. These tests pin
// that down end-to-end.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod set_field_elem {
    use super::*;

    #[midnight(ledger)]
    pub struct SetFieldState {
        pub members: Set<Field>,
    }

    #[midnight(witnesses)]
    pub struct SetFieldWitnesses {
        pub elem: Field,
    }

    impl SetFieldState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                members: Set::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn add(&mut self, witnesses: &SetFieldWitnesses) {
            self.members.insert(witnesses.elem);
        }

        #[midnight(circuit)]
        pub fn check(&self, witnesses: &SetFieldWitnesses) {
            let _exists = self.members.contains(&witnesses.elem);
        }

        #[midnight(circuit)]
        pub fn erase(&mut self, witnesses: &SetFieldWitnesses) {
            self.members.remove(&witnesses.elem);
        }
    }
}

fn build_set_field_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod set_field_elem {
            #[midnight(ledger)]
            pub struct SetFieldState { members: Set<Field> }
            #[midnight(witnesses)]
            pub struct SetFieldWitnesses { pub elem: Field }
            impl SetFieldState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { members: Set::empty() } }
                #[midnight(circuit)]
                pub fn add(&mut self, witnesses: &SetFieldWitnesses) {
                    self.members.insert(witnesses.elem);
                }
                #[midnight(circuit)]
                pub fn check(&self, witnesses: &SetFieldWitnesses) {
                    let _exists = self.members.contains(&witnesses.elem);
                }
                #[midnight(circuit)]
                pub fn erase(&mut self, witnesses: &SetFieldWitnesses) {
                    self.members.remove(&witnesses.elem);
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

#[tokio::test]
async fn set_field_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_field_ir("add");
    let elem = Field::from(0x1234u64);
    let witnesses = set_field_elem::SetFieldWitnesses { elem };
    let nocturne_transcript =
        set_field_elem::transcript::build_add_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(Fr::from(elem.value()))];
    let preimage = canonical_preimage("add", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove PIs must match ledger PIs for Set<Field>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<Field>::insert");
}

#[tokio::test]
async fn set_field_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_field_ir("check");
    let state = set_field_elem::SetFieldState::new();
    let elem = Field::from(0x5678u64);
    let witnesses = set_field_elem::SetFieldWitnesses { elem };
    let nocturne_transcript =
        set_field_elem::transcript::build_check_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(Fr::from(elem.value()))];
    let preimage = canonical_preimage("check", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove PIs must match ledger PIs for Set<Field>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<Field>::contains");
}

#[tokio::test]
async fn set_field_remove_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_field_ir("erase");
    let elem = Field::from(0x9abcu64);
    let witnesses = set_field_elem::SetFieldWitnesses { elem };
    let nocturne_transcript =
        set_field_elem::transcript::build_erase_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(Fr::from(elem.value()))];
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
        "prove PIs must match ledger PIs for Set<Field>::remove"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<Field>::remove");
}

#[midnight::contract]
mod set_digest_elem {
    use super::*;

    #[midnight(ledger)]
    pub struct SetDigestState {
        pub members: Set<MerkleTreeDigest>,
    }

    #[midnight(witnesses)]
    pub struct SetDigestWitnesses {
        pub elem: MerkleTreeDigest,
    }

    impl SetDigestState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                members: Set::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn add(&mut self, witnesses: &SetDigestWitnesses) {
            self.members.insert(witnesses.elem);
        }

        #[midnight(circuit)]
        pub fn check(&self, witnesses: &SetDigestWitnesses) {
            let _exists = self.members.contains(&witnesses.elem);
        }

        #[midnight(circuit)]
        pub fn erase(&mut self, witnesses: &SetDigestWitnesses) {
            self.members.remove(&witnesses.elem);
        }
    }
}

fn build_set_digest_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod set_digest_elem {
            #[midnight(ledger)]
            pub struct SetDigestState { members: Set<MerkleTreeDigest> }
            #[midnight(witnesses)]
            pub struct SetDigestWitnesses { pub elem: MerkleTreeDigest }
            impl SetDigestState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { members: Set::empty() } }
                #[midnight(circuit)]
                pub fn add(&mut self, witnesses: &SetDigestWitnesses) {
                    self.members.insert(witnesses.elem);
                }
                #[midnight(circuit)]
                pub fn check(&self, witnesses: &SetDigestWitnesses) {
                    let _exists = self.members.contains(&witnesses.elem);
                }
                #[midnight(circuit)]
                pub fn erase(&mut self, witnesses: &SetDigestWitnesses) {
                    self.members.remove(&witnesses.elem);
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

#[tokio::test]
async fn set_digest_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_digest_ir("add");
    let elem = MerkleTreeDigest::new(Field::from(0xFEEDu64));
    let witnesses = set_digest_elem::SetDigestWitnesses { elem };
    let nocturne_transcript =
        set_digest_elem::transcript::build_add_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(
        Fr::from_le_bytes(&elem.as_le_bytes())
            .expect("digest round-trips through Fr"),
    )];
    let preimage = canonical_preimage("add", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove PIs must match ledger PIs for Set<MerkleTreeDigest>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<MerkleTreeDigest>::insert");
}

#[tokio::test]
async fn set_digest_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_digest_ir("check");
    let state = set_digest_elem::SetDigestState::new();
    let elem = MerkleTreeDigest::new(Field::from(0xC0DEu64));
    let witnesses = set_digest_elem::SetDigestWitnesses { elem };
    let nocturne_transcript =
        set_digest_elem::transcript::build_check_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(
        Fr::from_le_bytes(&elem.as_le_bytes())
            .expect("digest round-trips through Fr"),
    )];
    let preimage = canonical_preimage("check", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove PIs must match ledger PIs for Set<MerkleTreeDigest>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<MerkleTreeDigest>::contains");
}

#[tokio::test]
async fn set_digest_remove_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_set_digest_ir("erase");
    let elem = MerkleTreeDigest::new(Field::from(0xBEAFu64));
    let witnesses = set_digest_elem::SetDigestWitnesses { elem };
    let nocturne_transcript =
        set_digest_elem::transcript::build_erase_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(
        Fr::from_le_bytes(&elem.as_le_bytes())
            .expect("digest round-trips through Fr"),
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
        "prove PIs must match ledger PIs for Set<MerkleTreeDigest>::remove"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Set<MerkleTreeDigest>::remove");
}

// ---------------------------------------------------------------------------
// Bytes<N != 32> coverage: lock in the multi-Fr key boundary cases.
//   - Bytes<16>: single-Fr key (16 ≤ 31 fits in one Fr chunk).
//   - Bytes<48>: multi-Fr key (48 = 17 + 31, two Fr chunks).
// Map<Bytes<32>, _> is already exercised by the byte_records tests.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod map_b16_key {
    use super::*;

    #[midnight(ledger)]
    pub struct MapB16State {
        pub records: Map<Bytes<16>, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct MapB16Witnesses {
        pub key: Bytes<16>,
        pub amount: Uint<64>,
    }

    impl MapB16State {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &MapB16Witnesses) {
            self.records.insert(witnesses.key.clone(), witnesses.amount);
        }

        #[midnight(circuit)]
        pub fn check_member(&self, witnesses: &MapB16Witnesses) {
            let _exists = self.records.contains(&witnesses.key);
        }
    }
}

fn build_map_b16_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod map_b16_key {
            #[midnight(ledger)]
            pub struct MapB16State { records: Map<Bytes<16>, Uint<64>> }
            #[midnight(witnesses)]
            pub struct MapB16Witnesses { pub key: Bytes<16>, pub amount: Uint<64> }
            impl MapB16State {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &MapB16Witnesses) {
                    self.records.insert(witnesses.key.clone(), witnesses.amount);
                }
                #[midnight(circuit)]
                pub fn check_member(&self, witnesses: &MapB16Witnesses) {
                    let _exists = self.records.contains(&witnesses.key);
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

/// `Map<Bytes<16>, Uint<64>>::insert(k, v)` — single-Fr key (Bytes<N ≤ 31>
/// fits in one Fr chunk). Confirms the encoding plumbing handles the
/// shorter alignment without regressing the Bytes<32> path.
#[tokio::test]
async fn map_b16_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_b16_ir("record");
    let key_bytes = [0x77u8; 16];
    let witnesses = map_b16_key::MapB16Witnesses {
        key: Bytes::<16>::from(key_bytes),
        amount: Uint::<64>::from(33u64),
    };
    let nocturne_transcript = map_b16_key::transcript::build_record_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(key_bytes),
        AlignedValue::from(33u64),
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
        "prove PIs must match ledger PIs for Map<Bytes<16>, _>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<16>, _>::insert");
}

/// `Map<Bytes<16>, Uint<64>>::contains(&k)` — single-Fr key Member lookup.
#[tokio::test]
async fn map_b16_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_b16_ir("check_member");
    let state = map_b16_key::MapB16State::new();
    let key_bytes = [0x88u8; 16];
    let witnesses = map_b16_key::MapB16Witnesses {
        key: Bytes::<16>::from(key_bytes),
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript =
        map_b16_key::transcript::build_check_member_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(key_bytes)];
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
        "prove PIs must match ledger PIs for Map<Bytes<16>, _>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<16>, _>::contains");
}

#[midnight::contract]
mod map_b48_key {
    use super::*;

    #[midnight(ledger)]
    pub struct MapB48State {
        pub records: Map<Bytes<48>, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct MapB48Witnesses {
        pub key: Bytes<48>,
        pub amount: Uint<64>,
    }

    impl MapB48State {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &MapB48Witnesses) {
            self.records.insert(witnesses.key.clone(), witnesses.amount);
        }

        #[midnight(circuit)]
        pub fn check_member(&self, witnesses: &MapB48Witnesses) {
            let _exists = self.records.contains(&witnesses.key);
        }
    }
}

fn build_map_b48_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod map_b48_key {
            #[midnight(ledger)]
            pub struct MapB48State { records: Map<Bytes<48>, Uint<64>> }
            #[midnight(witnesses)]
            pub struct MapB48Witnesses { pub key: Bytes<48>, pub amount: Uint<64> }
            impl MapB48State {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &MapB48Witnesses) {
                    self.records.insert(witnesses.key.clone(), witnesses.amount);
                }
                #[midnight(circuit)]
                pub fn check_member(&self, witnesses: &MapB48Witnesses) {
                    let _exists = self.records.contains(&witnesses.key);
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

/// `Map<Bytes<48>, Uint<64>>::insert(k, v)` — multi-Fr key, 48 bytes
/// chunked as 17 + 31 = 2 Frs (the bytes_n_layout splits the leading
/// remainder into the first chunk). Stresses the multi-Fr key path
/// beyond the Bytes<32>-only coverage.
#[tokio::test]
async fn map_b48_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_b48_ir("record");
    let key_bytes = [0xCDu8; 48];
    let witnesses = map_b48_key::MapB48Witnesses {
        key: Bytes::<48>::from(key_bytes),
        amount: Uint::<64>::from(2024u64),
    };
    let nocturne_transcript = map_b48_key::transcript::build_record_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(key_bytes),
        AlignedValue::from(2024u64),
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
        "prove PIs must match ledger PIs for Map<Bytes<48>, _>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<48>, _>::insert");
}

/// `Map<Bytes<48>, Uint<64>>::contains(&k)` — multi-Fr key Member lookup.
#[tokio::test]
async fn map_b48_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_b48_ir("check_member");
    let state = map_b48_key::MapB48State::new();
    let key_bytes = [0xEEu8; 48];
    let witnesses = map_b48_key::MapB48Witnesses {
        key: Bytes::<48>::from(key_bytes),
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript =
        map_b48_key::transcript::build_check_member_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(key_bytes)];
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
        "prove PIs must match ledger PIs for Map<Bytes<48>, _>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Bytes<48>, _>::contains");
}

// ---------------------------------------------------------------------------
// MerkleTree<H, Bytes<N != 32>> coverage: lift the Bytes<32>-only restriction
// on the leafHash persistent_hash alignment. Two boundary cases:
//   - Bytes<16>: single-Fr leaf (1 chunk, alignment [Bytes{6}, Bytes{16}]).
//   - Bytes<64>: 3-chunk leaf (chunks=2 + 1 trailing byte → bytes_n_layout
//                splits as [Bits(16), Bits(248), Bits(248)], 3 Fr inputs to
//                persistent_hash with alignment [Bytes{6}, Bytes{64}]).
// ---------------------------------------------------------------------------

#[midnight::contract]
mod mt_b16_insert {
    use super::*;

    #[midnight(ledger)]
    pub struct MtB16InsertState {
        pub entries: MerkleTree<10, Bytes<16>>,
    }

    #[midnight(witnesses)]
    pub struct MtB16InsertWitnesses {
        pub leaf: Bytes<16>,
    }

    impl MtB16InsertState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                entries: MerkleTree::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn add(&mut self, witnesses: &MtB16InsertWitnesses) {
            self.entries.insert(&witnesses.leaf);
        }
    }
}

fn build_mt_b16_add_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod mt_b16_insert {
            #[midnight(ledger)]
            pub struct MtB16InsertState { entries: MerkleTree<10, Bytes<16>> }
            #[midnight(witnesses)]
            pub struct MtB16InsertWitnesses { pub leaf: Bytes<16> }
            impl MtB16InsertState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { entries: MerkleTree::empty() } }
                #[midnight(circuit)]
                pub fn add(&mut self, witnesses: &MtB16InsertWitnesses) {
                    self.entries.insert(&witnesses.leaf);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "add")
        .unwrap()
        .ir_source
}

/// `MerkleTree<10, Bytes<16>>::insert(&leaf)` — single-Fr leaf path.
/// leafHash persistent_hash uses alignment [Bytes{6}, Bytes{16}] with
/// 2 Fr inputs (domain_sep + 1 leaf chunk).
#[tokio::test]
async fn mt_b16_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_mt_b16_add_ir();
    let leaf_bytes = [0xA5u8; 16];
    let witnesses = mt_b16_insert::MtB16InsertWitnesses {
        leaf: Bytes::<16>::from(leaf_bytes),
    };
    let nocturne_transcript = mt_b16_insert::transcript::build_add_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(leaf_bytes)];
    let preimage = canonical_preimage("add", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove PIs must match ledger PIs for MerkleTree<_, Bytes<16>>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for MerkleTree<_, Bytes<16>>::insert");
}

#[midnight::contract]
mod mt_b64_insert {
    use super::*;

    #[midnight(ledger)]
    pub struct MtB64InsertState {
        pub entries: MerkleTree<10, Bytes<64>>,
    }

    #[midnight(witnesses)]
    pub struct MtB64InsertWitnesses {
        pub leaf: Bytes<64>,
    }

    impl MtB64InsertState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                entries: MerkleTree::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn add(&mut self, witnesses: &MtB64InsertWitnesses) {
            self.entries.insert(&witnesses.leaf);
        }
    }
}

fn build_mt_b64_add_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod mt_b64_insert {
            #[midnight(ledger)]
            pub struct MtB64InsertState { entries: MerkleTree<10, Bytes<64>> }
            #[midnight(witnesses)]
            pub struct MtB64InsertWitnesses { pub leaf: Bytes<64> }
            impl MtB64InsertState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { entries: MerkleTree::empty() } }
                #[midnight(circuit)]
                pub fn add(&mut self, witnesses: &MtB64InsertWitnesses) {
                    self.entries.insert(&witnesses.leaf);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "add")
        .unwrap()
        .ir_source
}

/// `MerkleTree<10, Bytes<64>>::insert(&leaf)` — 3-chunk leaf path.
/// `bytes_n_layout(64)` splits the leaf as (2, 31, 31) bytes per Fr;
/// leafHash persistent_hash uses alignment [Bytes{6}, Bytes{64}] with
/// 4 Fr inputs (domain_sep + 3 leaf chunks).
#[tokio::test]
async fn mt_b64_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_mt_b64_add_ir();
    let leaf_bytes = [0xBBu8; 64];
    let witnesses = mt_b64_insert::MtB64InsertWitnesses {
        leaf: Bytes::<64>::from(leaf_bytes),
    };
    let nocturne_transcript = mt_b64_insert::transcript::build_add_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(leaf_bytes)];
    let preimage = canonical_preimage("add", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove PIs must match ledger PIs for MerkleTree<_, Bytes<64>>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for MerkleTree<_, Bytes<64>>::insert");
}

// Same path-verification end-to-end as mt_verify_path but with a
// single-Fr Bytes<16> leaf, exercising the lifted alignment in
// `emit_merkle_tree_path_root`.

#[midnight::contract]
mod mt_b16_verify_path {
    use super::*;

    #[midnight(ledger)]
    pub struct MtB16VerifyPathState {
        pub entries: MerkleTree<3, Bytes<16>>,
    }

    #[midnight(witnesses)]
    pub struct MtB16VerifyPathWitnesses {
        pub path: MerkleTreePath<3, Bytes<16>>,
    }

    impl MtB16VerifyPathState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                entries: MerkleTree::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn verify_path(&self, witnesses: &MtB16VerifyPathWitnesses) {
            let computed = merkle_tree_path_root(&witnesses.path);
            let _ok = self.entries.check_root(&computed);
        }
    }
}

fn build_mt_b16_verify_path_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod mt_b16_verify_path {
            #[midnight(ledger)]
            pub struct MtB16VerifyPathState { entries: MerkleTree<3, Bytes<16>> }
            #[midnight(witnesses)]
            pub struct MtB16VerifyPathWitnesses {
                pub path: MerkleTreePath<3, Bytes<16>>,
            }
            impl MtB16VerifyPathState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { entries: MerkleTree::empty() } }
                #[midnight(circuit)]
                pub fn verify_path(&self, witnesses: &MtB16VerifyPathWitnesses) {
                    let computed = merkle_tree_path_root(&witnesses.path);
                    let _ok = self.entries.check_root(&computed);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "verify_path")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn mt_b16_verify_path_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_mt_b16_verify_path_ir();
    let mut state = mt_b16_verify_path::MtB16VerifyPathState::new();
    let leaf = Bytes::<16>::from([0x99u8; 16]);
    state.entries.insert(&leaf);
    let path = state.entries.path_for_leaf(0, leaf.clone());

    assert_eq!(
        midnight::types::merkle_tree_path_root(&path),
        state.entries.root(),
        "off-chain merkle_tree_path_root must match tree.root() for Bytes<16> leaf",
    );

    let witnesses = mt_b16_verify_path::MtB16VerifyPathWitnesses {
        path: path.clone(),
    };
    let nocturne_transcript =
        mt_b16_verify_path::transcript::build_verify_path_transcript(&state, &witnesses);

    // private_transcript order: leaf (1 Fr) + 3 * (sibling, goes_left).
    let mut private_outputs: Vec<AlignedValue> = Vec::new();
    private_outputs.push(AlignedValue::from([0x99u8; 16]));
    for entry in path.path.iter() {
        let sibling_fr = Fr::from_le_bytes(&entry.sibling.as_le_bytes())
            .expect("sibling digest bytes round-trip through Fr");
        private_outputs.push(AlignedValue::from(sibling_fr));
        private_outputs.push(AlignedValue::from(entry.goes_left.value()));
    }
    let preimage = canonical_preimage(
        "verify_path",
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
        "prove PIs must match ledger PIs for path_root + check_root with Bytes<16> leaf"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for path_root + check_root with Bytes<16> leaf");
}

// ---------------------------------------------------------------------------
// Tuple keys: Map<(K1, K2), V>. Compact supports record-typed keys; the
// on-chain encoding is `Alignment::concat([K1::alignment(), K2::alignment()])`
// (base-crypto/src/fab/alignments.rs:49-53) with values laid out
// component-by-component. Start with a small `(Field, Uint<64>)` key as a
// probe — single-Fr per component, no multi-Fr edge cases.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod map_tuple_key {
    use super::*;

    #[midnight(ledger)]
    pub struct MapTupleState {
        pub records: Map<(Field, Uint<64>), Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct MapTupleWitnesses {
        pub key: (Field, Uint<64>),
        pub amount: Uint<64>,
    }

    impl MapTupleState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &MapTupleWitnesses) {
            self.records.insert(witnesses.key, witnesses.amount);
        }

        #[midnight(circuit)]
        pub fn check_member(&self, witnesses: &MapTupleWitnesses) {
            let _exists = self.records.contains(&witnesses.key);
        }
    }
}

fn build_map_tuple_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod map_tuple_key {
            #[midnight(ledger)]
            pub struct MapTupleState { records: Map<(Field, Uint<64>), Uint<64>> }
            #[midnight(witnesses)]
            pub struct MapTupleWitnesses { pub key: (Field, Uint<64>), pub amount: Uint<64> }
            impl MapTupleState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &MapTupleWitnesses) {
                    self.records.insert(witnesses.key, witnesses.amount);
                }
                #[midnight(circuit)]
                pub fn check_member(&self, witnesses: &MapTupleWitnesses) {
                    let _exists = self.records.contains(&witnesses.key);
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

#[tokio::test]
async fn map_tuple_key_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_tuple_ir("record");
    let key_field = Field::from(0xABCDu64);
    let key_uint = Uint::<64>::from(7u64);
    let witnesses = map_tuple_key::MapTupleWitnesses {
        key: (key_field, key_uint),
        amount: Uint::<64>::from(99u64),
    };
    let nocturne_transcript =
        map_tuple_key::transcript::build_record_transcript(&witnesses);

    // Witness layout: tuple expands as (Field, Uint<64>) → 2 Frs in
    // declaration order, then `amount` → 1 Fr.
    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(Fr::from(key_field.value())),
        AlignedValue::from(key_uint.value() as u64),
        AlignedValue::from(99u64),
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
        "prove PIs must match ledger PIs for Map<(Field, Uint<64>), _>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<(Field, Uint<64>), _>::insert");
}

#[tokio::test]
async fn map_tuple_key_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_tuple_ir("check_member");
    let state = map_tuple_key::MapTupleState::new();
    let key_field = Field::from(0x1234u64);
    let key_uint = Uint::<64>::from(5u64);
    let witnesses = map_tuple_key::MapTupleWitnesses {
        key: (key_field, key_uint),
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript =
        map_tuple_key::transcript::build_check_member_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(Fr::from(key_field.value())),
        AlignedValue::from(key_uint.value() as u64),
    ];
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
        "prove PIs must match ledger PIs for Map<(Field, Uint<64>), _>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<(Field, Uint<64>), _>::contains");
}

// ---------------------------------------------------------------------------
// Const-bounded `for i in 0..N { ... }` unrolling. The parser inlines N
// copies of the body with `i` substituted by the iteration value, so each
// iteration emits its own VM ops as if written out by hand.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod for_counter {
    use super::*;

    #[midnight(ledger)]
    pub struct ForCounterState {
        pub count: Counter,
    }

    impl ForCounterState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        // Unrolls to three Counter::increment() emissions.
        #[midnight(circuit)]
        pub fn inc_three(&mut self) {
            for _i in 0..3 {
                self.count.increment();
            }
        }
    }
}

fn build_for_counter_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod for_counter {
            #[midnight(ledger)]
            pub struct ForCounterState { count: Counter }
            impl ForCounterState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn inc_three(&mut self) {
                    for _i in 0..3 {
                        self.count.increment();
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
        .find(|c| c.circuit_name == "inc_three")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn for_loop_unroll_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_for_counter_ir();
    let nocturne_transcript = for_counter::transcript::build_inc_three_transcript();

    // Three increments → three Idx+Addi+Ins groups. No witnesses, no
    // popeq result, so private_transcript_outputs is empty.
    let preimage = canonical_preimage("inc_three", nocturne_transcript.ops.clone(), vec![]);

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
        "prove PIs must match ledger PIs for unrolled `for _ in 0..3` over Counter::increment"
    );

    // The transcript should contain exactly 3 Counter::increment op
    // groups (Idx + Addi + Ins per increment = 3 ops × 3 iterations).
    let increments = nocturne_transcript
        .ops
        .iter()
        .filter(|op| matches!(op, Op::Addi { immediate: 1 }))
        .count();
    assert_eq!(increments, 3, "for-loop unrolled to 3 Addi ops");

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for the unrolled for-loop circuit");
}

#[midnight::contract]
mod for_var_use {
    use super::*;

    #[midnight(ledger)]
    pub struct ForVarState {
        pub last: Cell<u64>,
    }

    impl ForVarState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                last: Cell::new(0u64),
            }
        }

        // Three `Cell::set` calls with values 0, 1, 2 (last wins). The
        // loop variable `i` is substituted by the iteration value at
        // parse time, so each iteration carries a distinct literal.
        #[midnight(circuit)]
        pub fn fill(&mut self) {
            for i in 0..3u64 {
                self.last.set(i);
            }
        }
    }
}

fn build_for_var_use_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod for_var_use {
            #[midnight(ledger)]
            pub struct ForVarState { last: Cell<u64> }
            impl ForVarState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { last: Cell::new(0u64) } }
                #[midnight(circuit)]
                pub fn fill(&mut self) {
                    for i in 0..3u64 {
                        self.last.set(i);
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
        .find(|c| c.circuit_name == "fill")
        .unwrap()
        .ir_source
}

/// Loop variable substitution test: `for i in 0..3u64` with `i` used
/// as the argument to `Cell::set`. If substitution fails (e.g. `i`
/// stays as a Var instead of being replaced by the literal),
/// compilation breaks because `i` isn't in scope at the call site.
#[tokio::test]
async fn for_loop_var_substituted_into_literals() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_for_var_use_ir();
    let nocturne_transcript = for_var_use::transcript::build_fill_transcript();

    let preimage = canonical_preimage("fill", nocturne_transcript.ops.clone(), vec![]);

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
        "prove PIs must match ledger PIs for `for i in 0..3` over Map::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for the loop-variable substitution circuit");
}

// ---------------------------------------------------------------------------
// Conditional edge-case coverage: cover paths the original conditional
// tests left implicit — else-active (vs. then-active), and the two
// non-deepest nested-if paths.
//
// All three reuse the existing `cond_writer` / `nested_cond` contracts
// and their IRs, but exercise different witness shapes so the cond_select
// zeroing + io_guards machinery has to handle the inactive branches in
// the opposite direction.
// ---------------------------------------------------------------------------

/// Else-active sibling of `conditional_cell_set_proves_and_verifies`:
/// `do_it=false` runs `self.raised.set(false)`. The then-branch's
/// `Cell::set(true)` declares must cond_select to zero so the prove PIs
/// line up with the Noop-padded transcript the ledger sees.
#[tokio::test]
async fn conditional_cell_set_else_active_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_maybe_raise_ir();
    let witnesses = cond_writer::CondWriterWitnesses {
        do_it: Boolean::from(false),
    };
    let nocturne_transcript = cond_writer::transcript::build_maybe_raise_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(false)];
    let preimage = canonical_preimage(
        "maybe_raise",
        nocturne_transcript.ops.clone(),
        private_outputs,
    );

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove PIs must match ledger PIs when the else branch is active"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for else-active conditional Cell::set");
}

/// Nested if-else middle path: outer=true, inner=false. The outer
/// guard activates the inner if/else; the inner else branch runs
/// `self.b.increment()`. The inner then's `self.a.increment()` and the
/// outer else's `self.c.increment()` must both cond_select to zero.
#[tokio::test]
async fn nested_conditional_inner_else_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_tick_ir();
    let witnesses = nested_cond::NestedCondWitnesses {
        outer: Boolean::from(true),
        inner: Boolean::from(false),
    };
    let nocturne_transcript = nested_cond::transcript::build_tick_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(true), AlignedValue::from(false)];
    let preimage = canonical_preimage("tick", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove PIs must match ledger PIs for nested (outer=true, inner=false)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for nested (outer=true, inner=false)");
}

/// Nested if-else outermost-else path: outer=false. Both inner
/// branches sit inside the outer-true block and must collectively
/// cond_select to zero. Only `self.c.increment()` is active.
#[tokio::test]
async fn nested_conditional_outer_else_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_tick_ir();
    // `inner` is unread when `outer` is false (the inner if/else is
    // entirely inside the outer-true branch). The IR still emits a
    // PrivateInput for it because witness reads aren't dataflow-pruned;
    // the io_guard ensures the inactive read is skipped on-chain, so
    // we still supply the value here for the prover's side.
    let witnesses = nested_cond::NestedCondWitnesses {
        outer: Boolean::from(false),
        inner: Boolean::from(false),
    };
    let nocturne_transcript = nested_cond::transcript::build_tick_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(false)];
    let preimage = canonical_preimage("tick", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove PIs must match ledger PIs for nested (outer=false)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for nested (outer=false)");
}

// ---------------------------------------------------------------------------
// Struct keys: `struct MyKey { a: Field, b: Uint<64> }` used as a Map key.
// Encoding-wise the same shape as the tuple `(Field, Uint<64>)`; the only
// novelty is field projection by name (`key.a` vs `key.0`).
// ---------------------------------------------------------------------------

#[midnight::contract]
mod map_struct_key {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct MyKey {
        pub a: Field,
        pub b: Uint<64>,
    }

    #[midnight(ledger)]
    pub struct MapStructState {
        pub records: Map<MyKey, Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct MapStructWitnesses {
        pub key: MyKey,
        pub amount: Uint<64>,
    }

    impl MapStructState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                records: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &MapStructWitnesses) {
            self.records.insert(witnesses.key, witnesses.amount);
        }

        #[midnight(circuit)]
        pub fn check_member(&self, witnesses: &MapStructWitnesses) {
            let _exists = self.records.contains(&witnesses.key);
        }
    }
}

fn build_map_struct_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod map_struct_key {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            pub struct MyKey { pub a: Field, pub b: Uint<64> }

            #[midnight(ledger)]
            pub struct MapStructState { records: Map<MyKey, Uint<64>> }
            #[midnight(witnesses)]
            pub struct MapStructWitnesses { pub key: MyKey, pub amount: Uint<64> }
            impl MapStructState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { records: Map::empty() } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &MapStructWitnesses) {
                    self.records.insert(witnesses.key, witnesses.amount);
                }
                #[midnight(circuit)]
                pub fn check_member(&self, witnesses: &MapStructWitnesses) {
                    let _exists = self.records.contains(&witnesses.key);
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

#[tokio::test]
async fn map_struct_key_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_struct_ir("record");
    let key_a = Field::from(0xABCDu64);
    let key_b = Uint::<64>::from(7u64);
    let witnesses = map_struct_key::MapStructWitnesses {
        key: map_struct_key::MyKey { a: key_a, b: key_b },
        amount: Uint::<64>::from(99u64),
    };
    let nocturne_transcript =
        map_struct_key::transcript::build_record_transcript(&witnesses);

    // Witness expansion: key.a → 1 Fr (Field), key.b → 1 Fr (Uint<64>),
    // amount → 1 Fr. Same shape as the equivalent (Field, Uint<64>)
    // tuple key, just projected by field name.
    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(Fr::from(key_a.value())),
        AlignedValue::from(key_b.value() as u64),
        AlignedValue::from(99u64),
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
        "prove PIs must match ledger PIs for Map<MyKey, Uint<64>>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<MyKey, _>::insert");
}

#[tokio::test]
async fn map_struct_key_contains_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_map_struct_ir("check_member");
    let state = map_struct_key::MapStructState::new();
    let key_a = Field::from(0x1234u64);
    let key_b = Uint::<64>::from(5u64);
    let witnesses = map_struct_key::MapStructWitnesses {
        key: map_struct_key::MyKey { a: key_a, b: key_b },
        amount: Uint::<64>::from(0u64),
    };
    let nocturne_transcript =
        map_struct_key::transcript::build_check_member_transcript(&state, &witnesses);

    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(Fr::from(key_a.value())),
        AlignedValue::from(key_b.value() as u64),
    ];
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
        "prove PIs must match ledger PIs for Map<MyKey, _>::contains"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<MyKey, _>::contains");
}

// ---------------------------------------------------------------------------
// Unit-variant enums as Cell values + as Map keys. Encoded as Bytes<1>
// carrying the variant discriminant.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod enum_state {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Status {
        Open,
        Closed,
        Cancelled,
    }

    #[midnight(ledger)]
    pub struct EnumStateLedger {
        pub status: Cell<Status>,
    }

    #[midnight(witnesses)]
    pub struct EnumStateWitnesses {
        pub new_status: Status,
    }

    impl EnumStateLedger {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                status: Cell::new(Status::Open),
            }
        }

        #[midnight(circuit)]
        pub fn transition(&mut self, witnesses: &EnumStateWitnesses) {
            self.status.set(witnesses.new_status);
        }
    }
}

fn build_enum_state_ir(circuit_name: &str) -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod enum_state {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            pub enum Status { Open, Closed, Cancelled }

            #[midnight(ledger)]
            pub struct EnumStateLedger { status: Cell<Status> }
            #[midnight(witnesses)]
            pub struct EnumStateWitnesses { pub new_status: Status }
            impl EnumStateLedger {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { status: Cell::new(Status::Open) } }
                #[midnight(circuit)]
                pub fn transition(&mut self, witnesses: &EnumStateWitnesses) {
                    self.status.set(witnesses.new_status);
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

/// `Cell<Status>::set(value)` where `Status` is a user enum encoded
/// as the Bytes<1> discriminant.
#[tokio::test]
async fn enum_cell_set_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_enum_state_ir("transition");
    let witnesses = enum_state::EnumStateWitnesses {
        new_status: enum_state::Status::Closed,
    };
    let nocturne_transcript =
        enum_state::transcript::build_transition_transcript(&witnesses);

    // Witness PrivateInput: 1 Fr (discriminant of Closed = 1).
    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(1u8)];
    let preimage =
        canonical_preimage("transition", nocturne_transcript.ops.clone(), private_outputs);

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
        "prove PIs must match ledger PIs for Cell<EnumStatus>::set"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Cell<EnumStatus>::set");
}

// ---------------------------------------------------------------------------
// Match-on-enum: structurally equivalent to the Boolean voting circuit but
// the conditional uses a user enum + match instead of `if witness.value()`.
// Confirms enum-variant patterns lower to nested If with cond_select-zeroed
// pub inputs and that runtime equality goes through `.discriminant()`.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod enum_vote {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Vote {
        For,
        Against,
    }

    #[midnight(ledger)]
    pub struct EnumBallot {
        pub votes_for: Counter,
        pub votes_against: Counter,
    }

    #[midnight(witnesses)]
    pub struct EnumBallotWitnesses {
        pub choice: Vote,
    }

    impl EnumBallot {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                votes_for: Counter::zero(),
                votes_against: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn cast_vote(&mut self, witnesses: &EnumBallotWitnesses) {
            match witnesses.choice {
                Vote::For => {
                    self.votes_for.increment();
                }
                _ => {
                    self.votes_against.increment();
                }
            }
        }
    }
}

fn build_enum_vote_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod enum_vote {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            pub enum Vote { For, Against }
            #[midnight(ledger)]
            pub struct EnumBallot {
                pub votes_for: Counter,
                pub votes_against: Counter,
            }
            #[midnight(witnesses)]
            pub struct EnumBallotWitnesses { pub choice: Vote }
            impl EnumBallot {
                #[midnight(constructor)]
                pub fn new() -> Self {
                    Self { votes_for: Counter::zero(), votes_against: Counter::zero() }
                }
                #[midnight(circuit)]
                pub fn cast_vote(&mut self, witnesses: &EnumBallotWitnesses) {
                    match witnesses.choice {
                        Vote::For => { self.votes_for.increment(); }
                        _ => { self.votes_against.increment(); }
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

/// Mirror of `voting_verifies_with_ledger_shape_pis` but the conditional
/// is driven by a user enum + match, not a Boolean witness + if.
#[tokio::test]
async fn enum_match_vote_verifies_with_ledger_shape_pis() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_enum_vote_ir();
    let witnesses = enum_vote::EnumBallotWitnesses {
        choice: enum_vote::Vote::For,
    };
    let nocturne_transcript = enum_vote::transcript::build_cast_vote_transcript(&witnesses);

    // Vote::For is discriminant 0 → push 0 to private transcript.
    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(0u8)];
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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "prove's PIs must match the on-chain ledger-shape PIs for the \
         enum-match conditional voting circuit"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for enum-match cast_vote");
}

// ---------------------------------------------------------------------------
// Map<Uint<N>, EnumValue>: per-user state tracked as a unit-variant enum.
// Confirms enum-value Map insert composes the Bytes<1> discriminant into
// the value AlignedValue and pushes the discriminant Fr to the private
// transcript in the right slot ordering.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod enum_records {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Status {
        Pending,
        Active,
        Closed,
    }

    #[midnight(ledger)]
    pub struct EnumRecords {
        pub status_of: Map<Uint<64>, Status>,
    }

    #[midnight(witnesses)]
    pub struct EnumRecordsWitnesses {
        pub user_id: Uint<64>,
        pub new_status: Status,
    }

    impl EnumRecords {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                status_of: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn set_status(&mut self, witnesses: &EnumRecordsWitnesses) {
            self.status_of
                .insert(witnesses.user_id, witnesses.new_status);
        }
    }
}

fn build_enum_records_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod enum_records {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            pub enum Status { Pending, Active, Closed }
            #[midnight(ledger)]
            pub struct EnumRecords { status_of: Map<Uint<64>, Status> }
            #[midnight(witnesses)]
            pub struct EnumRecordsWitnesses {
                pub user_id: Uint<64>,
                pub new_status: Status,
            }
            impl EnumRecords {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { status_of: Map::empty() } }
                #[midnight(circuit)]
                pub fn set_status(&mut self, witnesses: &EnumRecordsWitnesses) {
                    self.status_of.insert(witnesses.user_id, witnesses.new_status);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "set_status")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn map_with_enum_value_insert_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_enum_records_ir();
    let witnesses = enum_records::EnumRecordsWitnesses {
        user_id: Uint::<64>::from(11u64),
        new_status: enum_records::Status::Active, // discriminant = 1
    };
    let nocturne_transcript =
        enum_records::transcript::build_set_status_transcript(&witnesses);

    // Private transcript: user_id (Uint<64>) then Status (Bytes<1>).
    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(11u64),
        AlignedValue::from(1u8),
    ];
    let preimage = canonical_preimage(
        "set_status",
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
        "prove's PIs must match the on-chain ledger-shape PIs for \
         Map<Uint<64>, Status>::insert"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Map<Uint<64>, Status>::insert");
}

// ---------------------------------------------------------------------------
// Counter::increment(N) with a const literal N. Mirrors the bare-increment
// counter circuit but uses Addi { immediate: N }. Confirms the IR's
// LoadImm(N) feeds DeclarePubInput consistently with the transcript
// builder's Op::Addi { immediate: N }.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod counter_by_n {
    use super::*;

    #[midnight(ledger)]
    pub struct CounterByN {
        pub count: Counter,
    }

    impl CounterByN {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn bump(&mut self) {
            self.count.increment_by(7);
        }
    }
}

fn build_counter_by_n_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod counter_by_n {
            #[midnight(ledger)]
            pub struct CounterByN { count: Counter }
            impl CounterByN {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn bump(&mut self) { self.count.increment_by(7); }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "bump")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn counter_increment_by_n_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_counter_by_n_ir();
    let nocturne_transcript = counter_by_n::transcript::build_bump_transcript();
    let preimage = canonical_preimage("bump", nocturne_transcript.ops.clone(), vec![]);

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
        "prove's PIs must match the on-chain ledger-shape PIs for \
         Counter::increment(7)"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Counter::increment(7)");
}

// ---------------------------------------------------------------------------
// Constructor initial values: confirm `Cell::new(<expr>)` in the user's
// constructor surfaces through `deploy::initial_state()` instead of the
// previous always-zero default.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod init_values {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Phase {
        Setup,
        Running,
        Finished,
    }

    #[midnight(ledger)]
    pub struct InitState {
        pub limit: Cell<u64>,
        pub phase: Cell<Phase>,
        pub tag: Cell<Bytes<32>>,
        pub seen: Counter,
    }

    impl InitState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                limit: Cell::new(42u64),
                phase: Cell::new(Phase::Running),
                tag: Cell::new(Bytes::<32>::from_slice("nocturne:v1".as_bytes())),
                seen: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn touch(&mut self) {
            self.seen.increment();
        }
    }
}

#[test]
fn constructor_initial_values_flow_into_state_value() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_state::state::StateValue;
    use midnight::runtime::storage::arena::Sp;

    let state = init_values::deploy::initial_state();
    let StateValue::Array(ref fields) = state else {
        panic!("expected StateValue::Array root");
    };
    let collected: Vec<StateValue> = fields.iter().map(|v| (*v).clone()).collect();
    assert_eq!(collected.len(), 4);

    // Field 0: Cell<u64>(42)
    assert_eq!(
        collected[0],
        StateValue::Cell(Sp::new(AlignedValue::from(42u64))),
        "Cell<u64>::new(42) must deploy as the discriminated value, not 0"
    );

    // Field 1: Cell<Phase>(Phase::Running = discriminant 1)
    assert_eq!(
        collected[1],
        StateValue::Cell(Sp::new(AlignedValue::from(1u8))),
        "Cell<Phase>::new(Phase::Running) must deploy the variant's discriminant"
    );

    // Field 2: Cell<Bytes<32>>("nocturne:v1" padded with zeros)
    let expected_tag = midnight::types::Bytes::<32>::from_slice("nocturne:v1".as_bytes());
    assert_eq!(
        collected[2],
        StateValue::Cell(Sp::new(AlignedValue::from(*expected_tag.as_bytes()))),
        "Cell<Bytes<32>>::new(Bytes::from_slice(...)) must deploy the padded bytes"
    );

    // Field 3: Counter starting at 0.
    assert_eq!(
        collected[3],
        StateValue::from(0u64),
        "Counter::zero() must deploy as 0"
    );
}

// ---------------------------------------------------------------------------
// Constructor parameters flow into deploy::initial_state(_).
// ---------------------------------------------------------------------------

#[midnight::contract]
mod parametric_init {
    use super::*;

    #[midnight(ledger)]
    pub struct AdminState {
        pub admin: Cell<Bytes<32>>,
        pub fee_bps: Cell<u64>,
    }

    impl AdminState {
        #[midnight(constructor)]
        pub fn new(admin: Bytes<32>, fee_bps: u64) -> Self {
            Self {
                admin: Cell::new(admin),
                fee_bps: Cell::new(fee_bps),
            }
        }

        #[midnight(circuit)]
        pub fn noop(&mut self) {}
    }
}

#[test]
fn constructor_params_flow_into_initial_state() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_state::state::StateValue;
    use midnight::runtime::storage::arena::Sp;

    let admin = midnight::types::Bytes::<32>::from_slice("admin@example".as_bytes());
    let state = parametric_init::deploy::initial_state(admin.clone(), 250u64);
    let StateValue::Array(ref fields) = state else {
        panic!("expected StateValue::Array");
    };
    let collected: Vec<StateValue> = fields.iter().map(|v| (*v).clone()).collect();
    assert_eq!(collected.len(), 2);

    assert_eq!(
        collected[0],
        StateValue::Cell(Sp::new(AlignedValue::from(*admin.as_bytes()))),
        "constructor's `admin: Bytes<32>` parameter must reach the deployed Cell<Bytes<32>>"
    );
    assert_eq!(
        collected[1],
        StateValue::Cell(Sp::new(AlignedValue::from(250u64))),
        "constructor's `fee_bps: u64` parameter must reach the deployed Cell<u64>"
    );
}

// ---------------------------------------------------------------------------
// Composition: enum + match + assert! + conditional Counter + Cell<u64>.
// Pins on-chain compatibility for a realistic "role-gated counter" pattern
// where the enum drives both an assertion and a match-based mutation.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod role_gated_counter {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Caller {
        Admin,
        Member,
    }

    #[midnight(ledger)]
    pub struct RoleCounter {
        pub admin_ops: Counter,
        pub member_ops: Counter,
    }

    #[midnight(witnesses)]
    pub struct RoleCallerWitnesses {
        pub caller: Caller,
    }

    impl RoleCounter {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                admin_ops: Counter::zero(),
                member_ops: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &RoleCallerWitnesses) {
            match witnesses.caller {
                Caller::Admin => {
                    self.admin_ops.increment_by(3);
                }
                _ => {
                    self.member_ops.increment();
                }
            }
        }
    }
}

fn build_role_counter_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod role_gated_counter {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            pub enum Caller { Admin, Member }
            #[midnight(ledger)]
            pub struct RoleCounter {
                pub admin_ops: Counter,
                pub member_ops: Counter,
            }
            #[midnight(witnesses)]
            pub struct RoleCallerWitnesses { pub caller: Caller }
            impl RoleCounter {
                #[midnight(constructor)]
                pub fn new() -> Self {
                    Self { admin_ops: Counter::zero(), member_ops: Counter::zero() }
                }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &RoleCallerWitnesses) {
                    match witnesses.caller {
                        Caller::Admin => { self.admin_ops.increment_by(3); }
                        _ => { self.member_ops.increment(); }
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
        .find(|c| c.circuit_name == "record")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn role_gated_counter_admin_branch_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_role_counter_ir();
    let witnesses = role_gated_counter::RoleCallerWitnesses {
        caller: role_gated_counter::Caller::Admin, // discriminant 0
    };
    let nocturne_transcript =
        role_gated_counter::transcript::build_record_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(0u8)];
    let preimage =
        canonical_preimage("record", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    // Same Op::Noop interleave the voting test uses — conditional
    // branches splice Noops into the inactive segments.
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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "role-gated counter must produce ledger-shape PIs that match prove PIs"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for role-gated counter (admin branch)");
}

// ---------------------------------------------------------------------------
// `let v = witnesses.x; self.cell.set(v);` previously bound `v` to `()`
// (the let block evaluated to unit). This test pins that the binding
// now carries the real witness value through to the Cell::set call.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod let_witness_roundtrip {
    use super::*;

    #[midnight(ledger)]
    pub struct LetWitnessState {
        pub stored: Cell<Bytes<32>>,
    }

    #[midnight(witnesses)]
    pub struct LetWitnessWitnesses {
        pub incoming: Bytes<32>,
    }

    impl LetWitnessState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                stored: Cell::new(Bytes::<32>::zeroed()),
            }
        }

        #[midnight(circuit)]
        pub fn store(&mut self, witnesses: &LetWitnessWitnesses) {
            let v = witnesses.incoming.clone();
            self.stored.set(v);
        }
    }
}

fn build_let_witness_roundtrip_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod let_witness_roundtrip {
            #[midnight(ledger)]
            pub struct LetWitnessState { stored: Cell<Bytes<32>> }
            #[midnight(witnesses)]
            pub struct LetWitnessWitnesses { pub incoming: Bytes<32> }
            impl LetWitnessState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { stored: Cell::new(Bytes::<32>::zeroed()) } }
                #[midnight(circuit)]
                pub fn store(&mut self, witnesses: &LetWitnessWitnesses) {
                    let v = witnesses.incoming.clone();
                    self.stored.set(v);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "store")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn let_witness_bound_value_reaches_cell_set() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_let_witness_roundtrip_ir();
    let digest = Bytes::<32>::from_slice(b"deadbeefcafebabe0123456789abcdef");
    let witnesses = let_witness_roundtrip::LetWitnessWitnesses {
        incoming: digest.clone(),
    };
    let nocturne_transcript =
        let_witness_roundtrip::transcript::build_store_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> =
        vec![AlignedValue::from(*digest.as_bytes())];
    let preimage =
        canonical_preimage("store", nocturne_transcript.ops.clone(), private_outputs);

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
        "let-bound witness must reach Cell::set with the same digest bytes the witness carries"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for let-bound witness Cell::set");
}

// ---------------------------------------------------------------------------
// `let total = w.a + w.b; cell.set(total);` — witness arithmetic flowing
// into a Cell<Uint<64>> write. Both witnesses must push (in declaration
// order), the arithmetic must evaluate at runtime, and the resulting
// AlignedValue must match what `set` would produce for the raw sum.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod witness_sum {
    use super::*;

    #[midnight(ledger)]
    pub struct SumLedger {
        pub total: Cell<Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct SumWitnesses {
        pub a: Uint<64>,
        pub b: Uint<64>,
    }

    impl SumLedger {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                total: Cell::new(Uint::<64>::from(0u64)),
            }
        }

        #[midnight(circuit)]
        pub fn store_sum(&mut self, witnesses: &SumWitnesses) {
            let s = witnesses.a + witnesses.b;
            self.total.set(s);
        }
    }
}

fn build_witness_sum_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod witness_sum {
            #[midnight(ledger)]
            pub struct SumLedger { total: Cell<Uint<64>> }
            #[midnight(witnesses)]
            pub struct SumWitnesses { pub a: Uint<64>, pub b: Uint<64> }
            impl SumLedger {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { total: Cell::new(Uint::<64>::from(0u64)) } }
                #[midnight(circuit)]
                pub fn store_sum(&mut self, witnesses: &SumWitnesses) {
                    let s = witnesses.a.clone() + witnesses.b.clone();
                    self.total.set(s);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "store_sum")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn witness_arithmetic_let_binding_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_witness_sum_ir();
    let witnesses = witness_sum::SumWitnesses {
        a: Uint::<64>::from(11u64),
        b: Uint::<64>::from(31u64),
    };
    let nocturne_transcript =
        witness_sum::transcript::build_store_sum_transcript(&witnesses);

    // Private inputs in declaration order: a, then b. The Cell::set's
    // pushed value is the sum (42), so the on-chain AlignedValue is u64(42).
    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(11u64),
        AlignedValue::from(31u64),
    ];
    let preimage = canonical_preimage(
        "store_sum",
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
        "witness arithmetic let binding must produce ledger-shape PIs that match prove PIs"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for witness arithmetic let binding");
}

// ---------------------------------------------------------------------------
// `let n = self.counter.value();` — bind a ledger Counter read so the
// downstream Rust code can use the value in subsequent expressions.
// Pins that LedgerAccess::value flows through the let binding.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod counter_read_binding {
    use super::*;

    #[midnight(ledger)]
    pub struct CounterRead {
        pub count: Counter,
    }

    impl CounterRead {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn snapshot(&self) {
            let _n = self.count.value();
        }
    }
}

fn build_counter_read_binding_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod counter_read_binding {
            #[midnight(ledger)]
            pub struct CounterRead { count: Counter }
            impl CounterRead {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn snapshot(&self) {
                    let _n = self.count.value();
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "snapshot")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn counter_value_let_binding_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_counter_read_binding_ir();
    let mut state = counter_read_binding::CounterRead::new();
    state.count.increment_by(5); // make the state non-zero so the read isn't a no-op
    let nocturne_transcript = counter_read_binding::transcript::build_snapshot_transcript(&state);
    let preimage = canonical_preimage("snapshot", nocturne_transcript.ops.clone(), vec![]);

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
        "Counter::value let-binding read must produce ledger-shape PIs that match prove PIs"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Counter::value let-binding read");
}

// ---------------------------------------------------------------------------
// Counter::set(witness): dynamic counter assignment from a witness value.
// Counter shares Cell<u64>'s on-chain shape, so the Push + Push + Ins
// pattern reuses the Cell::set codegen path.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod counter_set {
    use super::*;

    #[midnight(ledger)]
    pub struct CounterSetState {
        pub count: Counter,
    }

    #[midnight(witnesses)]
    pub struct CounterSetWitnesses {
        pub target: Uint<64>,
    }

    impl CounterSetState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn assign(&mut self, witnesses: &CounterSetWitnesses) {
            self.count.set(witnesses.target.value() as u64);
        }
    }
}

fn build_counter_set_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod counter_set {
            #[midnight(ledger)]
            pub struct CounterSetState { count: Counter }
            #[midnight(witnesses)]
            pub struct CounterSetWitnesses { pub target: Uint<64> }
            impl CounterSetState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn assign(&mut self, witnesses: &CounterSetWitnesses) {
                    self.count.set(witnesses.target.value() as u64);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "assign")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn counter_set_from_witness_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_counter_set_ir();
    let witnesses = counter_set::CounterSetWitnesses {
        target: Uint::<64>::from(99u64),
    };
    let nocturne_transcript =
        counter_set::transcript::build_assign_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(99u64)];
    let preimage =
        canonical_preimage("assign", nocturne_transcript.ops.clone(), private_outputs);

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
        "Counter::set(witness) must produce ledger-shape PIs that match prove PIs"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Counter::set(witness)");
}

// ---------------------------------------------------------------------------
// Inline witness arithmetic: `cell.set(w.a + w.b)` without the let binding.
// Pins that `arg_to_runtime_expr`'s BinaryOp arm composes operand value
// expressions correctly, and `generate_op_stmt`'s BinaryOp arm still
// fires the witness pushes from the surrounding context.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod inline_sum {
    use super::*;

    #[midnight(ledger)]
    pub struct InlineSumLedger {
        pub total: Cell<Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct InlineSumWitnesses {
        pub a: Uint<64>,
        pub b: Uint<64>,
    }

    impl InlineSumLedger {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                total: Cell::new(Uint::<64>::from(0u64)),
            }
        }

        #[midnight(circuit)]
        pub fn put(&mut self, witnesses: &InlineSumWitnesses) {
            self.total
                .set(witnesses.a + witnesses.b);
        }
    }
}

fn build_inline_sum_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod inline_sum {
            #[midnight(ledger)]
            pub struct InlineSumLedger { total: Cell<Uint<64>> }
            #[midnight(witnesses)]
            pub struct InlineSumWitnesses { pub a: Uint<64>, pub b: Uint<64> }
            impl InlineSumLedger {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { total: Cell::new(Uint::<64>::from(0u64)) } }
                #[midnight(circuit)]
                pub fn put(&mut self, witnesses: &InlineSumWitnesses) {
                    self.total.set(witnesses.a.clone() + witnesses.b.clone());
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "put")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn inline_witness_arithmetic_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_inline_sum_ir();
    let witnesses = inline_sum::InlineSumWitnesses {
        a: Uint::<64>::from(11u64),
        b: Uint::<64>::from(31u64),
    };
    let nocturne_transcript =
        inline_sum::transcript::build_put_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(11u64),
        AlignedValue::from(31u64),
    ];
    let preimage =
        canonical_preimage("put", nocturne_transcript.ops.clone(), private_outputs);

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
        "inline `cell.set(w.a + w.b)` must produce ledger-shape PIs that match prove PIs"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for inline witness arithmetic");
}

// ---------------------------------------------------------------------------
// `assert!(cond)` in the transcript builder evaluates the condition at
// runtime so a violating witness fails fast before reaching the prover.
// Pins both the success path (transcript builder returns normally) and
// the failure path (assertion panics with the message we emit).
// ---------------------------------------------------------------------------

#[midnight::contract]
mod assert_runtime {
    use super::*;

    #[midnight(ledger)]
    pub struct AssertLedger {
        pub seen: Counter,
    }

    #[midnight(witnesses)]
    pub struct AssertWitnesses {
        pub flag: Boolean,
    }

    impl AssertLedger {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                seen: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn require_flag(&mut self, witnesses: &AssertWitnesses) {
            assert!(witnesses.flag.value(), "flag must be true");
            self.seen.increment();
        }
    }
}

#[test]
fn assert_in_circuit_body_evaluates_at_runtime() {
    // Success path — flag is true, builder returns without panicking.
    let ok = assert_runtime::AssertWitnesses {
        flag: Boolean::from(true),
    };
    let _t = assert_runtime::transcript::build_require_flag_transcript(&ok);
}

// ---------------------------------------------------------------------------
// Homogeneous payload-carrying enum: `enum Action { Mint(Uint<64>), Burn(Uint<64>) }`.
// Wire-encoded as `(Bytes<1>, Uint<64>)` — the upstream `Aligned for (A, B)`
// impl handles the tuple shape. Pins that the discriminant + payload both
// reach the on-chain transcript in the right order.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod payload_enum {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum Action {
        Mint(Uint<64>),
        Burn(Uint<64>),
    }

    #[midnight(ledger)]
    pub struct PayloadEnumLedger {
        pub last: Cell<Action>,
    }

    #[midnight(witnesses)]
    pub struct PayloadEnumWitnesses {
        pub next: Action,
    }

    impl PayloadEnumLedger {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                last: Cell::new(Action::Mint(Uint::<64>::from(0u64))),
            }
        }

        #[midnight(circuit)]
        pub fn record(&mut self, witnesses: &PayloadEnumWitnesses) {
            self.last.set(witnesses.next.clone());
        }
    }
}

fn build_payload_enum_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod payload_enum {
            #[derive(Clone, Debug, PartialEq, Eq, Hash)]
            pub enum Action { Mint(Uint<64>), Burn(Uint<64>) }
            #[midnight(ledger)]
            pub struct PayloadEnumLedger { last: Cell<Action> }
            #[midnight(witnesses)]
            pub struct PayloadEnumWitnesses { pub next: Action }
            impl PayloadEnumLedger {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { last: Cell::new(Action::Mint(Uint::<64>::from(0u64))) } }
                #[midnight(circuit)]
                pub fn record(&mut self, witnesses: &PayloadEnumWitnesses) {
                    self.last.set(witnesses.next.clone());
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "record")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn payload_enum_cell_set_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_payload_enum_ir();
    let witnesses = payload_enum::PayloadEnumWitnesses {
        next: payload_enum::Action::Burn(Uint::<64>::from(99u64)), // discriminant 1, payload 99
    };
    let nocturne_transcript =
        payload_enum::transcript::build_record_transcript(&witnesses);

    // Private inputs: discriminant Fr, then payload Fr.
    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(1u8),
        AlignedValue::from(99u64),
    ];
    let preimage =
        canonical_preimage("record", nocturne_transcript.ops.clone(), private_outputs);

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
        "payload enum Cell::set must produce ledger-shape PIs that match prove PIs"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for payload enum Cell::set");
}

// ---------------------------------------------------------------------------
// Match-on-payload binding: native Rust pattern matching binds the
// homogeneous payload from each variant arm, no synthetic accessor.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod match_payload {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum Action {
        Mint(Uint<64>),
        Burn(Uint<64>),
    }

    #[midnight(ledger)]
    pub struct MintBurn {
        pub minted: Cell<Uint<64>>,
        pub burned: Cell<Uint<64>>,
    }

    #[midnight(witnesses)]
    pub struct MintBurnWitnesses {
        pub action: Action,
    }

    impl MintBurn {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                minted: Cell::new(Uint::<64>::from(0u64)),
                burned: Cell::new(Uint::<64>::from(0u64)),
            }
        }

        #[midnight(circuit)]
        pub fn apply(&mut self, witnesses: &MintBurnWitnesses) {
            match witnesses.action.clone() {
                Action::Mint(amount) => {
                    self.minted.set(amount);
                }
                Action::Burn(amount) => {
                    self.burned.set(amount);
                }
            }
        }
    }
}

fn build_match_payload_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod match_payload {
            #[derive(Clone, Debug, PartialEq, Eq, Hash)]
            pub enum Action { Mint(Uint<64>), Burn(Uint<64>) }
            #[midnight(ledger)]
            pub struct MintBurn {
                pub minted: Cell<Uint<64>>,
                pub burned: Cell<Uint<64>>,
            }
            #[midnight(witnesses)]
            pub struct MintBurnWitnesses { pub action: Action }
            impl MintBurn {
                #[midnight(constructor)]
                pub fn new() -> Self {
                    Self {
                        minted: Cell::new(Uint::<64>::from(0u64)),
                        burned: Cell::new(Uint::<64>::from(0u64)),
                    }
                }
                #[midnight(circuit)]
                pub fn apply(&mut self, witnesses: &MintBurnWitnesses) {
                    match witnesses.action.clone() {
                        Action::Mint(amount) => { self.minted.set(amount); }
                        Action::Burn(amount) => { self.burned.set(amount); }
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
        .find(|c| c.circuit_name == "apply")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn match_on_payload_binding_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::onchain_vm::ops::Op as VmOp;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_match_payload_ir();
    let witnesses = match_payload::MintBurnWitnesses {
        action: match_payload::Action::Burn(Uint::<64>::from(99u64)),
    };
    let nocturne_transcript = match_payload::transcript::build_apply_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![
        AlignedValue::from(1u8),
        AlignedValue::from(99u64),
    ];
    let preimage =
        canonical_preimage("apply", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

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

    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut ledger_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    for op in &on_chain_program {
        op.field_repr(&mut ledger_pis);
    }

    assert_eq!(
        prove_pis, ledger_pis,
        "match-on-payload binding must produce ledger-shape PIs that match prove PIs"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for match-on-payload binding");
}

#[test]
#[should_panic(expected = "midnight-edsl: circuit assertion failed")]
fn assert_in_circuit_body_panics_on_violation() {
    // Failure path — flag is false, builder panics with the assertion
    // message we emit. Catches witness/state violations before the
    // prover wastes work on an impossible proof.
    let bad = assert_runtime::AssertWitnesses {
        flag: Boolean::from(false),
    };
    let _t = assert_runtime::transcript::build_require_flag_transcript(&bad);
}

// ---------------------------------------------------------------------------
// Uint<128> end-to-end. Witness a 128-bit value into a Cell<Uint<128>>.
// Confirms the wire encoding (`Bytes<16>` alignment via upstream
// `impl Aligned for u128`), the `Uint<128>` → `u128` cast path in
// `primitive_cast_for_type`, and the prove + verify round-trip.
// ---------------------------------------------------------------------------

#[midnight::contract]
mod uint128_pipeline {
    use super::*;

    #[midnight(ledger)]
    pub struct U128Ledger {
        pub big: Cell<Uint<128>>,
    }

    #[midnight(witnesses)]
    pub struct U128Witnesses {
        pub w: Uint<128>,
    }

    impl U128Ledger {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                big: Cell::new(Uint::<128>::from(0u64)),
            }
        }

        #[midnight(circuit)]
        pub fn set_big(&mut self, witnesses: &U128Witnesses) {
            self.big.set(witnesses.w);
        }
    }
}

fn build_uint128_pipeline_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod uint128_pipeline {
            #[midnight(ledger)]
            pub struct U128Ledger { big: Cell<Uint<128>> }
            #[midnight(witnesses)]
            pub struct U128Witnesses { pub w: Uint<128> }
            impl U128Ledger {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { big: Cell::new(Uint::<128>::from(0u64)) } }
                #[midnight(circuit)]
                pub fn set_big(&mut self, witnesses: &U128Witnesses) {
                    self.big.set(witnesses.w);
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "set_big")
        .unwrap()
        .ir_source
}

#[tokio::test]
async fn uint128_pipeline_proves_and_verifies() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_uint128_pipeline_ir();
    // A value that wouldn't fit in u64: 2^96 + 7.
    let payload: u128 = (1u128 << 96) + 7;
    let witnesses = uint128_pipeline::U128Witnesses {
        w: Uint::<128>::from(payload),
    };
    let nocturne_transcript = uint128_pipeline::transcript::build_set_big_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(payload)];
    let preimage =
        canonical_preimage("set_big", nocturne_transcript.ops.clone(), private_outputs);

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
        "Cell<Uint<128>>::set(witness) must produce ledger-shape PIs that match prove PIs"
    );

    vk.verify(&PARAMS_VERIFIER, &proof, ledger_pis.into_iter())
        .expect("on-chain verify must succeed for Cell<Uint<128>>::set");
}
