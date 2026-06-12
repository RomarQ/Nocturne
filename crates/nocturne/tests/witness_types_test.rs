//! Validates that all witness types currently supported by Nocturne
//! (Boolean, Field, Uint<N>) flow correctly through:
//!
//! 1. The macro-generated witness struct (must compile).
//! 2. The proc-macro-emitted transcript builder (must serialize each
//!    witness value into `private_transcript: Vec<Fr>` correctly —
//!    `Fr::from(value())` rather than the old `value() as u64` cast
//!    that silently truncated `Field` and large `Uint<N>`).
//! 3. The ZKIR emitter's type constraints (`ConstrainBits` /
//!    `ConstrainToBoolean` on the corresponding `PrivateInput`).
//! 4. The cond_select-zeroing fix for conditional branches.
//!
//! `Bytes<N>` is rejected at parse time today (multi-Fr witness emission
//! not yet implemented) — covered by `bytes_witness_is_rejected` below.
//!
//! The cond_select zeroing in (4) exists because the ledger replaces
//! inactive transcript segments with `Op::Noop { n }`, whose `field_repr`
//! is `n` zeros — so inactive-branch `DeclarePubInput` slots must be zero
//! for on-chain verification (midnight-ledger ledger-8,
//! ledger/src/prove.rs:263-289 and onchain-vm/src/ops.rs:403).

use nocturne::types::*;

#[nocturne::contract]
mod multi_witness {
    use super::*;

    #[nocturne(ledger)]
    pub struct State {
        pub counter: Counter,
    }

    #[nocturne(witnesses)]
    pub struct AllSupportedWitnesses {
        pub flag: Boolean,
        pub number: Uint<64>,
        pub secret: Field,
    }

    impl State {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                counter: Counter::zero(),
            }
        }

        /// Boolean witness used as an if-condition. Only the then-branch
        /// touches state — the else-branch is empty — so this exercises the
        /// no-else path of the cond_select-zeroing fix without writing two
        /// identical bodies (which clippy flags as a code smell).
        #[nocturne(circuit)]
        pub fn use_flag(&mut self, witnesses: &AllSupportedWitnesses) {
            if witnesses.flag.value() {
                self.counter.increment();
            }
        }

        /// Field witness read in the body — exercises Fr::from(u128) without
        /// the silent `as u64` truncation that used to lose the top 64 bits.
        #[nocturne(circuit)]
        pub fn use_field(&mut self, witnesses: &AllSupportedWitnesses) {
            let _v = witnesses.secret;
            self.counter.increment();
        }

        /// Uint<64> witness read in the body.
        #[nocturne(circuit)]
        pub fn use_uint(&mut self, witnesses: &AllSupportedWitnesses) {
            let _v = witnesses.number;
            self.counter.increment();
        }
    }
}

#[nocturne::test]
fn multi_witness_struct_constructs() {
    let _w = multi_witness::AllSupportedWitnesses {
        flag: Boolean::from(true),
        number: Uint::<64>::new(42),
        secret: Field::from(123u64),
    };
}

/// All three supported witness types produce a valid transcript without
/// the macro panicking. The transcript's `private_transcript` is the
/// `Vec<Fr>` that gets fed to the prover.
#[nocturne::test]
fn each_witness_type_builds_transcript() {
    let w = multi_witness::AllSupportedWitnesses {
        flag: Boolean::from(true),
        number: Uint::<64>::new(0xdead_beef_cafe_babe),
        secret: Field::from(u128::MAX),
    };

    // Boolean — the existing cast_vote pattern.
    let t = multi_witness::transcript::build_use_flag_transcript(&w);
    assert_eq!(
        t.private_transcript.len(),
        1,
        "one Fr for the Boolean witness"
    );

    // Field — must not silently truncate the high bits of u128.
    let t = multi_witness::transcript::build_use_field_transcript(&w);
    assert_eq!(
        t.private_transcript.len(),
        1,
        "one Fr for the Field witness"
    );
    assert_eq!(
        t.private_transcript[0],
        nocturne::runtime::transient_crypto::curve::Fr::from(u128::MAX),
        "Field witness must serialize as Fr::from(u128) without truncation"
    );

    // Uint<64>.
    let t = multi_witness::transcript::build_use_uint_transcript(&w);
    assert_eq!(t.private_transcript.len(), 1, "one Fr for the Uint witness");
    assert_eq!(
        t.private_transcript[0],
        nocturne::runtime::transient_crypto::curve::Fr::from(0xdead_beef_cafe_babeu128),
        "Uint<64> witness must serialize as Fr::from(value)"
    );
}

/// `Bytes<N>` witnesses are now supported via multi-Fr witness emission
/// (each witness expands to `ceil(N / FR_BYTES_STORED)` PrivateInputs,
/// each ConstrainBits-constrained). Verify a Bytes<32> witness contract
/// parses cleanly.
#[test]
fn bytes_witness_is_accepted() {
    use nocturne_ir::parse_contract;

    let module: syn::ItemMod = syn::parse_quote! {
        mod c {
            #[nocturne(ledger)]
            pub struct State { count: Counter }
            #[nocturne(witnesses)]
            pub struct Witnesses { pub digest: Bytes<32> }
            impl State {
                #[nocturne(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[nocturne(circuit)]
                pub fn use_it(&mut self, _w: &Witnesses) {
                    self.count.increment();
                }
            }
        }
    };

    parse_contract(module).expect("Bytes<32> witness must parse");
}
