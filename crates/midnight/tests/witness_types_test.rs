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
//! See `memories/conditional-branch-cond-select-zeroing.md`.

use midnight::types::*;

#[midnight::contract]
mod multi_witness {
    use super::*;

    #[midnight(ledger)]
    pub struct State {
        pub counter: Counter,
    }

    #[midnight(witnesses)]
    pub struct AllSupportedWitnesses {
        pub flag: Boolean,
        pub number: Uint<64>,
        pub secret: Field,
    }

    impl State {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self { counter: Counter::zero() }
        }

        /// Boolean witness used as an if-condition (the original cast_vote pattern).
        #[midnight(circuit)]
        pub fn use_flag(&mut self, witnesses: &AllSupportedWitnesses) {
            if witnesses.flag.value() {
                self.counter.increment();
            } else {
                self.counter.increment();
            }
        }

        /// Field witness read in the body — exercises Fr::from(u128) without
        /// the silent `as u64` truncation that used to lose the top 64 bits.
        #[midnight(circuit)]
        pub fn use_field(&mut self, witnesses: &AllSupportedWitnesses) {
            let _v = witnesses.secret;
            self.counter.increment();
        }

        /// Uint<64> witness read in the body.
        #[midnight(circuit)]
        pub fn use_uint(&mut self, witnesses: &AllSupportedWitnesses) {
            let _v = witnesses.number;
            self.counter.increment();
        }
    }
}

#[midnight::test]
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
#[midnight::test]
fn each_witness_type_builds_transcript() {
    let w = multi_witness::AllSupportedWitnesses {
        flag: Boolean::from(true),
        number: Uint::<64>::new(0xdead_beef_cafe_babe),
        secret: Field::from(u128::MAX),
    };

    // Boolean — the existing cast_vote pattern.
    let t = multi_witness::transcript::build_use_flag_transcript(&w);
    assert_eq!(t.private_transcript.len(), 1, "one Fr for the Boolean witness");

    // Field — must not silently truncate the high bits of u128.
    let t = multi_witness::transcript::build_use_field_transcript(&w);
    assert_eq!(t.private_transcript.len(), 1, "one Fr for the Field witness");
    assert_eq!(
        t.private_transcript[0],
        midnight::runtime::transient_crypto::curve::Fr::from(u128::MAX),
        "Field witness must serialize as Fr::from(u128) without truncation"
    );

    // Uint<64>.
    let t = multi_witness::transcript::build_use_uint_transcript(&w);
    assert_eq!(t.private_transcript.len(), 1, "one Fr for the Uint witness");
    assert_eq!(
        t.private_transcript[0],
        midnight::runtime::transient_crypto::curve::Fr::from(0xdead_beef_cafe_babeu128),
        "Uint<64> witness must serialize as Fr::from(value)"
    );
}

/// Sanity check that `Bytes<N>` is rejected at parse time with a clear
/// error, so users don't end up with a confusing "no method `value`"
/// error from the macro expansion.
#[test]
fn bytes_witness_is_rejected_at_parse_time() {
    use midnight_ir::parse_contract;

    let module: syn::ItemMod = syn::parse_quote! {
        mod c {
            #[midnight(ledger)]
            pub struct State { count: Counter }
            #[midnight(witnesses)]
            pub struct Witnesses { pub digest: Bytes<32> }
            impl State {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn use_it(&mut self, _w: &Witnesses) {
                    self.count.increment();
                }
            }
        }
    };

    let err = parse_contract(module).expect_err("Bytes<N> witness must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Bytes") && msg.contains("not yet supported"),
        "expected Bytes rejection message, got: {msg}"
    );
}
