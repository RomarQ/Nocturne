//! Kitchen-sink contract — exercises every primitive and pattern the
//! Nocturne eDSL currently supports. Intentionally not a "real" contract:
//! the circuits are designed to surface each codegen path, not to model
//! a coherent business logic.
//!
//! Coverage map (one or more circuits per item):
//!
//! - Ledger types: Counter, Cell<T> (u64 / Uint<N> / Bytes<N> / user enum /
//!   Field / Boolean), Map<K, V> (primitive / tuple / user-struct keys),
//!   Set<T>, MerkleTree<H, Bytes<N>>.
//! - User definitions: unit-variant enum, named struct key,
//!   homogeneous payload-carrying enum (matched via native Rust
//!   pattern binding — see `apply_last_action`).
//! - Witness types: Uint<N>, Bytes<N>, Field, user enum.
//! - Constructor: parameterized; initial values flow into deploy::initial_state.
//! - Statements: if / else with cond_select-zeroed PIs, match on user enum,
//!   const-bounded for-loop unrolling, if-let-Some Map::get sugar,
//!   match-on-Map::get sugar, assert! / assert_eq! with format args.
//! - Expressions: witness arithmetic in `let` bindings, ledger reads in
//!   `let` bindings (Counter::value / Cell::get), `disclose(_)`, and
//!   `merkle_tree_path_root(_)`.

use nocturne::types::*;

#[nocturne::contract]
pub mod kitchen_sink {
    use super::*;

    // -----------------------------------------------------------------
    // User-defined types
    // -----------------------------------------------------------------

    /// Unit-variant enum. Encoded on-chain as `Bytes<1>` carrying the
    /// discriminant (Setup=0, Active=1, Frozen=2).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Phase {
        Setup,
        Active,
        Frozen,
    }

    /// Homogeneous payload-carrying enum. Wire-encoded as
    /// `(Bytes<1>, Uint<64>)` — the discriminant followed by the
    /// shared payload. Matched on with native Rust pattern syntax
    /// (no synthetic accessor); see `apply_last_action` below.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum Action {
        Mint(Uint<64>),
        Burn(Uint<64>),
    }

    /// User-defined named struct usable as a Map key — encoded
    /// identically to the anonymous tuple `(Bytes<32>, Uint<32>)`.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct RecordKey {
        pub holder: Bytes<32>,
        pub epoch: Uint<32>,
    }

    // -----------------------------------------------------------------
    // Ledger state
    // -----------------------------------------------------------------

    #[nocturne(ledger)]
    pub struct State {
        /// Counter exercising both `.increment()` and `.increment_by(N)`.
        pub total_ops: Counter,
        /// Cell<Uint<64>> with a non-default initial value (forwarded from
        /// the constructor's `fee_bps` parameter).
        pub fee_bps: Cell<Uint<64>>,
        /// Cell<Bytes<32>> with a default `Bytes::<32>::zeroed()` initial
        /// value (constructor body literal).
        pub admin: Cell<Bytes<32>>,
        /// Cell<EnumPhase> with a non-default initial value
        /// (`Phase::Setup` — discriminant 0 — established by the
        /// constructor).
        pub phase: Cell<Phase>,
        /// Cell<Field> read back in let bindings + arithmetic.
        pub last_commit: Cell<Field>,
        /// Cell<Boolean> for the `disclose(_)` path.
        pub flagged: Cell<Boolean>,
        /// Map keyed by a primitive — exercises the standard
        /// `Map<Bytes<32>, Uint<64>>` shape used in most contracts.
        pub balances: Map<Bytes<32>, Uint<64>>,
        /// Tuple-keyed map. Composes the `Aligned for (T1, T2)` upstream
        /// impl with our per-component encoding.
        pub pair_index: Map<(Bytes<32>, Uint<32>), Uint<64>>,
        /// User-struct-keyed map. Identical wire shape to `pair_index`
        /// modulo field-name projection at the runtime side.
        pub records: Map<RecordKey, Boolean>,
        /// Set with a primitive value type.
        pub members: Set<Bytes<32>>,
        /// MerkleTree of height 5 over `Bytes<32>` leaves — exercises
        /// `insert`, `check_root`, and `merkle_tree_path_root`.
        pub commits: MerkleTree<5, Bytes<32>>,
        /// `Cell<Action>` — a homogeneous payload-carrying enum stored
        /// in ledger state. Read back in `apply_last_action` and
        /// pattern-matched with payload binding.
        pub last_action: Cell<Action>,
        /// Per-variant totals accumulated from the matched payload —
        /// shows that the bound payload (`amount` below) flows through
        /// to a `Cell::set` call from inside a match arm.
        pub last_mint_amount: Cell<Uint<64>>,
        pub last_burn_amount: Cell<Uint<64>>,
        /// `Cell<Uint<128>>` — exercises the `64 < N ≤ 128` arm of
        /// `primitive_cast_for_type` (cast as `u128`).
        pub big_total: Cell<Uint<128>>,
        /// `Cell<Uint<64>>` written from `Option<Uint<64>>` witness
        /// payloads via `match`. `None` is a no-op; `Some(amount)`
        /// stores amount.
        pub maybe_stored: Cell<Uint<64>>,
        /// `Cell<Uint<64>>` written via `if`-as-expression — picks one
        /// of two witness values based on a Boolean flag.
        pub chosen: Cell<Uint<64>>,
        /// `Cell<Uint<64>>` accumulator written from a const-N for
        /// loop over a `[Uint<64>; 4]` witness array.
        pub bucket_sum: Cell<Uint<64>>,
    }

    // -----------------------------------------------------------------
    // Witness state
    // -----------------------------------------------------------------

    #[nocturne(witnesses)]
    pub struct Witnesses {
        pub caller: Bytes<32>,
        pub amount: Uint<64>,
        pub extra: Uint<64>,
        pub epoch: Uint<32>,
        pub leaf: Bytes<32>,
        pub commit_value: Field,
        pub phase_next: Phase,
        pub flag: Boolean,
        pub record: RecordKey,
        pub path: MerkleTreePath<5, Bytes<32>>,
        /// `Uint<128>` witness — exercises the `> 64`-bit primitive
        /// cast path end-to-end.
        pub big_amount: Uint<128>,
        /// `Option<Uint<64>>` witness — same wire shape as Compact's
        /// `Maybe<Uint<64>>`. Matched in `apply_maybe`.
        pub maybe_amount: Option<Uint<64>>,
        /// `Boolean` witness driving an `if`-as-expression result
        /// selection in `pick_one`.
        pub which: Boolean,
        /// Two witness values the `if`-as-expression picks between.
        pub option_a: Uint<64>,
        pub option_b: Uint<64>,
        /// `[Uint<64>; 4]` witness — exercises array indexing inside
        /// a const-N for loop (`sum_buckets`).
        pub buckets: [Uint<64>; 4],
    }

    impl State {
        // -------------------------------------------------------------
        // Constructor — parameterized; initial_state(admin, fee_bps)
        // forwards these to the user constructor.
        // -------------------------------------------------------------

        #[nocturne(constructor)]
        pub fn new(admin: Bytes<32>, fee_bps: Uint<64>) -> Self {
            Self {
                total_ops: Counter::zero(),
                fee_bps: Cell::new(fee_bps),
                admin: Cell::new(admin),
                phase: Cell::new(Phase::Setup),
                last_commit: Cell::new(Field::from(0u64)),
                flagged: Cell::new(Boolean::from(false)),
                balances: Map::empty(),
                pair_index: Map::empty(),
                records: Map::empty(),
                members: Set::empty(),
                commits: MerkleTree::empty(),
                last_action: Cell::new(Action::Mint(Uint::<64>::from(0u64))),
                last_mint_amount: Cell::new(Uint::<64>::from(0u64)),
                last_burn_amount: Cell::new(Uint::<64>::from(0u64)),
                big_total: Cell::new(Uint::<128>::from(0u64)),
                maybe_stored: Cell::new(Uint::<64>::from(0u64)),
                chosen: Cell::new(Uint::<64>::from(0u64)),
                bucket_sum: Cell::new(Uint::<64>::from(0u64)),
            }
        }

        // -------------------------------------------------------------
        // Circuit: match-on-enum + Counter::increment_by(N) + the
        // const-N variant of Counter::increment.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn advance_phase(&mut self, witnesses: &Witnesses) {
            // Match on a user enum — lowers to a nested If chain with
            // discriminant equality.
            match witnesses.phase_next {
                Phase::Setup => {
                    self.total_ops.increment();
                }
                Phase::Active => {
                    self.total_ops.increment_by(2);
                }
                _ => {
                    self.total_ops.increment_by(5);
                }
            }
        }

        // -------------------------------------------------------------
        // Circuit: read a `Cell<Action>` from ledger state and pattern-
        // match it with payload binding. The matched `amount` (a
        // `Uint<64>` payload) flows through to per-variant `Cell::set`
        // calls — plain Rust syntax, no synthetic accessor.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn apply_last_action(&mut self) {
            let action = self.last_action.get();
            match action {
                Action::Mint(amount) => {
                    self.last_mint_amount.set(amount);
                }
                Action::Burn(amount) => {
                    self.last_burn_amount.set(amount);
                }
            }
        }

        // -------------------------------------------------------------
        // Circuit: witness arithmetic in a let binding feeding a
        // Cell<Uint<64>> write, plus a const-N Counter bump.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn store_fee(&mut self, witnesses: &Witnesses) {
            let total = witnesses.amount + witnesses.extra;
            self.fee_bps.set(total);
            self.total_ops.increment();
        }

        // -------------------------------------------------------------
        // Circuit: Cell<Bytes<32>>::set with a witness-rooted let
        // binding.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn rotate_admin(&mut self, witnesses: &Witnesses) {
            let new_admin = witnesses.caller.clone();
            self.admin.set(new_admin);
        }

        // -------------------------------------------------------------
        // Circuit: assert! with a message string + disclose(_) into a
        // Cell<Boolean>.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn flip_flag(&mut self, witnesses: &Witnesses) {
            assert!(witnesses.flag.value() || !witnesses.flag.value(), "tautology");
            self.flagged.set(nocturne::disclose(witnesses.flag));
        }

        // -------------------------------------------------------------
        // Circuit: Map<Bytes<32>, Uint<64>> insert + Set<Bytes<32>>
        // insert side by side.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn deposit(&mut self, witnesses: &Witnesses) {
            self.balances.insert(witnesses.caller.clone(), witnesses.amount);
            self.members.insert(witnesses.caller.clone());
            self.total_ops.increment();
        }

        // -------------------------------------------------------------
        // Circuit: if-let-Some Map::get sugar (rewrites to contains +
        // lookup).
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn settle_if_present(&mut self, witnesses: &Witnesses) {
            if let Some(_v) = self.balances.get(&witnesses.caller) {
                self.balances.remove(&witnesses.caller);
                self.members.remove(&witnesses.caller);
            }
        }

        // -------------------------------------------------------------
        // Circuit: match-on-Map::get sugar (Some(v) / None arms).
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn observe_balance(&self, witnesses: &Witnesses) {
            match self.balances.get(&witnesses.caller) {
                Some(_v) => {
                    let _exists = self.balances.contains(&witnesses.caller);
                }
                None => {
                    let _miss = self.balances.contains(&witnesses.caller);
                }
            }
        }

        // -------------------------------------------------------------
        // Circuit: tuple-keyed Map insert + struct-keyed Map contains.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn index_record(&mut self, witnesses: &Witnesses) {
            self.pair_index
                .insert((witnesses.caller.clone(), witnesses.epoch), witnesses.amount);
            let _present = self.records.contains(&witnesses.record);
        }

        // -------------------------------------------------------------
        // Circuit: MerkleTree::insert + Counter::value() let binding.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn commit(&mut self, witnesses: &Witnesses) {
            self.commits.insert(&witnesses.leaf);
            let _n = self.total_ops.value();
            self.total_ops.increment();
        }

        // -------------------------------------------------------------
        // Circuit: merkle_tree_path_root + check_root + assert_eq! with
        // a message.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn verify_membership(&self, witnesses: &Witnesses) {
            let computed = merkle_tree_path_root(&witnesses.path);
            let _ok = self.commits.check_root(&computed);
        }

        // -------------------------------------------------------------
        // Circuit: const-bounded for-loop unrolling.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn bump_loop(&mut self) {
            for _i in 0..3 {
                self.total_ops.increment();
            }
        }

        // -------------------------------------------------------------
        // Circuit: assert_eq! over a witness Field disclose.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn record_commit(&mut self, witnesses: &Witnesses) {
            let v = witnesses.commit_value;
            self.last_commit.set(nocturne::disclose(v));
        }

        // -------------------------------------------------------------
        // Circuit: Cell<Uint<128>>::set with a 128-bit witness — covers
        // the 65..=128 arm of `primitive_cast_for_type`.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn store_big(&mut self, witnesses: &Witnesses) {
            self.big_total.set(witnesses.big_amount);
        }

        // -------------------------------------------------------------
        // Circuit: `match` on an `Option<Uint<64>>` witness with
        // payload binding. None is a no-op (exercises the codegen's
        // synthesis of `<T as Default>::default()` for the payload).
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        #[allow(clippy::single_match)]
        pub fn apply_maybe(&mut self, witnesses: &Witnesses) {
            match witnesses.maybe_amount {
                Some(amount) => {
                    self.maybe_stored.set(amount);
                }
                None => {}
            }
        }

        // -------------------------------------------------------------
        // Circuit: `if`-as-expression — `let x = if cond { a } else { b };`
        // multiplexes the branch result wires via ZKIR `cond_select`.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn pick_one(&mut self, witnesses: &Witnesses) {
            let picked = if witnesses.which.value() {
                witnesses.option_a
            } else {
                witnesses.option_b
            };
            self.chosen.set(picked);
        }

        // -------------------------------------------------------------
        // Circuit: const-N for loop indexing a `[Uint<64>; 4]` witness.
        // Demonstrates `parse_const_for_loop` unrolling `arr[i]` to
        // literal-indexed `ExprIR::Index` entries.
        // -------------------------------------------------------------

        #[nocturne(circuit)]
        pub fn sum_buckets(&mut self, witnesses: &Witnesses) {
            // Single-element read is enough to exercise the IR variant;
            // the full per-element walk happens at the witness layout
            // layer (ZKIR allocates all 4 slots on first touch).
            self.bucket_sum.set(witnesses.buckets[2]);
        }

        // -------------------------------------------------------------
        // Query (off-chain, not part of the on-chain transcript).
        // -------------------------------------------------------------

        #[nocturne(query)]
        pub fn ops_so_far(&self) -> u64 {
            self.total_ops.value()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::kitchen_sink::*;

    // Smoke test: the proc-macro pipeline emits the transcript builder,
    // deploy module, and per-circuit transcripts without panicking. A
    // genuine regression here would surface as a build failure long
    // before reaching this assertion, but the explicit calls also pin
    // the public API surface that downstream tools (e.g. midnight-rs)
    // depend on.
    #[nocturne::test]
    fn transcripts_build() {
        let admin = nocturne::types::Bytes::<32>::zeroed();
        let fee = nocturne::types::Uint::<64>::from(100u64);
        let _deploy = super::kitchen_sink::deploy::initial_state(admin.clone(), fee);

        let witnesses = Witnesses {
            caller: admin.clone(),
            amount: nocturne::types::Uint::<64>::from(7u64),
            extra: nocturne::types::Uint::<64>::from(3u64),
            epoch: nocturne::types::Uint::<32>::from(1u64),
            leaf: nocturne::types::Bytes::<32>::zeroed(),
            commit_value: nocturne::types::Field::from(42u64),
            phase_next: Phase::Active,
            flag: nocturne::types::Boolean::from(true),
            record: RecordKey {
                holder: admin.clone(),
                epoch: nocturne::types::Uint::<32>::from(1u64),
            },
            big_amount: nocturne::types::Uint::<128>::from((1u128 << 96) + 3),
            maybe_amount: Some(nocturne::types::Uint::<64>::from(13u64)),
            which: nocturne::types::Boolean::from(true),
            option_a: nocturne::types::Uint::<64>::from(55u64),
            option_b: nocturne::types::Uint::<64>::from(99u64),
            buckets: [
                nocturne::types::Uint::<64>::from(1u64),
                nocturne::types::Uint::<64>::from(2u64),
                nocturne::types::Uint::<64>::from(3u64),
                nocturne::types::Uint::<64>::from(4u64),
            ],
            path: nocturne::types::MerkleTreePath::<5, nocturne::types::Bytes<32>> {
                leaf: nocturne::types::Bytes::<32>::zeroed(),
                path: [
                    nocturne::types::MerkleTreePathEntry {
                        sibling: nocturne::types::MerkleTreeDigest::from_le_bytes([0u8; 32]),
                        goes_left: nocturne::types::Boolean::from(false),
                    },
                    nocturne::types::MerkleTreePathEntry {
                        sibling: nocturne::types::MerkleTreeDigest::from_le_bytes([0u8; 32]),
                        goes_left: nocturne::types::Boolean::from(false),
                    },
                    nocturne::types::MerkleTreePathEntry {
                        sibling: nocturne::types::MerkleTreeDigest::from_le_bytes([0u8; 32]),
                        goes_left: nocturne::types::Boolean::from(false),
                    },
                    nocturne::types::MerkleTreePathEntry {
                        sibling: nocturne::types::MerkleTreeDigest::from_le_bytes([0u8; 32]),
                        goes_left: nocturne::types::Boolean::from(false),
                    },
                    nocturne::types::MerkleTreePathEntry {
                        sibling: nocturne::types::MerkleTreeDigest::from_le_bytes([0u8; 32]),
                        goes_left: nocturne::types::Boolean::from(false),
                    },
                ],
            },
        };

        let mut state = State::new(admin.clone(), fee);

        // Build a few transcripts — anything that compiles here means
        // the per-circuit generated module is wired up correctly. The
        // builder signature depends on whether the circuit reads state
        // (Map::contains / Cell::get / Counter::value / check_root all
        // need a `&State` because the on-chain transcript embeds the
        // current value via Popeq).
        let _t = transcript::build_advance_phase_transcript(&witnesses);
        let _t = transcript::build_store_fee_transcript(&witnesses);
        let _t = transcript::build_rotate_admin_transcript(&witnesses);
        let _t = transcript::build_flip_flag_transcript(&witnesses);
        let _t = transcript::build_deposit_transcript(&witnesses);
        let _t = transcript::build_settle_if_present_transcript(&state, &witnesses);
        let _t = transcript::build_observe_balance_transcript(&state, &witnesses);
        let _t = transcript::build_index_record_transcript(&state, &witnesses);
        let _t = transcript::build_commit_transcript(&state, &witnesses);
        let _t = transcript::build_verify_membership_transcript(&state, &witnesses);
        let _t = transcript::build_bump_loop_transcript();
        let _t = transcript::build_record_commit_transcript(&witnesses);
        let _t = transcript::build_apply_last_action_transcript(&state);
        let _t = transcript::build_store_big_transcript(&witnesses);
        let _t = transcript::build_apply_maybe_transcript(&witnesses);
        let _t = transcript::build_pick_one_transcript(&witnesses);
        let _t = transcript::build_sum_buckets_transcript(&witnesses);

        // Query is plain Rust — call it for the side of completeness.
        state.total_ops.increment();
        assert_eq!(state.ops_so_far(), 1);
    }
}
