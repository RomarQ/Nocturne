//! Integration test: verify that the generated deploy module
//! produces a valid initial StateValue for contract deployment.

use nocturne::runtime::onchain_state::state::StateValue;
use nocturne::types::*;

#[nocturne::contract]
mod counter {
    use super::*;

    #[nocturne(ledger)]
    pub struct CounterState {
        count: Counter,
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

#[nocturne::test]
fn test_initial_state_is_array() {
    let state = counter::deploy::initial_state();

    // Initial state should be an Array with one entry (the count field).
    match &state {
        StateValue::Array(arr) => {
            assert_eq!(arr.len(), 1, "should have 1 field");
            println!("✓ Counter initial state has 1 field");
        }
        other => panic!("expected Array, got: {other:?}"),
    }
}

#[nocturne::contract]
mod multi_field {
    use super::*;

    #[nocturne(ledger)]
    pub struct State {
        counter: Counter,
        data: Cell<u64>,
        store: Map<u64, u64>,
    }

    impl State {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                counter: Counter::zero(),
                data: Cell::new(0u64),
                store: Map::empty(),
            }
        }

        #[nocturne(circuit)]
        pub fn noop(&mut self) {}
    }
}

#[nocturne::test]
fn test_multi_field_initial_state() {
    let state = multi_field::deploy::initial_state();

    match &state {
        StateValue::Array(arr) => {
            assert_eq!(arr.len(), 3, "should have 3 fields");
            println!("✓ Multi-field initial state has 3 fields");
        }
        other => panic!("expected Array, got: {other:?}"),
    }
}

#[nocturne::contract]
mod mt_holder {
    use super::*;

    #[nocturne(ledger)]
    pub struct MtHolderState {
        pub entries: MerkleTree<10, Bytes<32>>,
    }

    impl MtHolderState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                entries: MerkleTree::empty(),
            }
        }

        #[nocturne(circuit)]
        pub fn noop(&mut self) {}
    }
}

/// MerkleTree<H, T> fields must initialize to a 2-element Array of
/// `[BoundedMerkleTree<()>(height=H, rehashed), Cell<u64>(0)]` —
/// matching compactc 0.30.0's emission for the same field type.
/// Anything else fails on-chain Idx/Root access at the first call.
#[nocturne::test]
fn test_merkle_tree_field_initial_state() {
    let state = mt_holder::deploy::initial_state();
    let StateValue::Array(top) = &state else {
        panic!("expected top-level Array, got: {state:?}");
    };
    assert_eq!(top.len(), 1, "MtHolderState has one ledger field");

    // The MerkleTree field should be a 2-element Array.
    let field0 = top.iter().next().unwrap();
    let StateValue::Array(mt_inner) = field0.deref() else {
        panic!("expected MerkleTree field to be StateValue::Array, got {field0:?}");
    };
    assert_eq!(
        mt_inner.len(),
        2,
        "MerkleTree<H, T> on-chain shape is [BoundedMerkleTree<()>, Cell<u64>(next_index)]"
    );

    let slot0 = mt_inner.iter().next().unwrap();
    let slot1 = mt_inner.iter().nth(1).unwrap();

    // Slot 0: BoundedMerkleTree with height 10 (matches our `MerkleTree<10, _>`).
    let StateValue::BoundedMerkleTree(tree) = slot0.deref() else {
        panic!("expected slot 0 to be BoundedMerkleTree, got {slot0:?}");
    };
    assert_eq!(tree.height(), 10, "blank tree height must match declared H");
    // The blank-and-rehashed tree has a deterministic root; just confirm
    // root() succeeds (would panic on a non-rehashed tree).
    let _ = tree.root().expect("blank tree must be rehashed");

    // Slot 1: Cell<u64>(0) — the next_index counter.
    let StateValue::Cell(av) = slot1.deref() else {
        panic!("expected slot 1 to be Cell, got {slot1:?}");
    };
    // value_only_field_repr of u64(0) is a single Fr(0).
    use nocturne::runtime::transient_crypto::curve::Fr;
    use nocturne::runtime::transient_crypto::fab::AlignedValueExt;
    let mut frs: Vec<Fr> = Vec::new();
    av.deref().value_only_field_repr(&mut frs);
    assert_eq!(
        frs,
        vec![Fr::from(0u64)],
        "next_index counter must start at 0"
    );
}

use std::ops::Deref;

#[nocturne::contract]
mod prepopulated {
    use super::*;

    #[nocturne(ledger)]
    pub struct PrepopState {
        pub allowed: Set<Uint<64>>,
    }

    impl PrepopState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            let mut allowed = Set::empty();
            allowed.insert(Uint::<64>::new(1));
            Self { allowed }
        }

        #[nocturne(circuit)]
        pub fn noop(&mut self) {}
    }
}

/// Constructor-populated Map/Set/Array fields are not yet encoded into
/// the deploy StateValue — `initial_state` must fail LOUDLY instead of
/// silently deploying an empty container that desyncs from the
/// constructor's view of the state.
#[nocturne::test]
#[should_panic(expected = "must start empty")]
fn constructor_populated_set_panics_at_deploy() {
    let _ = prepopulated::deploy::initial_state();
}
