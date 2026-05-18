//! Integration test: verify that the generated deploy module
//! produces a valid initial StateValue for contract deployment.

use midnight::runtime::onchain_state::state::StateValue;
use midnight::types::*;

#[midnight::contract]
mod counter {
    use super::*;

    #[midnight(ledger)]
    pub struct CounterState {
        count: Counter,
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

#[midnight::test]
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

#[midnight::contract]
mod multi_field {
    use super::*;

    #[midnight(ledger)]
    pub struct State {
        counter: Counter,
        data: Cell<u64>,
        store: Map<u64, u64>,
    }

    impl State {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                counter: Counter::zero(),
                data: Cell::new(0u64),
                store: Map::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn noop(&mut self) {}
    }
}

#[midnight::test]
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
