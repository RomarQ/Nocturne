//! Integration test: verify that the #[midnight::contract] macro
//! accepts and compiles a counter contract.

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

        #[midnight(query)]
        pub fn get_count(&self) -> u64 {
            self.count.value()
        }
    }
}

#[midnight::test]
fn test_counter_works() {
    let mut state = counter::CounterState::new();
    assert_eq!(state.get_count(), 0);
    state.increment();
    assert_eq!(state.get_count(), 1);
    state.increment();
    state.increment();
    assert_eq!(state.get_count(), 3);
}
