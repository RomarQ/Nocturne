//! Integration test: verify that the #[nocturne::contract] macro
//! accepts and compiles a counter contract.

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

        #[nocturne(query)]
        pub fn get_count(&self) -> u64 {
            self.count.value()
        }
    }
}

#[nocturne::test]
fn test_counter_works() {
    let mut state = counter::CounterState::new();
    assert_eq!(state.get_count(), 0);
    state.increment();
    assert_eq!(state.get_count(), 1);
    state.increment();
    state.increment();
    assert_eq!(state.get_count(), 3);
}
