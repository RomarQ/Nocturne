use nocturne::types::*;

#[nocturne::contract]
pub mod counter {
    use super::*;

    #[nocturne(ledger)]
    pub struct CounterState {
        pub count: Counter,
    }

    impl Default for CounterState {
        fn default() -> Self {
            Self::new()
        }
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

#[cfg(test)]
mod tests {
    use super::counter::*;

    #[nocturne::test]
    fn test_counter() {
        let mut state = CounterState::new();
        assert_eq!(state.get_count(), 0);
        state.increment();
        state.increment();
        assert_eq!(state.get_count(), 2);
    }

    #[nocturne::test]
    fn test_transcript() {
        let t = super::counter::transcript::build_increment_transcript();
        assert_eq!(t.ops.len(), 3); // Idx + Addi + Ins
    }

    #[nocturne::test]
    fn test_deploy() {
        let state = super::counter::deploy::initial_state();
        assert!(matches!(
            state,
            nocturne::runtime::onchain_state::state::StateValue::Array(_)
        ));
    }
}
