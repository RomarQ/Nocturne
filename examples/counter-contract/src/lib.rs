use midnight::types::*;

#[midnight::contract]
pub mod counter {
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

        #[midnight(query)]
        pub fn get_count(&self) -> u64 {
            self.count.value()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::counter::*;
    use midnight::types::*;

    #[midnight::test]
    fn test_counter() {
        let mut state = CounterState::new();
        assert_eq!(state.get_count(), 0);
        state.increment();
        state.increment();
        assert_eq!(state.get_count(), 2);
    }

    #[midnight::test]
    fn test_transcript() {
        let t = super::counter::transcript::build_increment_transcript();
        assert_eq!(t.ops.len(), 3); // Idx + Addi + Ins
    }

    #[midnight::test]
    fn test_deploy() {
        let state = super::counter::deploy::initial_state();
        assert!(matches!(
            state,
            midnight::runtime::onchain_state::state::StateValue::Array(_)
        ));
    }
}
