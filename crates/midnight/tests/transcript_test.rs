//! Integration test: verify that the generated transcript builder
//! produces real midnight-ledger Op types.

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
fn test_transcript_produces_real_ops() {
    let result = counter::transcript::build_increment_transcript();

    // Should have 3 ops: Idx, Addi, Ins
    assert_eq!(result.ops.len(), 3, "expected 3 VM ops, got {}", result.ops.len());

    // No witnesses needed for counter increment.
    assert!(result.private_transcript.is_empty());
}
