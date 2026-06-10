//! Integration test: verify that the generated transcript builder
//! produces real midnight-ledger Op types.

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
fn test_transcript_produces_real_ops() {
    let result = counter::transcript::build_increment_transcript();

    // Should have 3 ops: Idx, Addi, Ins
    assert_eq!(
        result.ops.len(),
        3,
        "expected 3 VM ops, got {}",
        result.ops.len()
    );

    // No witnesses needed for counter increment.
    assert!(result.private_transcript.is_empty());
}

/// Generated builder internals use reserved `__nocturne_*` idents, so
/// user bindings named `ops`, `state`, or `private_transcript` can't
/// shadow them. Also: the user's witnesses param is NOT named
/// `witnesses` — the generated builder normalizes its own param name.
#[nocturne::contract]
mod shadowing {
    use super::*;

    #[nocturne(ledger)]
    pub struct ShadowState {
        pub value: Cell<Uint<64>>,
    }

    #[nocturne(witnesses)]
    pub struct ShadowWitnesses {
        pub v: Uint<64>,
    }

    impl ShadowState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                value: Cell::new(Uint::<64>::from(0u64)),
            }
        }

        #[nocturne(circuit)]
        pub fn store(&mut self, w: &ShadowWitnesses) {
            let ops = w.v;
            let state = ops;
            let private_transcript = state;
            self.value.set(private_transcript);
        }
    }
}

#[nocturne::test]
fn user_bindings_named_like_internals_do_not_shadow() {
    let w = shadowing::ShadowWitnesses {
        v: Uint::<64>::new(7),
    };
    let result = shadowing::transcript::build_store_transcript(&w);

    // Cell::set emits 3 ops (Push path, Push value, Ins) and the witness
    // pushes exactly once despite three intermediate bindings.
    assert_eq!(result.ops.len(), 3, "expected 3 VM ops");
    assert_eq!(
        result.private_transcript.len(),
        1,
        "witness field must push exactly once at its first touch"
    );
    assert_eq!(
        result.private_transcript_outputs.len(),
        1,
        "one AlignedValue per witness invocation"
    );
}
