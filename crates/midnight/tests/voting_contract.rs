//! Integration test: a more complex contract with witnesses, if/else,
//! and multiple circuit functions.

use midnight::types::*;

#[midnight::contract]
mod ballot {
    use super::*;

    #[midnight(ledger)]
    pub struct Ballot {
        votes_for: Counter,
        votes_against: Counter,
        has_ended: Cell<bool>,
    }

    #[midnight(witnesses)]
    pub struct BallotWitnesses {
        pub vote_choice: Boolean,
    }

    impl Ballot {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                votes_for: Counter::zero(),
                votes_against: Counter::zero(),
                has_ended: Cell::new(false),
            }
        }

        #[midnight(circuit)]
        pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
            if witnesses.vote_choice.value() {
                self.votes_for.increment();
            } else {
                self.votes_against.increment();
            }
        }

        #[midnight(circuit)]
        pub fn end_ballot(&mut self) {
            self.has_ended.set(true);
        }

        #[midnight(query)]
        pub fn get_tally(&self) -> (u64, u64) {
            (self.votes_for.value(), self.votes_against.value())
        }

        #[midnight(query)]
        pub fn is_ended(&self) -> bool {
            self.has_ended.get()
        }
    }
}

#[midnight::test]
fn test_voting_flow() {
    let mut state = ballot::Ballot::new();

    // Vote yes.
    let yes_witness = ballot::BallotWitnesses {
        vote_choice: Boolean::from(true),
    };
    state.cast_vote(&yes_witness);

    // Vote no.
    let no_witness = ballot::BallotWitnesses {
        vote_choice: Boolean::from(false),
    };
    state.cast_vote(&no_witness);

    // Vote yes again.
    state.cast_vote(&yes_witness);

    let (yes, no) = state.get_tally();
    assert_eq!(yes, 2);
    assert_eq!(no, 1);

    // End ballot.
    assert!(!state.is_ended());
    state.end_ballot();
    assert!(state.is_ended());
}
