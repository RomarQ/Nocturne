//! Integration test: verify contract-info.json matches Compact's schema.

use midnight::types::*;

#[midnight::contract]
mod ballot {
    use super::*;

    #[midnight(ledger)]
    pub struct Ballot {
        pub votes_for: Counter,
        pub votes_against: Counter,
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
        pub fn register(&mut self, _voter_id: u64) {
            // placeholder
        }

        #[midnight(query)]
        pub fn tally(&self) -> (u64, u64) {
            (self.votes_for.value(), self.votes_against.value())
        }
    }
}

#[midnight::test]
fn test_contract_info_matches_compact_schema() {
    // Generate contract-info for the ballot contract.
    let module: syn::ItemMod = syn::parse_quote! {
        mod ballot {
            #[midnight(ledger)]
            pub struct Ballot {
                pub votes_for: Counter,
                pub votes_against: Counter,
            }

            #[midnight(witnesses)]
            pub struct BallotWitnesses {
                pub vote_choice: Boolean,
            }

            impl Ballot {
                #[midnight(constructor)]
                pub fn new() -> Self {
                    Self { votes_for: Counter::zero(), votes_against: Counter::zero() }
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
                pub fn register(&mut self, voter_id: u64) {}
            }
        }
    };

    let contract = nocturne_ir::parse_contract(module).expect("parse");
    let info = nocturne_metadata::generate_contract_info(&contract);
    let json = serde_json::to_string_pretty(&info).unwrap();
    println!("contract-info.json:\n{json}");

    // Parse as generic JSON and validate structure.
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Required top-level fields.
    assert!(v["compiler-version"].is_string());
    assert!(v["language-version"].is_string());
    assert!(v["runtime-version"].is_string());
    assert!(v["circuits"].is_array());
    assert!(v["witnesses"].is_array());
    assert!(v["contracts"].is_array());

    // Circuits.
    let circuits = v["circuits"].as_array().unwrap();
    assert_eq!(circuits.len(), 2); // cast_vote + register

    let cast_vote = &circuits[0];
    assert_eq!(cast_vote["name"], "cast_vote");
    assert_eq!(cast_vote["pure"], false);
    assert_eq!(cast_vote["proof"], true);
    assert!(cast_vote["result-type"].is_object());

    let register = &circuits[1];
    assert_eq!(register["name"], "register");
    assert_eq!(register["arguments"].as_array().unwrap().len(), 1);
    assert_eq!(register["arguments"][0]["name"], "voter_id");

    // Witnesses.
    let witnesses = v["witnesses"].as_array().unwrap();
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0]["name"], "private$vote_choice");

    println!("✓ contract-info.json matches expected schema");
}
