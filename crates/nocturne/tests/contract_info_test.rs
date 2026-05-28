//! Integration test: verify contract-info.json matches Compact's schema.

use nocturne::types::*;

#[nocturne::contract]
mod ballot {
    use super::*;

    #[nocturne(ledger)]
    pub struct Ballot {
        pub votes_for: Counter,
        pub votes_against: Counter,
    }

    #[nocturne(witnesses)]
    pub struct BallotWitnesses {
        pub vote_choice: Boolean,
    }

    impl Ballot {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                votes_for: Counter::zero(),
                votes_against: Counter::zero(),
            }
        }

        #[nocturne(circuit)]
        pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
            if witnesses.vote_choice.value() {
                self.votes_for.increment();
            } else {
                self.votes_against.increment();
            }
        }

        #[nocturne(circuit)]
        pub fn register(&mut self, _voter_id: u64) {
            // placeholder
        }

        #[nocturne(query)]
        pub fn tally(&self) -> (u64, u64) {
            (self.votes_for.value(), self.votes_against.value())
        }
    }
}

#[nocturne::test]
fn test_contract_info_matches_compact_schema() {
    // Generate contract-info for the ballot contract.
    let module: syn::ItemMod = syn::parse_quote! {
        mod ballot {
            #[nocturne(ledger)]
            pub struct Ballot {
                pub votes_for: Counter,
                pub votes_against: Counter,
            }

            #[nocturne(witnesses)]
            pub struct BallotWitnesses {
                pub vote_choice: Boolean,
            }

            impl Ballot {
                #[nocturne(constructor)]
                pub fn new() -> Self {
                    Self { votes_for: Counter::zero(), votes_against: Counter::zero() }
                }

                #[nocturne(circuit)]
                pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
                    if witnesses.vote_choice.value() {
                        self.votes_for.increment();
                    } else {
                        self.votes_against.increment();
                    }
                }

                #[nocturne(circuit)]
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

    // Ledger fields: ballot has two Counters, both default-exported.
    let ledger = v["ledger"]
        .as_array()
        .expect("ledger[] in contract-info.json");
    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger[0]["name"], "votes_for");
    assert_eq!(ledger[0]["index"], 0);
    assert_eq!(ledger[0]["exported"], true);
    assert_eq!(ledger[1]["name"], "votes_against");
    assert_eq!(ledger[1]["index"], 1);
    assert_eq!(ledger[1]["exported"], true);

    println!("✓ contract-info.json matches expected schema");
}

#[nocturne::test]
fn private_marker_flips_exported_in_contract_info() {
    // Per-field opt-out via `#[nocturne(private)]`. Other fields stay
    // `exported: true` by default.
    let module: syn::ItemMod = syn::parse_quote! {
        mod mixed_ledger {
            #[nocturne(ledger)]
            pub struct State {
                pub counter: Counter,
                #[nocturne(private)]
                pub secret: Cell<Uint<64>>,
                pub public_flag: Cell<Boolean>,
            }
            impl State {
                #[nocturne(constructor)]
                pub fn new() -> Self {
                    Self {
                        counter: Counter::zero(),
                        secret: Cell::new(Uint::<64>::from(0u64)),
                        public_flag: Cell::new(Boolean::from(false)),
                    }
                }
                #[nocturne(circuit)]
                pub fn bump(&mut self) { self.counter.increment(); }
            }
        }
    };

    let contract = nocturne_ir::parse_contract(module).expect("parse");
    let info = nocturne_metadata::generate_contract_info(&contract);
    let v = serde_json::to_value(&info).unwrap();

    let ledger = v["ledger"].as_array().unwrap();
    assert_eq!(ledger.len(), 3);
    assert_eq!(ledger[0]["name"], "counter");
    assert_eq!(ledger[0]["exported"], true);
    assert_eq!(ledger[1]["name"], "secret");
    assert_eq!(ledger[1]["exported"], false);
    assert_eq!(ledger[2]["name"], "public_flag");
    assert_eq!(ledger[2]["exported"], true);
}
