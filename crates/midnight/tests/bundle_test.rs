//! Test the ContractBundle API.

use midnight::types::*;

#[midnight::contract]
mod counter {
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
    }
}

#[midnight::test]
fn test_bundle_creation() {
    let module: syn::ItemMod = syn::parse_quote! {
        mod counter {
            #[midnight(ledger)]
            pub struct CounterState { count: Counter }
            impl CounterState {
                #[midnight(constructor)]
                pub fn new() -> Self { Self { count: Counter::zero() } }
                #[midnight(circuit)]
                pub fn increment(&mut self) { self.count.increment(); }
            }
        }
    };

    let contract = midnight_ir::parse_contract(module).expect("parse");
    let bundle = midnight_codegen::bundle::build_bundle(&contract);

    assert_eq!(bundle.name, "counter");
    assert_eq!(bundle.entry_points, vec!["increment"]);
    assert_eq!(bundle.circuits.len(), 1);
    assert!(bundle.circuits.contains_key("increment"));
    assert!(!bundle.contract_info_json.is_empty());

    // The ZKIR should be valid.
    let ir = &bundle.circuits["increment"];
    assert!(!ir.instructions.is_empty());

    println!(
        "✓ ContractBundle: name={}, entries={:?}, circuits={}",
        bundle.name,
        bundle.entry_points,
        bundle.circuits.len()
    );
}
