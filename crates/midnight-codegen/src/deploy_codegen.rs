//! Deployment codegen: generates Rust code for constructing the initial
//! contract state (StateValue tree) for deployment.

use midnight_ir::ContractIR;
use midnight_ir::LedgerTypeKind;
use proc_macro2::TokenStream;
use quote::quote;

/// Generate the deployment module for a contract.
pub fn generate_deploy_module(contract: &ContractIR) -> TokenStream {
    let field_inits: Vec<TokenStream> = contract
        .ledger
        .fields
        .iter()
        .map(|field| match &field.type_kind {
            LedgerTypeKind::Counter => quote! {
                fields.push(StateValue::from(0u64));
            },
            LedgerTypeKind::Cell => quote! {
                fields.push(StateValue::from(0u64));
            },
            LedgerTypeKind::Map | LedgerTypeKind::Set => quote! {
                fields.push(StateValue::Map(Default::default()));
            },
            LedgerTypeKind::MerkleTree => quote! {
                fields.push(StateValue::Null);
            },
            LedgerTypeKind::Array => quote! {
                fields.push(StateValue::Array(Default::default()));
            },
            LedgerTypeKind::Unknown(_) => quote! {
                fields.push(StateValue::Null);
            },
        })
        .collect();

    let num_fields = contract.ledger.fields.len();

    quote! {
        /// Generated deployment helpers.
        pub mod deploy {
            use midnight::runtime::onchain_state::state::StateValue;

            /// Construct the initial contract state as a StateValue::Array
            /// containing one entry per ledger field.
            pub fn initial_state() -> StateValue {
                let mut fields: Vec<StateValue> = Vec::with_capacity(#num_fields);

                #(#field_inits)*

                StateValue::Array(fields.into_iter().collect())
            }
        }
    }
}
