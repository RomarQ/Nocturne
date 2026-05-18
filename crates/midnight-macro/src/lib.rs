//! Procedural macros for midnight-edsl.
//!
//! Provides `#[midnight::contract]` and `#[midnight::test]` attribute macros.

use proc_macro::TokenStream;

/// Marks a module as a Midnight smart contract.
///
/// The macro parses the module into an IR, validates it, generates ZKIR
/// circuits and transcript VM bytecode, and writes artifacts to the
/// `target/midnight/` directory.
///
/// The original module is returned with midnight attributes stripped
/// so that `cargo test` works in test mode without proof generation.
#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let module: syn::ItemMod = match syn::parse(item) {
        Ok(m) => m,
        Err(e) => return e.to_compile_error().into(),
    };

    match midnight_ir::parse_contract(module.clone()) {
        Ok(contract_ir) => {
            // Generate all artifacts (ZKIR, VM, metadata).
            let artifacts = midnight_codegen::codegen::generate_artifacts(&contract_ir);

            // Write artifacts to the target/midnight/ directory.
            let contract_name = contract_ir.name.to_string();
            let artifact_dir = find_artifact_dir(&contract_name);
            if let Err(e) = write_artifacts(&artifact_dir, &artifacts) {
                eprintln!(
                    "midnight-edsl: warning: failed to write artifacts to {}: {e}",
                    artifact_dir.display()
                );
            }

            // Generate transcript builder and deployment modules.
            let transcript_mod =
                midnight_codegen::transcript_codegen::generate_transcript_module(&contract_ir);
            let deploy_mod = midnight_codegen::deploy_codegen::generate_deploy_module(&contract_ir);

            // Return the module with midnight attributes stripped +
            // generated modules injected. `#[allow(dead_code)]` on the module
            // suppresses warnings for contract structs/methods that are only
            // referenced by the generated transcript/deploy code paths.
            let mut cleaned = strip_midnight_attrs_from_module(module);
            if let Some((brace, ref mut items)) = cleaned.content {
                items.push(syn::parse2(transcript_mod).expect("generated transcript module"));
                items.push(syn::parse2(deploy_mod).expect("generated deploy module"));
                cleaned.content = Some((brace, std::mem::take(items)));
            }
            quote::quote! {
                #[allow(dead_code)]
                #cleaned
            }
            .into()
        }
        Err(e) => {
            let error = e.to_compile_error();
            let cleaned = strip_midnight_attrs_from_module(module);
            let output = quote::quote! {
                #cleaned
                #error
            };
            output.into()
        }
    }
}

/// Sets up a simulated Midnight environment for unit testing.
#[proc_macro_attribute]
pub fn test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item: proc_macro2::TokenStream = item.into();
    let output = quote::quote! {
        #[test]
        #item
    };
    output.into()
}

/// Strip all `#[midnight(...)]` attributes from a module's items.
fn strip_midnight_attrs_from_module(mut module: syn::ItemMod) -> syn::ItemMod {
    if let Some((brace, ref mut items)) = module.content {
        let cleaned_items: Vec<syn::Item> = items.drain(..).map(strip_item_attrs).collect();
        module.content = Some((brace, cleaned_items));
    }
    // Also strip attrs from the module itself.
    module.attrs.retain(|a| !is_midnight_attr(a));
    module
}

fn strip_item_attrs(item: syn::Item) -> syn::Item {
    match item {
        syn::Item::Struct(mut s) => {
            s.attrs.retain(|a| !is_midnight_attr(a));
            syn::Item::Struct(s)
        }
        syn::Item::Impl(mut imp) => {
            imp.attrs.retain(|a| !is_midnight_attr(a));
            imp.items = imp
                .items
                .into_iter()
                .map(|item| match item {
                    syn::ImplItem::Fn(mut f) => {
                        f.attrs.retain(|a| !is_midnight_attr(a));
                        syn::ImplItem::Fn(f)
                    }
                    other => other,
                })
                .collect();
            syn::Item::Impl(imp)
        }
        syn::Item::Enum(mut e) => {
            e.attrs.retain(|a| !is_midnight_attr(a));
            syn::Item::Enum(e)
        }
        other => other,
    }
}

fn is_midnight_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("midnight")
}

fn find_artifact_dir(contract_name: &str) -> std::path::PathBuf {
    // Try CARGO_TARGET_DIR, then OUT_DIR, then default to ./target.
    let target = std::env::var("CARGO_TARGET_DIR")
        .or_else(|_| {
            std::env::var("OUT_DIR").map(|d| {
                // OUT_DIR is like target/debug/build/<crate>/out -- walk up to target/
                let p = std::path::PathBuf::from(d);
                p.ancestors()
                    .nth(4)
                    .unwrap_or(&p)
                    .to_path_buf()
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .unwrap_or_else(|_| "target".to_string());
    std::path::PathBuf::from(target)
        .join("midnight")
        .join(contract_name)
}

fn write_artifacts(
    dir: &std::path::Path,
    artifacts: &midnight_codegen::codegen::ContractArtifacts,
) -> std::io::Result<()> {
    let zkir_dir = dir.join("zkir");
    let compiler_dir = dir.join("compiler");

    std::fs::create_dir_all(&zkir_dir)?;
    std::fs::create_dir_all(&compiler_dir)?;

    // Write ZKIR circuits (one per circuit function).
    // IrSource::load() expects a "version" field, so we wrap the serialization.
    for circuit in &artifacts.zkir.circuits {
        let mut value = serde_json::to_value(&circuit.ir_source).map_err(std::io::Error::other)?;
        if let serde_json::Value::Object(ref mut map) = value {
            map.insert(
                "version".to_string(),
                serde_json::json!({ "major": 2, "minor": 0 }),
            );
        }
        let json = serde_json::to_string_pretty(&value).map_err(std::io::Error::other)?;
        std::fs::write(
            zkir_dir.join(format!("{}.zkir", circuit.circuit_name)),
            json,
        )?;
    }

    // Write contract metadata.
    std::fs::write(
        compiler_dir.join("contract-info.json"),
        &artifacts.contract_info_json,
    )?;

    Ok(())
}
