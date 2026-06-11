//! Procedural macros for nocturne.
//!
//! Provides `#[nocturne::contract]` and `#[nocturne::test]` attribute macros.

use proc_macro::TokenStream;

/// Marks a module as a Midnight smart contract.
///
/// The macro parses the module into an IR, validates it, generates ZKIR
/// circuits and transcript VM bytecode, and writes artifacts to the
/// `target/nocturne/` directory.
///
/// The original module is returned with midnight attributes stripped
/// so that `cargo test` works in test mode without proof generation.
#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let module: syn::ItemMod = match syn::parse(item) {
        Ok(m) => m,
        Err(e) => return e.to_compile_error().into(),
    };

    match nocturne_ir::parse_contract(module.clone()) {
        Ok(contract_ir) => {
            // Generate all artifacts (ZKIR, VM, metadata). Circuit
            // emission errors are hard compile errors — NOT warnings:
            // a silently incomplete circuit can verify proofs that
            // enforce less than the contract source says.
            let artifacts = match nocturne_codegen::codegen::generate_artifacts(&contract_ir) {
                Ok(artifacts) => artifacts,
                Err(errors) => {
                    // The emitter can record the same message more than
                    // once for a single construct (e.g. the return-
                    // position check). Each `compile_error!` is one
                    // diagnostic, so dedup here — keeping first-
                    // occurrence order — to surface each distinct
                    // message exactly once.
                    let mut seen = std::collections::HashSet::new();
                    let error_tokens: Vec<proc_macro2::TokenStream> = errors
                        .iter()
                        .filter(|msg| seen.insert(msg.as_str()))
                        .map(|msg| {
                            let msg = format!("nocturne: {msg}");
                            quote::quote! { compile_error!(#msg); }
                        })
                        .collect();
                    let cleaned = strip_midnight_attrs_from_module(module);
                    return quote::quote! {
                        #cleaned
                        #(#error_tokens)*
                    }
                    .into();
                }
            };

            // Write artifacts to the target/nocturne/ directory.
            let contract_name = contract_ir.name.to_string();
            let artifact_dir = find_artifact_dir(&contract_name);
            if let Err(e) = write_artifacts(&artifact_dir, &artifacts) {
                eprintln!(
                    "nocturne: warning: failed to write artifacts to {}: {e}",
                    artifact_dir.display()
                );
            }

            // Generate transcript builder and deployment modules.
            let transcript_mod =
                nocturne_codegen::transcript_codegen::generate_transcript_module(&contract_ir);
            let deploy_mod = nocturne_codegen::deploy_codegen::generate_deploy_module(&contract_ir);
            let enum_helpers_tokens =
                nocturne_codegen::enum_helpers::generate_enum_helpers(&contract_ir);

            // Return the module with midnight attributes stripped +
            // generated modules injected. `#[allow(dead_code)]` on the module
            // suppresses warnings for contract structs/methods that are only
            // referenced by the generated transcript/deploy code paths.
            let mut cleaned = strip_midnight_attrs_from_module(module);
            if let Some((brace, ref mut items)) = cleaned.content {
                // Enum helpers go in first as raw items
                // (impl blocks) so the rest of the generated code
                // can call `.discriminant()` on user enum values.
                let helper_items: Vec<syn::Item> = syn::parse2::<syn::File>(enum_helpers_tokens)
                    .map(|f| f.items)
                    .unwrap_or_default();
                for item in helper_items {
                    items.push(item);
                }
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
        Err(diagnostics) => {
            // Emit EVERY collected diagnostic, not just the first —
            // the user fixes all of them in one build instead of
            // playing whack-a-mole.
            let errors = diagnostics.to_compile_errors();
            let cleaned = strip_midnight_attrs_from_module(module);
            let output = quote::quote! {
                #cleaned
                #errors
            };
            output.into()
        }
    }
}

/// Marks a contract test function.
///
/// Currently equivalent to `#[test]` — it adds no behavior of its own.
/// Reserved for future environment setup (e.g. wiring up a simulated
/// Midnight ledger before the test body runs).
#[proc_macro_attribute]
pub fn test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item: proc_macro2::TokenStream = item.into();
    let output = quote::quote! {
        #[test]
        #item
    };
    output.into()
}

/// Strip all `#[nocturne(...)]` attributes from a module's items.
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
            // Also strip field-level `#[nocturne(...)]` attributes
            // (e.g. `#[nocturne(private)]` on a ledger field). Without
            // this they'd leak into the user-visible struct and Rust
            // would reject the unknown `nocturne` tool path.
            if let syn::Fields::Named(ref mut named) = s.fields {
                for field in named.named.iter_mut() {
                    field.attrs.retain(|a| !is_midnight_attr(a));
                }
            }
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
    attr.path().is_ident("nocturne")
}

/// `target/nocturne/<crate>/<contract>/` — keyed by `CARGO_CRATE_NAME`
/// *and* the contract module name. The crate level matters: every
/// compilation target gets a distinct `CARGO_CRATE_NAME` (integration
/// tests get the test file's name), so seven test crates that all
/// define `mod counter` with different circuit sets no longer clobber
/// each other's artifacts during parallel compilation.
fn find_artifact_dir(contract_name: &str) -> std::path::PathBuf {
    // Try CARGO_TARGET_DIR, then OUT_DIR, then default to ./target.
    // The bare-"target" fallback is relative, so it resolves against
    // rustc's CWD — under cargo that's the workspace root, which is
    // where ./target lives.
    let target = std::env::var("CARGO_TARGET_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("OUT_DIR")
                .ok()
                .and_then(|d| workspace_target_from_out_dir(std::path::Path::new(&d)))
        })
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    let crate_name =
        std::env::var("CARGO_CRATE_NAME").unwrap_or_else(|_| "unknown_crate".to_string());
    target.join("nocturne").join(crate_name).join(contract_name)
}

/// Ascend from `OUT_DIR` (`<target>/<profile>/build/<crate>-<hash>/out`)
/// to the enclosing cargo target directory. Structural, not a fixed
/// `nth(4)` hop: a renamed target dir (`CARGO_TARGET_DIR=mytarget`) or
/// a custom layout still resolves, because cargo drops a `CACHEDIR.TAG`
/// marker at the target dir root. The name check is the fast path for
/// the conventional `target/` name; the marker check covers the rest.
fn workspace_target_from_out_dir(out_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    out_dir
        .ancestors()
        .find(|a| {
            a.file_name().map(|n| n == "target").unwrap_or(false)
                || a.join("CACHEDIR.TAG").is_file()
        })
        .map(std::path::Path::to_path_buf)
}

fn write_artifacts(
    dir: &std::path::Path,
    artifacts: &nocturne_codegen::codegen::ContractArtifacts,
) -> std::io::Result<()> {
    let zkir_dir = dir.join("zkir");
    let compiler_dir = dir.join("compiler");

    std::fs::create_dir_all(&zkir_dir)?;
    std::fs::create_dir_all(&compiler_dir)?;

    // Write ZKIR circuits (one per circuit function).
    // IrSource::load() expects a "version" field, so we wrap the serialization.
    let mut current_files = std::collections::HashSet::new();
    for circuit in &artifacts.zkir.circuits {
        let mut value = serde_json::to_value(&circuit.ir_source).map_err(std::io::Error::other)?;
        if let serde_json::Value::Object(ref mut map) = value {
            let (major, minor) = nocturne_codegen::zkir_emitter::ZKIR_VERSION;
            map.insert(
                "version".to_string(),
                serde_json::json!({ "major": major, "minor": minor }),
            );
        }
        let json = serde_json::to_string_pretty(&value).map_err(std::io::Error::other)?;
        let file_name = format!("{}.zkir", circuit.circuit_name);
        write_if_changed(&zkir_dir.join(&file_name), json.as_bytes())?;
        current_files.insert(file_name);
    }

    // Prune orphans: a renamed or deleted circuit must not leave its
    // old `.zkir` behind — `cargo nocturne keygen` walks the directory
    // and would happily keygen a circuit that no longer exists. Also
    // sweep `*.tmp<pid>` leftovers: a rustc that crashed between the
    // `write` and `rename` in `write_if_changed` leaves its temp file
    // behind forever otherwise. (A live concurrent writer's temp file
    // could in principle be swept in the microseconds between its
    // write and rename — the loser's rename fails, it prints the
    // write-failure warning, and the next build rewrites the artifact.)
    if let Ok(entries) = std::fs::read_dir(&zkir_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_orphan_zkir = name.ends_with(".zkir") && !current_files.contains(&name);
            if (is_orphan_zkir || is_stale_tmp(&name))
                && let Err(e) = std::fs::remove_file(entry.path())
            {
                eprintln!(
                    "nocturne: warning: failed to remove stale artifact {}: {e}",
                    entry.path().display()
                );
            }
        }
    }

    // Write contract metadata.
    write_if_changed(
        &compiler_dir.join("contract-info.json"),
        artifacts.contract_info_json.as_bytes(),
    )?;

    Ok(())
}

/// True for `write_if_changed` temp names (`<file>.tmp<pid>`). These
/// only persist when a writer died between `write` and `rename` — our
/// own temp files are always renamed away before the prune loop runs,
/// so anything matching here is a leftover from a crashed process.
fn is_stale_tmp(name: &str) -> bool {
    let Some(idx) = name.rfind(".tmp") else {
        return false;
    };
    let pid_suffix = &name[idx + ".tmp".len()..];
    !pid_suffix.is_empty() && pid_suffix.bytes().all(|b| b.is_ascii_digit())
}

/// Write `content` to `path` only when the existing content differs.
/// Stops the proc macro from touching `.zkir` and `contract-info.json`
/// on every build — without this, downstream tools that key off file
/// mtimes (e.g. `cargo nocturne build`'s "is this circuit's keygen
/// stale?" check) would re-run on every invocation even when nothing
/// actually changed.
///
/// The write itself is atomic: content goes to a temp file in the same
/// directory and is `rename`d over the destination, so a reader never
/// observes a half-written artifact even if two rustc processes race.
fn write_if_changed(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    if let Ok(existing) = std::fs::read(path)
        && existing == content
    {
        return Ok(());
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("artifact path has no file name"))?
        .to_string_lossy()
        .into_owned();
    // Pid suffix keeps concurrent writers (parallel rustc invocations)
    // from stomping each other's temp file before the rename.
    let tmp = path.with_file_name(format!("{file_name}.tmp{}", std::process::id()));
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::{is_stale_tmp, workspace_target_from_out_dir};
    use std::path::{Path, PathBuf};

    #[test]
    fn out_dir_walk_finds_conventional_target_by_name() {
        let out = Path::new("/ws/target/debug/build/my-crate-abc123/out");
        assert_eq!(
            workspace_target_from_out_dir(out),
            Some(PathBuf::from("/ws/target"))
        );
    }

    #[test]
    fn out_dir_walk_handles_cross_compile_depth() {
        // Cross-compiled OUT_DIR has an extra <triple> component:
        // <target>/<triple>/<profile>/build/<crate>-<hash>/out. The
        // old fixed `ancestors().nth(4)` hop lands on the <triple>
        // dir here, so this fixture only passes with the structural
        // walk — guard that the fixture actually discriminates.
        let out = Path::new("/ws/target/aarch64-unknown-linux-gnu/debug/build/my-crate-abc123/out");
        assert_ne!(
            out.ancestors().nth(4),
            Some(Path::new("/ws/target")),
            "fixture no longer discriminates against the old fixed-depth logic"
        );
        assert_eq!(
            workspace_target_from_out_dir(out),
            Some(PathBuf::from("/ws/target"))
        );
    }

    #[test]
    fn stale_tmp_matches_pid_suffixed_names_only() {
        assert!(is_stale_tmp("increment.zkir.tmp12345"));
        assert!(is_stale_tmp("contract-info.json.tmp7"));
        // Real artifacts and near-misses must survive the sweep.
        assert!(!is_stale_tmp("increment.zkir"));
        assert!(!is_stale_tmp("increment.tmp")); // no pid digits
        assert!(!is_stale_tmp("increment.tmpfile")); // non-digit suffix
        assert!(!is_stale_tmp("increment.tmp12a")); // mixed suffix
    }

    #[test]
    fn out_dir_walk_finds_renamed_target_via_cachedir_tag() {
        // A renamed target dir has no "target" path component; the walk
        // must fall back to cargo's CACHEDIR.TAG marker.
        let root = std::env::temp_dir().join(format!(
            "nocturne-macro-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let target = root.join("mytarget");
        let out = target.join("debug/build/my-crate-abc123/out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55",
        )
        .unwrap();

        assert_eq!(workspace_target_from_out_dir(&out), Some(target));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn out_dir_walk_returns_none_when_unrecognizable() {
        assert_eq!(
            workspace_target_from_out_dir(Path::new("/nonexistent/a/b/c")),
            None
        );
    }
}
