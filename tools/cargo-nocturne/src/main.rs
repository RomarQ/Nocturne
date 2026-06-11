use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // When invoked as `cargo nocturne`, cargo passes "nocturne" as argv[1].
    let subcommand = if args.get(1).map(|s| s.as_str()) == Some("nocturne") {
        args.get(2).map(|s| s.as_str())
    } else {
        args.get(1).map(|s| s.as_str())
    };

    match subcommand {
        Some("build") => cmd_build(),
        Some("keygen") => cmd_keygen(),
        Some("test") => cmd_test(),
        Some("deploy") => {
            eprintln!("cargo-nocturne: deploy not yet implemented");
            std::process::exit(1);
        }
        Some(other) => {
            eprintln!("cargo-nocturne: unknown subcommand '{other}'");
            std::process::exit(1);
        }
        None => print_usage(),
    }
}

fn print_usage() {
    println!("cargo-nocturne: Midnight smart contract build tool");
    println!();
    println!("Usage: cargo nocturne <command>");
    println!();
    println!("Commands:");
    println!("  build    Compile contract, emit ZKIR + contract-info.json");
    println!("  keygen   Generate prover/verifier keys from ZKIR files");
    println!("  test     Run contract tests");
    println!("  deploy   Deploy contract to a Midnight node");
}

/// Run `cargo build`, list emitted artifacts, then keygen any circuit
/// whose `.prover`/`.verifier` are missing or older than its `.zkir`.
/// Existing keys are left untouched — fast iteration doesn't re-pay
/// the keygen cost on every build.
fn cmd_build() {
    println!("Building contract...");

    let status = Command::new("cargo")
        .arg("build")
        .status()
        .expect("failed to run cargo build");

    if !status.success() {
        eprintln!("cargo build failed");
        std::process::exit(1);
    }

    let target_dir = find_target_dir();
    let nocturne_dir = target_dir.join("nocturne");

    let contract_dirs = find_contract_dirs(&nocturne_dir);
    if contract_dirs.is_empty() {
        println!("Build succeeded, but no contract artifacts found.");
        println!("Tip: artifacts are generated when a crate uses #[nocturne::contract].");
        println!(
            "Tip: the macro only re-runs on recompile — if the contract crate is \
             cached, force a re-expansion with `cargo clean -p <crate>` first."
        );
        return;
    }

    let mut needs_keygen: Vec<PathBuf> = Vec::new();
    for contract_dir in &contract_dirs {
        // Label as `<crate>/<contract>` relative to target/nocturne/.
        let label = contract_dir
            .strip_prefix(&nocturne_dir)
            .unwrap_or(contract_dir)
            .display();
        println!("Contract '{label}':");

        prune_orphan_keys(contract_dir);

        let zkir_dir = contract_dir.join("zkir");
        if let Ok(files) = std::fs::read_dir(&zkir_dir) {
            let mut zkir_paths: Vec<PathBuf> = files
                .flatten()
                .map(|f| f.path())
                .filter(|p| p.extension().map(|e| e == "zkir").unwrap_or(false))
                .collect();
            zkir_paths.sort();
            for zkir_path in zkir_paths {
                if let Some(fname) = zkir_path.file_name() {
                    println!("  zkir/{}", fname.to_string_lossy());
                }
                if keys_need_update(&zkir_path) {
                    needs_keygen.push(zkir_path);
                }
            }
        }

        let info = contract_dir.join("compiler").join("contract-info.json");
        if info.exists() {
            println!("  compiler/contract-info.json");
        }
    }

    println!("\nArtifacts at: {}", nocturne_dir.display());

    if needs_keygen.is_empty() {
        println!("Keys are up to date.");
        return;
    }

    println!(
        "\nGenerating keys for {} circuit(s) with missing/stale prover/verifier files...",
        needs_keygen.len()
    );
    keygen_paths(&needs_keygen);
}

/// True if either the prover or verifier file is missing, or any of
/// them is older than the `.zkir` source. Lets `cmd_build` skip keygen
/// for circuits that are already up to date — a clean re-build still
/// only pays the keygen cost for what actually changed.
fn keys_need_update(zkir_path: &Path) -> bool {
    let Some(zkir_dir) = zkir_path.parent() else {
        return true;
    };
    let Some(contract_dir) = zkir_dir.parent() else {
        return true;
    };
    let stem = match zkir_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
    {
        Some(s) => s,
        None => return true,
    };
    let keys_dir = contract_dir.join("keys");
    let pk = keys_dir.join(format!("{stem}.prover"));
    let vk = keys_dir.join(format!("{stem}.verifier"));
    let zkir_mtime = std::fs::metadata(zkir_path).and_then(|m| m.modified()).ok();
    let key_pair_mtimes = [pk.as_path(), vk.as_path()]
        .iter()
        .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .collect::<Vec<_>>();
    if key_pair_mtimes.iter().any(|m| m.is_none()) {
        return true; // missing file
    }
    match zkir_mtime {
        Some(zm) => key_pair_mtimes
            .iter()
            .any(|km| km.map(|k| k < zm).unwrap_or(true)),
        None => true, // weird case — be conservative
    }
}

/// Run `IrSource::keygen()` on every .zkir file under `target/nocturne/`.
/// Unlike `cmd_build`, this re-keygens unconditionally — useful when
/// the universal setup params change or you want to refresh stale keys.
fn cmd_keygen() {
    let target_dir = find_target_dir();
    let nocturne_dir = target_dir.join("nocturne");

    if !nocturne_dir.exists() {
        eprintln!("No nocturne artifacts found. Run `cargo nocturne build` first.");
        std::process::exit(1);
    }

    let contract_dirs = find_contract_dirs(&nocturne_dir);
    let mut zkir_files = Vec::new();
    for contract_dir in &contract_dirs {
        // Drop key pairs whose circuit no longer exists before
        // keygenning the ones that do.
        prune_orphan_keys(contract_dir);
        find_zkir_files(&contract_dir.join("zkir"), &mut zkir_files);
    }
    zkir_files.sort();

    if zkir_files.is_empty() {
        eprintln!("No .zkir files found in {}", nocturne_dir.display());
        std::process::exit(1);
    }

    println!(
        "Found {} ZKIR circuit(s). Generating keys...",
        zkir_files.len()
    );

    keygen_paths(&zkir_files);
}

/// Per-zkir keygen loop shared between `cmd_build` and `cmd_keygen`.
/// Each circuit's keygen is wrapped in `catch_unwind` so a single
/// upstream panic (e.g. midnight-circuits constraint failures on a
/// pathological zkir) doesn't abort the run — the user gets the
/// keys that did succeed and a clear error for the ones that didn't.
fn keygen_paths(zkir_files: &[PathBuf]) {
    use std::panic::AssertUnwindSafe;
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    for zkir_path in zkir_files {
        let circuit_name = zkir_path.file_stem().unwrap().to_string_lossy().to_string();
        println!("  Compiling circuit '{circuit_name}'...");

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| load_and_keygen(zkir_path)));
        match result {
            Ok(Ok((k, rows))) => {
                println!("    k={k}, rows={rows}");
                let keys_dir = zkir_path
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|c| c.join("keys"));
                if let Some(d) = keys_dir {
                    println!("    Keys written to {}", d.display());
                }
                succeeded += 1;
            }
            Ok(Err(e)) => {
                eprintln!("    Failed: {e}");
                failed += 1;
            }
            Err(payload) => {
                let msg = panic_message(&*payload);
                eprintln!("    Failed: upstream panic during keygen: {msg}");
                failed += 1;
            }
        }
    }
    if failed > 0 {
        println!(
            "\nKeygen summary: {succeeded} succeeded, {failed} failed. \
             Failed circuits won't have prover/verifier files."
        );
    }
}

/// Extract a readable string from a `catch_unwind` panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "<non-string panic payload>".to_string()
}

/// Run `cargo test`.
fn cmd_test() {
    let status = Command::new("cargo")
        .arg("test")
        .status()
        .expect("failed to run cargo test");

    std::process::exit(status.code().unwrap_or(1));
}

/// Load a ZKIR file, compute model, and generate prover/verifier keys.
fn load_and_keygen(path: &Path) -> Result<(u8, usize), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let ir = midnight_zkir::IrSource::load(file)?;
    let model = ir.model();
    let k = model.k();
    let rows = model.rows();

    // Generate actual keys using tokio runtime.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
        use midnight_serialize::tagged_serialize;
        use midnight_transient_crypto::proofs::Zkir;

        let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])?;

        let (pk, vk) = ir.keygen(&pp).await?;

        // Write key files to a sibling `keys/` directory, matching the
        // compactc layout (`target/nocturne/<contract>/{zkir,compiler,keys}/`).
        // Downstream tooling expects prover/verifier files separated from
        // the ZKIR sources, not interleaved with them.
        let zkir_dir = path.parent().unwrap();
        let contract_dir = zkir_dir.parent().unwrap();
        let keys_dir = contract_dir.join("keys");
        std::fs::create_dir_all(&keys_dir)?;

        let stem = path.file_stem().unwrap().to_string_lossy();
        let pk_path = keys_dir.join(format!("{stem}.prover"));
        let vk_path = keys_dir.join(format!("{stem}.verifier"));

        let mut pk_file = std::io::BufWriter::new(std::fs::File::create(&pk_path)?);
        let mut vk_file = std::io::BufWriter::new(std::fs::File::create(&vk_path)?);

        tagged_serialize(&pk, &mut pk_file)?;
        tagged_serialize(&vk, &mut vk_file)?;

        println!("    → {}", pk_path.display());
        println!("    → {}", vk_path.display());

        Ok::<_, anyhow::Error>(())
    })?;

    Ok((k, rows))
}

fn find_target_dir() -> PathBuf {
    // Check CARGO_TARGET_DIR, then default to ./target
    std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target"))
}

fn find_zkir_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                find_zkir_files(&path, files);
            } else if path.extension().map(|e| e == "zkir").unwrap_or(false) {
                files.push(path);
            }
        }
    }
}

/// Recursively find contract artifact dirs under `target/nocturne/` —
/// any directory containing a `zkir/` subdirectory. The macro writes
/// `target/nocturne/<crate>/<contract>/{zkir,compiler,keys}/`, but a
/// structural search keeps the tool independent of the exact nesting
/// depth. Results are sorted for deterministic output.
fn find_contract_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    collect_contract_dirs(root, &mut dirs);
    dirs.sort();
    dirs
}

fn collect_contract_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join("zkir").is_dir() {
        // Contract dirs don't nest; no need to descend further.
        out.push(dir.to_path_buf());
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_contract_dirs(&path, out);
            }
        }
    }
}

/// Remove `.prover`/`.verifier` files in `<contract_dir>/keys/` whose
/// circuit's `.zkir` is gone (circuit renamed or deleted). The macro
/// prunes orphan `.zkir` files itself, so a key pair without a
/// matching `.zkir` is dead weight that would otherwise persist —
/// and mislead anything that registers verifier keys by globbing.
fn prune_orphan_keys(contract_dir: &Path) {
    let zkir_stems = zkir_stems(&contract_dir.join("zkir"));
    let keys_dir = contract_dir.join("keys");
    let Ok(entries) = std::fs::read_dir(&keys_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_key = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("prover" | "verifier")
        );
        if !is_key {
            continue;
        }
        let Some(stem) = path.file_stem().map(|s| s.to_string_lossy().into_owned()) else {
            continue;
        };
        if !zkir_stems.contains(&stem) {
            match std::fs::remove_file(&path) {
                Ok(()) => println!(
                    "  Removed orphan key {} (no matching .zkir)",
                    path.display()
                ),
                Err(e) => eprintln!("  Failed to remove orphan key {}: {e}", path.display()),
            }
        }
    }
}

/// Circuit names (file stems) of every `.zkir` in `zkir_dir`.
fn zkir_stems(zkir_dir: &Path) -> std::collections::HashSet<String> {
    let mut stems = std::collections::HashSet::new();
    if let Ok(entries) = std::fs::read_dir(zkir_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "zkir").unwrap_or(false)
                && let Some(stem) = path.file_stem()
            {
                stems.insert(stem.to_string_lossy().into_owned());
            }
        }
    }
    stems
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scaffold `<root>/<crate>/<contract>/zkir/` with the given
    /// circuit files, returning the contract dir.
    fn make_contract_dir(root: &Path, krate: &str, contract: &str, circuits: &[&str]) -> PathBuf {
        let contract_dir = root.join(krate).join(contract);
        let zkir_dir = contract_dir.join("zkir");
        std::fs::create_dir_all(&zkir_dir).unwrap();
        for c in circuits {
            std::fs::write(zkir_dir.join(format!("{c}.zkir")), b"{}").unwrap();
        }
        contract_dir
    }

    #[test]
    fn find_contract_dirs_two_level_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let a = make_contract_dir(tmp.path(), "crate_a", "counter", &["increment"]);
        let b = make_contract_dir(tmp.path(), "crate_b", "counter", &["increment", "reset"]);
        // A stray non-contract dir must not be reported.
        std::fs::create_dir_all(tmp.path().join("crate_c").join("not_a_contract")).unwrap();

        let dirs = find_contract_dirs(tmp.path());
        assert_eq!(dirs, vec![a, b]);
    }

    #[test]
    fn find_contract_dirs_missing_root() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = find_contract_dirs(&tmp.path().join("does_not_exist"));
        assert!(dirs.is_empty());
    }

    #[test]
    fn prune_orphan_keys_removes_stale_pairs() {
        let tmp = tempfile::tempdir().unwrap();
        let contract_dir = make_contract_dir(tmp.path(), "crate_a", "counter", &["increment"]);
        let keys_dir = contract_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();
        for name in [
            "increment.prover",
            "increment.verifier",
            "old_circuit.prover",
            "old_circuit.verifier",
        ] {
            std::fs::write(keys_dir.join(name), b"key").unwrap();
        }

        prune_orphan_keys(&contract_dir);

        assert!(keys_dir.join("increment.prover").exists());
        assert!(keys_dir.join("increment.verifier").exists());
        assert!(!keys_dir.join("old_circuit.prover").exists());
        assert!(!keys_dir.join("old_circuit.verifier").exists());
    }

    #[test]
    fn prune_orphan_keys_no_keys_dir_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let contract_dir = make_contract_dir(tmp.path(), "crate_a", "counter", &["increment"]);
        // No keys/ dir at all — must not panic or create one.
        prune_orphan_keys(&contract_dir);
        assert!(!contract_dir.join("keys").exists());
    }

    #[test]
    fn keys_need_update_missing_and_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let contract_dir = make_contract_dir(tmp.path(), "crate_a", "counter", &["increment"]);
        let zkir = contract_dir.join("zkir").join("increment.zkir");

        // No keys at all -> stale.
        assert!(keys_need_update(&zkir));

        // Both keys newer than zkir -> fresh.
        let keys_dir = contract_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("increment.prover"), b"pk").unwrap();
        std::fs::write(keys_dir.join("increment.verifier"), b"vk").unwrap();
        assert!(!keys_need_update(&zkir));

        // zkir newer than keys -> stale again.
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&zkir)
            .unwrap()
            .set_modified(future)
            .unwrap();
        assert!(keys_need_update(&zkir));

        // Only one key present -> stale.
        std::fs::remove_file(keys_dir.join("increment.verifier")).unwrap();
        assert!(keys_need_update(&zkir));
    }
}
