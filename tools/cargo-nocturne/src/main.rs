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

    if !nocturne_dir.exists() {
        println!("Build succeeded. No contract artifacts found.");
        println!("Tip: artifacts are generated when a crate uses #[nocturne::contract].");
        return;
    }

    let mut found = false;
    let mut needs_keygen: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&nocturne_dir) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                continue;
            }
            found = true;
            let name = entry.file_name().to_string_lossy().to_string();
            println!("Contract '{name}':");

            let zkir_dir = entry.path().join("zkir");
            if zkir_dir.exists()
                && let Ok(files) = std::fs::read_dir(&zkir_dir)
            {
                for f in files.flatten() {
                    let fname = f.file_name().to_string_lossy().to_string();
                    if !fname.ends_with(".zkir") {
                        continue;
                    }
                    println!("  zkir/{fname}");
                    let zkir_path = f.path();
                    if keys_need_update(&zkir_path) {
                        needs_keygen.push(zkir_path);
                    }
                }
            }

            let info = entry.path().join("compiler").join("contract-info.json");
            if info.exists() {
                println!("  compiler/contract-info.json");
            }
        }
    }

    if !found {
        println!("Build succeeded, but no contract artifacts found.");
        return;
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

    let mut zkir_files = Vec::new();
    find_zkir_files(&nocturne_dir, &mut zkir_files);

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
