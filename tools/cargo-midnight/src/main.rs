use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // When invoked as `cargo midnight`, cargo passes "midnight" as argv[1].
    let subcommand = if args.get(1).map(|s| s.as_str()) == Some("midnight") {
        args.get(2).map(|s| s.as_str())
    } else {
        args.get(1).map(|s| s.as_str())
    };

    match subcommand {
        Some("build") => cmd_build(),
        Some("keygen") => cmd_keygen(),
        Some("test") => cmd_test(),
        Some("deploy") => {
            eprintln!("cargo-midnight: deploy not yet implemented");
            std::process::exit(1);
        }
        Some(other) => {
            eprintln!("cargo-midnight: unknown subcommand '{other}'");
            std::process::exit(1);
        }
        None => print_usage(),
    }
}

fn print_usage() {
    println!("cargo-midnight: Midnight smart contract build tool");
    println!();
    println!("Usage: cargo midnight <command>");
    println!();
    println!("Commands:");
    println!("  build    Compile contract, emit ZKIR + contract-info.json");
    println!("  keygen   Generate prover/verifier keys from ZKIR files");
    println!("  test     Run contract tests");
    println!("  deploy   Deploy contract to a Midnight node");
}

/// Run `cargo build` and collect generated artifacts.
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

    // Artifacts are written to target/midnight/ by the proc macro.
    let target_dir = find_target_dir();
    let midnight_dir = target_dir.join("midnight");

    if !midnight_dir.exists() {
        println!("Build succeeded. No contract artifacts found.");
        println!("Tip: artifacts are generated when a crate uses #[midnight::contract].");
        return;
    }

    // List all contract directories.
    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(&midnight_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                found = true;
                let name = entry.file_name().to_string_lossy().to_string();
                println!("Contract '{name}':");

                let zkir_dir = entry.path().join("zkir");
                if zkir_dir.exists()
                    && let Ok(files) = std::fs::read_dir(&zkir_dir)
                {
                    for f in files.flatten() {
                        let fname = f.file_name().to_string_lossy().to_string();
                        if fname.ends_with(".zkir") {
                            println!("  zkir/{fname}");
                        }
                    }
                }

                let info = entry.path().join("compiler").join("contract-info.json");
                if info.exists() {
                    println!("  compiler/contract-info.json");
                }
            }
        }
    }

    if found {
        println!("\nArtifacts at: {}", midnight_dir.display());
    } else {
        println!("Build succeeded, but no contract artifacts found.");
    }
}

/// Run `IrSource::keygen()` on each .zkir file to generate prover/verifier keys.
fn cmd_keygen() {
    let target_dir = find_target_dir();
    let midnight_dir = target_dir.join("midnight");

    if !midnight_dir.exists() {
        eprintln!("No midnight artifacts found. Run `cargo midnight build` first.");
        std::process::exit(1);
    }

    let mut zkir_files = Vec::new();
    find_zkir_files(&midnight_dir, &mut zkir_files);

    if zkir_files.is_empty() {
        eprintln!("No .zkir files found in {}", midnight_dir.display());
        std::process::exit(1);
    }

    println!(
        "Found {} ZKIR circuit(s). Generating keys...",
        zkir_files.len()
    );

    for zkir_path in &zkir_files {
        let circuit_name = zkir_path.file_stem().unwrap().to_string_lossy().to_string();

        println!("  Compiling circuit '{circuit_name}'...");

        match load_and_keygen(zkir_path) {
            Ok((k, rows)) => {
                println!("    k={k}, rows={rows}");
                println!(
                    "    Keys written to {}",
                    zkir_path.parent().unwrap().display()
                );
            }
            Err(e) => {
                eprintln!("    Failed: {e}");
            }
        }
    }
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

        // Write key files next to the ZKIR file.
        let dir = path.parent().unwrap();
        let stem = path.file_stem().unwrap().to_string_lossy();

        let pk_path = dir.join(format!("{stem}.prover"));
        let vk_path = dir.join(format!("{stem}.verifier"));

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

#[allow(dead_code)]
fn copy_dir_recursive(src: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).ok();
    if let Ok(entries) = std::fs::read_dir(src) {
        for entry in entries.flatten() {
            let src_path = entry.path();
            let dest_path = dest.join(entry.file_name());
            if src_path.is_dir() {
                copy_dir_recursive(&src_path, &dest_path);
            } else {
                std::fs::copy(&src_path, &dest_path).ok();
            }
        }
    }
}
