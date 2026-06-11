//! Integration test: artifact directories are keyed by
//! `CARGO_CRATE_NAME` *and* contract module name
//! (`target/nocturne/<crate>/<contract>/`).
//!
//! This matters because several integration-test crates in this
//! workspace all define `mod counter` with different circuit sets; a
//! module-name-only key made them clobber each other's artifacts
//! during parallel compilation. The `mod counter` below intentionally
//! reuses that colliding name: its circuit set is unique to this test
//! crate, so if another crate's `counter` had clobbered the directory
//! the exact-circuit-set assertion would fail.

use nocturne::types::*;
use std::collections::BTreeSet;
use std::path::PathBuf;

#[nocturne::contract]
mod counter {
    use super::*;

    #[nocturne(ledger)]
    pub struct CounterState {
        count: Counter,
    }

    impl CounterState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[nocturne(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }

        #[nocturne(circuit)]
        pub fn layout_probe_circuit(&mut self) {
            self.count.increment();
        }
    }
}

#[nocturne::contract]
mod second_contract {
    use super::*;

    #[nocturne(ledger)]
    pub struct SecondState {
        total: Counter,
    }

    impl SecondState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                total: Counter::zero(),
            }
        }

        #[nocturne(circuit)]
        pub fn bump(&mut self) {
            self.total.increment();
        }
    }
}

/// Locate the cargo target directory the test binary was built into:
/// `CARGO_TARGET_DIR` if set, else ascend from the test executable
/// (`<target>/debug/deps/<test>-<hash>`) to the enclosing `target`.
fn target_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    let exe = std::env::current_exe().expect("test binary path");
    exe.ancestors()
        .find(|a| {
            a.file_name().map(|n| n == "target").unwrap_or(false)
                || a.join("CACHEDIR.TAG").is_file()
        })
        .expect("test binary should live under a cargo target dir")
        .to_path_buf()
}

fn zkir_names(contract_dir: &std::path::Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let entries = std::fs::read_dir(contract_dir.join("zkir"))
        .unwrap_or_else(|e| panic!("missing zkir dir under {}: {e}", contract_dir.display()));
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".zkir") {
            names.insert(name);
        }
    }
    names
}

#[nocturne::test]
fn artifacts_are_keyed_by_crate_and_contract() {
    // CARGO_CRATE_NAME for an integration test target is the test
    // file's name, which is what the macro saw at expansion time.
    let crate_dir = target_dir().join("nocturne").join("artifact_layout_test");

    let counter_dir = crate_dir.join("counter");
    let second_dir = crate_dir.join("second_contract");
    assert_ne!(counter_dir, second_dir);

    // Exact circuit sets: proves this crate's `counter` wasn't
    // clobbered by another test crate's `mod counter` (different
    // circuit set) and that orphan pruning leaves no strays.
    assert_eq!(
        zkir_names(&counter_dir),
        BTreeSet::from(["increment.zkir".into(), "layout_probe_circuit.zkir".into()]),
    );
    assert_eq!(
        zkir_names(&second_dir),
        BTreeSet::from(["bump.zkir".into()]),
    );

    for dir in [&counter_dir, &second_dir] {
        assert!(
            dir.join("compiler").join("contract-info.json").is_file(),
            "missing contract-info.json under {}",
            dir.display()
        );
    }
}
