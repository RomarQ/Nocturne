# Compiling a contract

This walks through compiling a Nocturne contract from source to deployable artifacts. The Hello-World here is the counter contract in `examples/counter-contract`; the same flow applies to any `#[nocturne::contract]` module.

## 1. Write the contract

A contract is a Rust module annotated with `#[nocturne::contract]`. The macro inspects the module at compile time and emits ZKIR, a transcript builder, deploy helpers, and `contract-info.json` alongside the user's code.

```rust
// examples/counter-contract/src/lib.rs
use nocturne::types::*;

#[nocturne::contract]
pub mod counter {
    use super::*;

    #[nocturne(ledger)]
    pub struct CounterState {
        pub count: Counter,
    }

    impl CounterState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self { count: Counter::zero() }
        }

        #[nocturne(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }
    }
}
```

Minimum requirements:

- A `#[nocturne(ledger)]` struct describing on-chain state.
- At least one `#[nocturne(constructor)]` returning `Self`.
- At least one `#[nocturne(circuit)]` method (`&self` for read-only, `&mut self` for state transitions).

Optional:

- `#[nocturne(witnesses)]` struct for private (off-chain) inputs.
- `#[nocturne(query)]` methods for off-chain reads (plain Rust, never on-chain).
- Plain `pub struct` / `pub enum` declarations are picked up as user types and can be used as `Cell<T>` values, `Map<K, V>` keys, witness fields, etc.

### Supported value types

The eDSL is plain Rust syntax. The following types are recognised in witness fields, ledger field payloads (`Cell<T>`, `Map<K, V>`, `Set<T>`), and circuit local bindings:

| Type | Wire shape | Notes |
|---|---|---|
| `Boolean` | `Bytes<1>` | Conditions use `.value()` to unwrap to native `bool`. |
| `Field` | one Fr (low 128 bits) | Field element, lossy for the full 254-bit range. |
| `Uint<N>` for `N ≤ 128` | `Bytes<ceil(N/8)>` | Maps to `u8`/`u16`/`u32`/`u64`/`u128` for primitive casts. |
| `Bytes<N>` | `Bytes<N>`, chunked into ceil(N/31) Frs when `N > 31` | Fixed-size byte arrays. Multi-Fr shapes (e.g. `Bytes<48>` Map keys, `Bytes<64>` Merkle leaves) are prove-tested. |
| `Option<T>` | `(Bytes<1>, T)` | Same wire shape as Compact's `Maybe<T>`. `None` synthesises `T::default()` for the payload slot. |
| `[T; N]` for `1 ≤ N ≤ 11` | N-tuple of `T` | Same wire shape as Compact's `Vector<N, T>`. Index reads (`arr[i]`) accept compile-time integer literals; use `for i in 0..N { ... arr[i] ... }` to unroll a const range to literal indices. |
| `MerkleTreeDigest`, `MerkleTreePath<H, T>` | Field-aligned | See `memories/merkle-tree-encoding.md`. |
| Tuples `(T1, ..., Tn)` for `n ≤ 11` | concatenated component layouts | Upstream tuple `Aligned` impl. |
| User `struct` / homogeneous-payload `enum` | as tuple / `(Bytes<1>, T)` | See `memories/compactc-vs-nocturne-divergences.md`. |

`if`-as-expression is supported: `let x = if cond { a } else { b };` multiplexes the branch result wires via ZKIR `cond_select` and emits a Rust `if`-expression on the transcript side. Either branch must yield a value (no missing `else`); rustc enforces this at the macro output.

The contract crate is an ordinary Rust library — its `Cargo.toml` just depends on the `nocturne` umbrella crate:

```toml
[package]
name = "counter-contract"
version = "0.1.0"
edition = "2024"

[dependencies]
nocturne = { path = "../../crates/nocturne" }  # or a published version once we ship
```

## 2. Build with `cargo nocturne build`

Install the tool (one-time, from the workspace root):

```sh
cargo install --path tools/cargo-nocturne
```

Then from the contract crate directory:

```sh
cargo nocturne build
```

This runs `cargo build` (which fires the proc macro), lists the artifacts, and runs keygen for any circuit whose prover/verifier files are missing or older than its `.zkir`:

```
Building contract...
Contract 'counter_contract/counter':
  zkir/increment.zkir
  compiler/contract-info.json

Artifacts at: /path/to/workspace/target/nocturne

Generating keys for 1 circuit(s) with missing/stale prover/verifier files...
  Compiling circuit 'increment'...
    → target/nocturne/counter_contract/counter/keys/increment.prover
    → target/nocturne/counter_contract/counter/keys/increment.verifier
    k=5, rows=24
    Keys written to target/nocturne/counter_contract/counter/keys
```

The keygen step is skipped on subsequent builds when nothing has changed — the proc macro writes ZKIR with `write_if_changed` semantics, so a contract whose source didn't change leaves its `.zkir` mtime untouched and its keys are considered up to date.

If `cargo nocturne build` reports "No contract artifacts found," the macro didn't fire — usually because the crate doesn't apply `#[nocturne::contract]` to any module, or the build cache made the macro skip (run `cargo clean -p <crate>` to force a re-expansion).

> [!NOTE]
> `cargo nocturne build` is a thin wrapper around `cargo build` plus the conditional keygen pass. Plain `cargo build` gives you the ZKIR + `contract-info.json` only; use `cargo nocturne keygen` to derive prover/verifier keys separately.

## 3. Inspect the artifacts

```
target/nocturne/<crate_name>/<contract_name>/
├── zkir/
│   └── <circuit_name>.zkir       # one per circuit function
├── compiler/
│   └── contract-info.json        # circuit signatures + witness types
└── keys/                         # populated by `cargo nocturne keygen`
    ├── <circuit_name>.prover
    └── <circuit_name>.verifier
```

`<crate_name>` is the `CARGO_CRATE_NAME` of the crate the contract module lives in (hyphens become underscores), so the counter example lands at `target/nocturne/counter_contract/counter/`. Keying by crate *and* contract keeps two crates that define equally named contract modules from overwriting each other.

`keys/` is empty until you run keygen — `cargo nocturne build` only emits `zkir/` and `compiler/`. The layout mirrors compactc's so downstream tooling sees the same shape from either compiler.

**`*.zkir`** is a JSON-serialised `IrSource` — the ZK circuit definition. One file per `#[nocturne(circuit)]` method. Consumed by `IrSource::load()` downstream for keygen, proving, and verification.

**`contract-info.json`** matches Compact's schema so the same downstream tooling (TypeScript bindings, indexers, deploy scripts) can consume both:

```json
{
  "compiler-version": "nocturne 0.1.0",
  "language-version": "1.0",
  "runtime-version": "1.0",
  "circuits": [
    { "name": "increment", "pure": false, "proof": true, "arguments": [], "result-type": { "type-name": "Tuple", "types": [] } }
  ],
  "witnesses": [],
  "contracts": []
}
```

In addition, the macro injects two submodules inside the user's contract module — visible to your code, not on disk:

- `contract::transcript` — `build_<circuit>_transcript(witnesses?, state?)` builders that produce the on-chain transcript `Op` sequence at call time.
- `contract::deploy::initial_state(...)` — constructs the `StateValue` tree the ledger expects at deploy, forwarding any constructor parameters.

See [artifacts.md](./artifacts.md) for the per-artifact reference (what each file contains, who produces it, who consumes it, when it changes).

## 4. Force-regenerate keys with `cargo nocturne keygen`

`cargo nocturne build` runs keygen automatically for new or out-of-date circuits, so you usually don't need to call this directly. Use it when you want to re-keygen every circuit unconditionally — typically after the upstream universal setup parameters change, or to verify a clean build from a fresh `target/`:

```sh
cargo nocturne keygen
```

For every `.zkir` under `target/nocturne/`, this writes:

```
target/nocturne/<crate_name>/<contract_name>/keys/<circuit_name>.prover     # binary prover key
target/nocturne/<crate_name>/<contract_name>/keys/<circuit_name>.verifier   # binary verifier key
```

Key pairs whose `.zkir` is gone (circuit renamed or deleted) are removed before keygen runs, so `keys/` always mirrors the current circuit set.

The verifier key is what gets registered on-chain when you deploy. Keys are tagged with `midnight-serialize` so downstream tools recognise them.

> [!NOTE]
> Keygen reads Midnight's universal setup parameters via `MidnightDataProvider`. The first run downloads them on demand; subsequent runs reuse the cache.

## 5. Run tests with `cargo nocturne test`

Contract crates can include ordinary Rust unit and integration tests. `cargo nocturne test` is a thin wrapper around `cargo test` that doesn't require contract artifacts to be built first:

```sh
cargo nocturne test
```

The proc macro strips its own attributes from the user's module, so circuit methods are plain Rust functions you can call directly from tests. The injected `transcript::build_*_transcript` builders are also available for asserting on-chain behaviour without going through prove/verify.

## 6. Consume the artifacts downstream

Nocturne stops at producing artifacts. Deployment, transaction building, wallet interaction, and node RPC live in downstream tools — primarily [`midnight-rs`](https://github.com/RomarQ/midnight-rs). The handoff:

| Artifact | Downstream use |
|---|---|
| `<circuit>.zkir` | Loaded by `IrSource::load()` for proving and verification |
| `<circuit>.prover` | Held by the client; feeds `IrSource::prove(...)` |
| `<circuit>.verifier` | Registered on-chain per circuit at deploy time |
| `contract-info.json` | Describes the contract's surface to indexers, type generators, and deploy scripts |
| `contract::transcript::build_*` | Called at runtime by the client to assemble the transcript that goes into the on-chain transaction |
| `contract::deploy::initial_state(...)` | Called at deploy time to construct the initial `StateValue` |

The end-to-end flow once you have all of the above:

```
cargo nocturne build         →  ZKIR + contract-info.json
cargo nocturne keygen        →  prover + verifier keys
<downstream tool>            →  deploy verifier keys on-chain
<downstream tool>            →  client builds transcript + proof per circuit call
<midnight node>              →  re-verifies the proof + transcript against the on-chain state
```

## Troubleshooting

**"No contract artifacts found"** — The macro didn't fire. Run `cargo clean -p <crate>` and rebuild.

**Artifacts in the wrong place** — `cargo nocturne` resolves the target directory via `cargo metadata`, so it works from any directory inside the workspace (a member crate's directory included). If you're outside a cargo project entirely, it falls back to `CARGO_TARGET_DIR` and then `./target` relative to the current directory.

**`Bytes::<32>::from_slice(...)` panics at deploy time** — `from_slice` zero-pads, so it never panics. If you're seeing a panic, the constructor body itself is panicking; check that the user types referenced in initializers (e.g. enum variants in `Cell::new(Status::Open)`) are imported into scope.

**ZKIR file is missing for a circuit you wrote** — Check that the method has `#[nocturne(circuit)]` (not `#[nocturne(query)]` — queries don't emit ZKIR, they're plain off-chain Rust).

**`cargo nocturne` reports build success but no artifact path** — The macro only re-runs when the contract crate actually recompiles; a fully cached build leaves a cleaned `target/nocturne/` empty. Run `cargo clean -p <crate>` to force a re-expansion. If you set a custom `CARGO_TARGET_DIR`, both the macro and the tool resolve it, so artifacts and lookup stay in sync.
