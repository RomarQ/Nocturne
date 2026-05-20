# Compiling a contract

This walks through compiling a Nocturne contract from source to deployable artifacts. The Hello-World here is the counter contract in `examples/counter-contract`; the same flow applies to any `#[midnight::contract]` module.

## 1. Write the contract

A contract is a Rust module annotated with `#[midnight::contract]`. The macro inspects the module at compile time and emits ZKIR, a transcript builder, deploy helpers, and `contract-info.json` alongside the user's code.

```rust
// examples/counter-contract/src/lib.rs
use midnight::types::*;

#[midnight::contract]
pub mod counter {
    use super::*;

    #[midnight(ledger)]
    pub struct CounterState {
        pub count: Counter,
    }

    impl CounterState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self { count: Counter::zero() }
        }

        #[midnight(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }
    }
}
```

Minimum requirements:

- A `#[midnight(ledger)]` struct describing on-chain state.
- At least one `#[midnight(constructor)]` returning `Self`.
- At least one `#[midnight(circuit)]` method (`&self` for read-only, `&mut self` for state transitions).

Optional:

- `#[midnight(witnesses)]` struct for private (off-chain) inputs.
- `#[midnight(query)]` methods for off-chain reads (plain Rust, never on-chain).
- Plain `pub struct` / `pub enum` declarations are picked up as user types and can be used as `Cell<T>` values, `Map<K, V>` keys, witness fields, etc.

The contract crate is an ordinary Rust library — its `Cargo.toml` just depends on the `midnight` umbrella crate:

```toml
[package]
name = "counter-contract"
version = "0.1.0"
edition = "2024"

[dependencies]
midnight = { path = "../../crates/midnight" }  # or a published version once we ship
```

## 2. Build with `cargo midnight build`

Install the tool (one-time, from the workspace root):

```sh
cargo install --path tools/cargo-midnight
```

Then from the contract crate directory:

```sh
cargo midnight build
```

This runs `cargo build` (which fires the proc macro) and lists the artifacts the macro wrote to `target/midnight/<contract_name>/`:

```
Building contract...
Contract 'counter':
  zkir/increment.zkir
  compiler/contract-info.json

Artifacts at: ./target/midnight/
```

If `cargo midnight build` reports "No contract artifacts found," the macro didn't fire — usually because the crate doesn't apply `#[midnight::contract]` to any module, or the build cache made the macro skip (run `cargo clean -p <crate>` to force a re-expansion).

> [!NOTE]
> `cargo midnight build` is a thin wrapper around `cargo build`. You can use plain `cargo build` if you don't want the artifact summary printed.

## 3. Inspect the artifacts

```
target/midnight/<contract_name>/
├── zkir/
│   └── <circuit_name>.zkir       # one per circuit function
├── compiler/
│   └── contract-info.json        # circuit signatures + witness types
└── keys/                         # populated by `cargo midnight keygen`
    ├── <circuit_name>.prover
    └── <circuit_name>.verifier
```

`keys/` is empty until you run keygen — `cargo midnight build` only emits `zkir/` and `compiler/`. The layout mirrors compactc's so downstream tooling sees the same shape from either compiler.

**`*.zkir`** is a JSON-serialised `IrSource` — the ZK circuit definition. One file per `#[midnight(circuit)]` method. Consumed by `IrSource::load()` downstream for keygen, proving, and verification.

**`contract-info.json`** matches Compact's schema so the same downstream tooling (TypeScript bindings, indexers, deploy scripts) can consume both:

```json
{
  "compiler-version": "midnight-edsl 0.1.0",
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

## 4. Generate keys with `cargo midnight keygen`

ZKIR alone isn't enough to prove or verify — you need Plonk prover and verifier keys derived from each circuit. Run keygen once per release:

```sh
cargo midnight keygen
```

For every `.zkir` under `target/midnight/`, this writes:

```
target/midnight/<contract_name>/keys/<circuit_name>.prover     # binary prover key
target/midnight/<contract_name>/keys/<circuit_name>.verifier   # binary verifier key
```

The verifier key is what gets registered on-chain when you deploy. Keys are tagged with `midnight-serialize` so downstream tools recognise them.

> [!NOTE]
> Keygen reads Midnight's universal setup parameters via `MidnightDataProvider`. The first run downloads them on demand; subsequent runs reuse the cache.

## 5. Run tests with `cargo midnight test`

Contract crates can include ordinary Rust unit and integration tests. `cargo midnight test` is a thin wrapper around `cargo test` that doesn't require contract artifacts to be built first:

```sh
cargo midnight test
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
cargo midnight build         →  ZKIR + contract-info.json
cargo midnight keygen        →  prover + verifier keys
<downstream tool>            →  deploy verifier keys on-chain
<downstream tool>            →  client builds transcript + proof per circuit call
<midnight node>              →  re-verifies the proof + transcript against the on-chain state
```

## Troubleshooting

**"No contract artifacts found"** — The macro didn't fire. Run `cargo clean -p <crate>` and rebuild.

**Artifacts in the wrong place** — `cargo midnight` looks for `./target/midnight/` relative to the current directory. Run from the workspace root, not from inside an example crate's directory.

**`Bytes::<32>::from_slice(...)` panics at deploy time** — `from_slice` zero-pads, so it never panics. If you're seeing a panic, the constructor body itself is panicking; check that the user types referenced in initializers (e.g. enum variants in `Cell::new(Status::Open)`) are imported into scope.

**ZKIR file is missing for a circuit you wrote** — Check that the method has `#[midnight(circuit)]` (not `#[midnight(query)]` — queries don't emit ZKIR, they're plain off-chain Rust).

**`cargo midnight` reports build success but no artifact path** — The macro write only fires when `OUT_DIR` is reachable from the workspace target. If you set a custom `CARGO_TARGET_DIR`, the artifacts land there; the tool walks both locations.
