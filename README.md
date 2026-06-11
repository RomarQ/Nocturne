# Nocturne

> [!WARNING]
> This project is under active development and is **not production ready**. APIs may change without notice.

A Rust eDSL for writing [Midnight](https://midnight.network) smart contracts.

You write contracts as ordinary Rust modules annotated with `#[nocturne::contract]`, and a proc macro lowers them to ZKIR circuits, Plonk prover/verifier keys, transcript builders, and contract metadata. The only hard constraint on output is `midnight-ledger` compliance: the ZKIR must verify, the on-chain transcript ops must execute correctly, and the initial state must deserialize. Surface syntax, IR shape, and artifact format are all open to do better where Rust's type system and metaprogramming enable something better.

## Status

Alpha. The codegen is being driven by translating real contracts; expect rough edges and missing features. Counter and a kitchen-sink contract exercising most primitives are in `examples/`. The end-to-end pipeline (write contract, build, keygen, prove, verify on-chain ledger state) is wired up and covered by an integration test suite that runs against the `midnight-ledger` types directly.

What's in:

- Ledger types: `Counter`, `Cell<T>`, `Map<K, V>`, `Set<T>`, `MerkleTree<H, T>`
- Value types: `Boolean`, `Field`, `Uint<N>` for N ≤ 128, `Bytes<N>` (values wider than one field element are chunked into ceil(N/31) Frs; 48- and 64-byte shapes are prove-tested), `Option<T>`, `[T; N]` for N ≤ 11, tuples up to arity 11, user structs, homogeneous-payload enums
- Control flow: `if`/`else`, `match` on user enums and `Option`, const-bounded `for` loops, `assert!` / `assert_eq!`, `if`-as-expression with `cond_select` multiplex
- Composition: free `fn` helpers in the contract module inlined into circuits (compactc's no-annotation lowering rule), parametric witness methods (`witnesses.foo(args)`) alongside plain witness fields
- Cross-circuit: parameterized constructors with `deploy::initial_state(...)`, witness reads inside `let` bindings, `disclose(_)`, `merkle_tree_path_root(_)`
- Tooling: `cargo nocturne build` (auto-keygens stale circuits), `cargo nocturne keygen`, `cargo nocturne test`

What's not yet:

- `kernel.self()`, block height, caller (needs upstream slot layout confirmation)
- Heterogeneous-payload enums (`enum E { A(u64), B(Bytes<32>) }`)
- ZSwap and Kernel
- Cross-contract calls

## Example: counter contract

```rust
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

        #[nocturne(query)]
        pub fn get_count(&self) -> u64 {
            self.count.value()
        }
    }
}
```

Build it:

```sh
cargo install --path tools/cargo-nocturne
cd examples/counter-contract
cargo nocturne build
```

`cargo nocturne` resolves the target directory via `cargo metadata`, so it works from any directory inside the workspace. Artifacts land in the workspace target dir, keyed by crate and contract module — for the counter example that's `target/nocturne/counter_contract/counter/`:

```
zkir/increment.zkir
keys/increment.prover
keys/increment.verifier
compiler/contract-info.json
```

`zkir/*.zkir` is the circuit definition (one per `#[nocturne(circuit)]`). `keys/*.{prover,verifier}` are Plonk keys derived from the ZKIR. `contract-info.json` describes the contract's surface (circuit signatures, witness types) for indexers and code generators.

See [`docs/compiling.md`](docs/compiling.md) for the full build flow, [`docs/artifacts.md`](docs/artifacts.md) for what each file is for and who consumes it, [`docs/compactc-vs-nocturne.md`](docs/compactc-vs-nocturne.md) if you're coming from Compact and want a reference of where the two diverge, and [`docs/compactc-ir-mapping.md`](docs/compactc-ir-mapping.md) for a construct-by-construct comparison of compactc's internal IR with Nocturne's `ExprIR`.

## Repo layout

```
crates/
  nocturne                  umbrella crate end-users depend on
  nocturne-macro            #[nocturne::contract] proc macro
  nocturne-ir               typed IR the macro emits
  nocturne-codegen          ZKIR + transcript + deploy emitters
  nocturne-types            user-facing types (Counter, Cell<T>, Map<...>, ...)
  nocturne-storage          storage primitives mirroring the ledger crate
  nocturne-metadata         contract-info.json schema
tools/
  cargo-nocturne            cargo subcommand for build/keygen/test
examples/
  counter-contract          minimal example
  kitchen-sink              exercises every supported primitive
docs/                       compiling.md, artifacts.md, compactc-vs-nocturne.md, compactc-ir-mapping.md
```

## Truth source

When upstream protocol behavior matters, the canonical reference is [`midnight-ledger` `ledger-8`](https://github.com/midnightntwrk/midnight-ledger/tree/ledger-8). Inferring from existing code or docs is not enough; if you're adding or changing something that touches the on-chain VM, ZKIR, or transcript layout, read the upstream source first.

## Scope

Nocturne stops at producing artifacts. Deploying contracts, building transactions, talking to wallets, indexer / node RPC: those belong in downstream tools, primarily [`midnight-rs`](https://github.com/RomarQ/midnight-rs).
