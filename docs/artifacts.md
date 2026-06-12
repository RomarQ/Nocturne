# Compilation artifacts

`#[nocturne::contract]` produces three kinds of output, each consumed by a different downstream tool. This document describes what each file is for, how it's generated, what consumes it, and when you should expect it to change.

```
target/nocturne/<crate_name>/<contract_name>/
├── zkir/
│   └── <circuit_name>.zkir       # circuit definition (JSON)
├── keys/
│   ├── <circuit_name>.prover     # Plonk prover key (binary)
│   └── <circuit_name>.verifier   # Plonk verifier key (binary)
└── compiler/
    └── contract-info.json        # contract metadata (JSON)
```

`<crate_name>` is the `CARGO_CRATE_NAME` of the compilation target the macro expanded in (hyphens become underscores; an integration test target uses the test file's name). The extra level keeps two crates that both define a `mod counter` from clobbering each other's artifacts. For the counter example that's `target/nocturne/counter_contract/counter/`.

There's a fourth kind of "artifact" that doesn't land on disk: the proc macro also injects `pub mod transcript { ... }` and `pub mod deploy { ... }` submodules into the user's contract module. Those are generated Rust, not files; covered at the bottom.

## `<circuit_name>.zkir` — circuit definition

JSON serialisation of `midnight_zkir::IrSource` plus a `version` wrapper. One file per `#[nocturne(circuit)]` method.

**What it contains**: an instruction list (`load_imm`, `private_input`, `public_input`, `add`, `mul`, `cond_select`, `declare_pub_input`, …) over a linear memory model that describes the Plonk constraint system for one circuit. Also `num_inputs` and `do_communications_commitment: true`. The commitment flag is required for on-chain compatibility: the ledger's verify path (`ledger/src/verify.rs` on the `ledger-8` branch) unconditionally feeds the communication commitment as the second public input, so a circuit built without that slot fails verification with a public-input count mismatch.

**Produced by**: the `#[nocturne::contract]` proc macro at compile time. Written via `write_if_changed` (atomic temp-file + rename), so unchanged source leaves the file's mtime alone. Stale `.zkir` files from renamed or deleted circuits are pruned on the next macro expansion.

**Consumed by**:
- `cargo nocturne keygen` — calls `IrSource::load()` then `IrSource::keygen()` to derive prover/verifier keys.
- Downstream tooling (e.g. midnight-rs) that needs to re-derive proofs or inspect circuit structure.

**Format**: pretty-printed JSON, small for simple circuits, scales with circuit complexity.

**Determinism**: byte-for-byte deterministic for a given source. Two clean builds of the same contract produce identical `.zkir`.

**Versioning**: each file carries `"version": { "major": 2, "minor": 0 }` matching the ZKIR opcode set this Nocturne release targets. Upstream ZKIR v3 (when released) will change the opcode layout — that's a Nocturne release upgrade, not a per-contract migration.

**When it changes**: only when the circuit body or any type it touches changes. Renaming a field, reordering ledger declarations, or changing a Cell's inner type will trigger a write.

## `<circuit_name>.prover` — Plonk prover key

Binary, tagged-serialized prover key for the Plonk circuit defined by the matching `.zkir`. One file per circuit, derived from `.zkir`.

**What it contains**: the precomputed witness polynomials, lookup tables, and commitments the prover needs to construct a ZK proof. The prover key encodes the structure of the circuit at the Plonk level, so the same `.zkir` always yields the same key (modulo universal-setup-parameter changes).

**Produced by**: `cargo nocturne build` (when missing or stale) or `cargo nocturne keygen` (unconditionally). Both call `IrSource::keygen()` with the Midnight universal setup parameters fetched via `MidnightDataProvider`.

**Consumed by**: the client building a transaction. Downstream tools like midnight-rs load the prover key, collect witness values, and call `IrSource::prove(rng, params, pk, &preimage)` to produce a `Proof`.

**Format**: binary, `midnight-serialize` tagged framing. Complex circuits with Merkle or hash operations produce larger keys.

**Security**: the prover key is not secret — it can be derived from `.zkir` plus the public universal setup. Keep it bundled with the application that calls `prove`, but you don't need to treat it like a private key.

**When it changes**: when the underlying `.zkir` changes, or when the universal setup parameters are rotated. Don't ship a prover key derived from one universal setup against a chain that uses a different one.

## `<circuit_name>.verifier` — Plonk verifier key

Binary, tagged-serialized verifier key for the same circuit.

**What it contains**: the public commitments and parameters the verifier needs to check a proof. Much smaller than the prover key — it's just the polynomial commitments and the structure description, not the full witness tables.

**Produced by**: same step as `.prover`. Always generated alongside it.

**Consumed by**:
- The on-chain ledger — the verifier key is registered per circuit when the contract is deployed; nodes use it to check `ContractCall` proofs.
- Off-chain verifiers (e.g. light clients, audit tooling) that want to validate a proof without proving it.

**Format**: binary, `midnight-serialize` tagged framing. Verifier keys are several times smaller than the matching prover keys.

**Reproducibility**: byte-for-byte deterministic given the same `.zkir` and the same universal setup parameters. The counter contract's verifier key is byte-identical to compactc's output for the equivalent Compact contract — CI compares against `tests/golden/counter-increment.verifier` as a regression guard.

**When it changes**: same triggers as `.prover` — circuit changes, universal setup rotation. Once deployed on-chain, a verifier key is immutable for that contract instance; deploying a new version means a new contract address with a new verifier key.

## `contract-info.json` — contract metadata

Human-readable JSON describing the contract's external surface. One file per contract (not per circuit).

**What it contains**:

```json
{
  "compiler-version": "nocturne 0.1.0",
  "language-version": "1.0",
  "runtime-version": "1.0",
  "circuits": [
    {
      "name": "increment",
      "pure": false,
      "proof": true,
      "arguments": [],
      "result-type": { "type-name": "Tuple", "types": [] }
    }
  ],
  "witnesses": [],
  "ledger": [
    {
      "name": "count",
      "index": 0,
      "exported": true,
      "type": { "type-name": "Counter" }
    }
  ],
  "contracts": []
}
```

- `circuits[]` — one entry per `#[nocturne(circuit)]`. `pure` is `false` for state-mutating circuits (`&mut self`), `true` for read-only (`&self`). `proof: true` means a ZK proof is required to invoke (the default; the false case is reserved for future "no-proof" circuit shapes).
- `witnesses[]` — declared witness fields and parametric witness methods, named with a `private$` prefix (`private$voter_secret`). Used by code generators to produce client-side types that match the prover's expected layout.
- `ledger[]` — one entry per `#[nocturne(ledger)]` struct field, in declaration order. `index` is the field's slot index in the on-chain state array; `exported` tells downstream tools whether to advertise the field as queryable. Mark a field `#[nocturne(private)]` to set `exported: false`; the field still lives on-chain (all ledger state is public on Midnight), it's just dropped from the advertised query surface.
- `contracts[]` — reserved for cross-contract call metadata.

**Schema**: matches Compact's `contract-info.json` schema. The same downstream type generators, indexers, and deploy scripts that consume compactc output also work with Nocturne's. Compactc is the reference for the schema; this file deliberately mirrors it.

**Produced by**: the proc macro, written alongside `.zkir`. Same `write_if_changed` semantics — only touched when content changes.

**Consumed by**:
- TypeScript bindings generators (`@midnight-ntwrk/compact-runtime` and similar) — produce typed client wrappers from this file.
- Indexers and block explorers — discover circuit names, witness shapes, return types.
- Deploy scripts — pull the circuit list to know which verifier keys to register on-chain.

**Format**: pretty-printed JSON, typically a few hundred bytes to a few KB.

**Versioning**: `compiler-version` advances per Nocturne release. `language-version` and `runtime-version` track the Compact-language semantics the file is compatible with — bump when we land features that change the schema.

## The injected `transcript` and `deploy` submodules

These don't appear under `target/nocturne/`. They live inside the user's contract module as generated Rust:

```rust
pub mod my_contract {
    // user code...

    pub mod transcript {
        pub fn build_<circuit>_transcript(state?: &State, witnesses?: &Witnesses)
            -> TranscriptResult { /* generated */ }
    }

    pub mod deploy {
        pub fn initial_state(/* constructor params */) -> StateValue { /* generated */ }
    }
}
```

**`transcript::build_<circuit>_transcript(...)`** — one function per circuit. Returns the `Op` sequence and private-input `Fr`s the client submits on-chain. Called at call time (when a user wants to invoke a circuit), not at deploy time. The function signature depends on what the circuit reads: it takes `&State` if the circuit reads ledger state (Map::contains, Cell::get, ...), and `&Witnesses` if the circuit has any `#[nocturne(witnesses)]` parameter.

**`deploy::initial_state(...)`** — one function per contract. Calls the user's constructor at runtime and encodes each ledger field into the on-chain `StateValue` tree. The function forwards the constructor's parameter list verbatim, so `fn new(admin: Bytes<32>, fee: u64)` produces `initial_state(admin: Bytes<32>, fee: u64) -> StateValue`.

**Consumed by**: the client-side application. midnight-rs (or whatever downstream you wire up) calls these directly — no JSON intermediary, no separate runtime library. The transcript builder gets you the on-chain ops; the initial_state builder gets you the `StateValue` to submit at deploy.

**Visibility**: emitted at `pub` so any crate that depends on the contract crate can import them. They participate in normal Rust compilation, so type errors at the call site are surfaced like any other Rust error.

## Summary table

| Artifact | Format | Produced by | Consumed by |
|---|---|---|---|
| `<circuit>.zkir` | JSON | proc macro at `cargo build` | `keygen`, midnight-rs |
| `<circuit>.prover` | binary | `cargo nocturne build`/`keygen` | midnight-rs (proving) |
| `<circuit>.verifier` | binary | `cargo nocturne build`/`keygen` | on-chain ledger, off-chain verifiers |
| `contract-info.json` | JSON | proc macro at `cargo build` | type generators, indexers |
| `transcript::build_*` | Rust | proc macro | midnight-rs (transcript construction) |
| `deploy::initial_state` | Rust | proc macro | midnight-rs (deploy) |
