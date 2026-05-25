# Project scope: Nocturne is an authoring eDSL, not a chain client

**Discovered**: 2026-05-18 (user clarification)

Nocturne is an embedded DSL in Rust for **writing** Midnight smart contracts. Its responsibility ends at producing artifacts (`zkir/*.zkir`, `zkir/*.prover`, `zkir/*.verifier`, `compiler/contract-info.json`) that downstream tooling can deploy and call on a Midnight node.

## In scope

- The `#[midnight::contract]` proc-macro frontend
- ZKIR generation (`crates/nocturne-codegen`)
- Compile-time transcript-builder generation
- `keygen` (via `cargo midnight keygen` → midnight-zkir)
- `contract-info.json` matching Compact's schema
- Type system: ledger types (Counter, Cell, Map, MerkleTree, ...), witness types (Boolean, Field, Uint<N>, Bytes<N>)
- Compile-time correctness checks and clear errors for unsupported patterns
- Verification that emitted artifacts are on-chain compatible — done through `midnight-ledger` integration tests, not by deploying to a node

## Out of scope

- Deploying contracts to a real Midnight node
- Building transactions (`Intent::add_call`, transaction signing)
- Wallet management
- Node RPC / indexer queries
- `cargo midnight deploy` / `cargo midnight call` CLI commands

Anything that talks to a running Midnight node belongs in a downstream tool such as [`midnight-rs`](https://github.com/RomarQ/midnight-rs) or Compact's TypeScript runtime.

## How to apply

- When prioritizing work, weight features that improve **authoring** (more types, better errors, more language patterns supported). Deprioritize anything that touches transaction construction or node RPC.
- When validating "is this on-chain compatible," reach for `crates/midnight/tests/ledger_integration_test.rs` (drives Nocturne artifacts through midnight-ledger's canonical code path). Don't propose standing up a Midnight node.
- When a user asks "how do I deploy this," point them at midnight-rs or another SDK — don't propose building deployment into Nocturne.
