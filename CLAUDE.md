# Project guide for Claude Code agents

This is **Nocturne**, a Rust eDSL for **writing** Midnight smart contracts. It compiles `#[nocturne::contract]` modules to ZKIR + transcript builders, generates Plonk proving/verifier keys, and emits a `contract-info.json` describing the contract's surface. The only hard constraint on output is that it stays compliant with `midnight-ledger`; surface syntax, IR shape, and artifact format are all open to do better where Rust's type system and metaprogramming enable something better.

**Scope**: Nocturne stops at producing artifacts. Deploying, building transactions, wallets, indexer/node RPC are explicitly **not** Nocturne's responsibility; they belong in downstream tools like [`midnight-rs`](https://github.com/RomarQ/midnight-rs).

## Truth sources

When you need to know how Midnight's on-chain protocol actually behaves, **read the source**, do not infer:

- **midnight-ledger ledger-8 branch**: https://github.com/midnightntwrk/midnight-ledger/tree/ledger-8, the canonical implementation of ledger semantics, ZKIR VM (zkir/), on-chain VM (onchain-vm/), transaction construction (ledger/src/construct.rs), and verification (ledger/src/verify.rs).
- **Local mirror**: `reference-repos/midnight-ledger/` (gitignored), same content if cloned locally, faster to grep.

When upstream and our local mirror disagree, the GitHub branch wins.

## Durable protocol findings

Non-obvious upstream behaviors, protocol invariants, and workarounds for upstream quirks are documented as WHY-comments at the relevant call sites, each with an upstream file:line reference that justifies it (e.g. why `do_communications_commitment` is unconditionally `true` in the ZKIR emitter). When you confirm a new non-obvious upstream behavior by source reading, leave that kind of comment where the code depends on it. Before claiming "X probably works on-chain", check whether a comment near the relevant emitter code already says otherwise.

## Persistence rule (inherited from user's global CLAUDE.md)

Do not stop at "needs investigation," "TODO," "unclear," or "worth a deeper look" when the relevant source is available. Read it and find the answer. A finding is not a result — investigate to a definitive answer (root cause + fix path) before reporting, unless it requires a destructive action or external decision that needs approval.

## Common gotchas

- The proc macro writes `target/nocturne/<crate>/<contract>/{zkir,compiler}/` into the workspace target dir (it honors `CARGO_TARGET_DIR`, otherwise walks up from `OUT_DIR`). To regenerate artifacts after a code change, you may need `cargo clean -p <contract_crate>` first; incremental builds don't re-run the macro.
- `cargo-nocturne` resolves the target directory via `cargo metadata`, so it works from any directory inside the workspace; outside a cargo project it falls back to `CARGO_TARGET_DIR`, then `./target`.
