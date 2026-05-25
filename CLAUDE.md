# Project guide for Claude Code agents

This is **Nocturne**, a Rust eDSL for **writing** Midnight smart contracts. It compiles `#[midnight::contract]` modules to ZKIR + transcript builders, generates Plonk proving/verifier keys, and emits a `contract-info.json` describing the contract's surface. The only hard constraint on output is that it stays compliant with `midnight-ledger`; surface syntax, IR shape, and artifact format are all open to do better where Rust's type system and metaprogramming enable something better.

**Scope**: Nocturne stops at producing artifacts. Deploying, building transactions, wallets, indexer/node RPC are explicitly **not** Nocturne's responsibility — they belong in downstream tools like [`midnight-rs`](https://github.com/RomarQ/midnight-rs). See `memories/project-scope.md`.

## Truth sources

When you need to know how Midnight's on-chain protocol actually behaves, **read the source**, do not infer:

- **midnight-ledger ledger-8 branch**: https://github.com/midnightntwrk/midnight-ledger/tree/ledger-8 — the canonical implementation of ledger semantics, ZKIR VM (zkir/), on-chain VM (onchain-vm/), transaction construction (ledger/src/construct.rs), and verification (ledger/src/verify.rs).
- **Local mirror**: `reference-repos/midnight-ledger/` (gitignored) — same content if cloned locally, faster to grep.

When upstream and our local mirror disagree, the GitHub branch wins.

## `memories/` — durable findings

Non-obvious truths about the upstream protocol, architectural decisions, and known divergences from compactc live in `memories/`. **Read it before assuming, write to it after discovering.**

### When to write a memory

Write a new memory (or update an existing one) when you discover any of:

- A non-obvious behavior of midnight-ledger, midnight-zkir, midnight-onchain-vm, or any upstream crate that took source-reading to confirm.
- An architectural decision in Nocturne's emitter or runtime that wouldn't be guessable from the code alone (the *why*, not the *what*).
- A known divergence from compactc and the reason for it.
- A workaround for an upstream quirk, with the upstream file:line reference that justifies it.
- A protocol invariant that, if violated, breaks on-chain compatibility.

### When NOT to write a memory

- Step-by-step task progress (session-scoped, use TodoWrite or the conversation).
- Things already clear from the code with one grep (don't duplicate `git blame` or function signatures).
- General Rust or cryptography knowledge.
- Anything that would be better as a code comment on the specific call site.

### Memory file conventions

- One topic per file, named `kebab-case.md`.
- Lead with what (one sentence), then why (the upstream evidence with file:line), then implications (what code must do, what tests must check).
- Date the discovery in the file so future readers can sanity-check staleness.
- Link related memories with relative paths.
- Maintain `memories/INDEX.md` as a one-line-per-memory table of contents.

### When to read

- Before starting any task that touches the ZKIR emitter, transcript codegen, or anything that interacts with midnight-ledger types — scan `memories/INDEX.md` for relevant topics.
- When you're about to claim "X probably works on-chain" or "Y can be done by Z", check whether a memory already says otherwise.
- When a test fails in a way that mentions PI counts, commitments, transcript layout, or proof verification — there's likely a memory explaining the surrounding protocol.

## Persistence rule (inherited from user's global CLAUDE.md)

Do not stop at "needs investigation," "TODO," "unclear," or "worth a deeper look" when the relevant source is available. Read it and find the answer. A finding is not a result — investigate to a definitive answer (root cause + fix path) before reporting, unless it requires a destructive action or external decision that needs approval.

## Pending crate rename

Internal crates are still named `midnight-*` (`midnight-codegen`, `midnight-ir`, etc.). A rename to `nocturne-*` is pending. When editing manifests, leave the name as-is — don't preemptively rename.

## Common gotchas

- `midnight-storage` (our internal path crate) clashes with `midnight-storage` (the upstream ledger crate). When pulling in upstream storage types, rename: `midnight-ledger-storage = { package = "midnight-storage", version = "..." }`.
- The proc macro writes `target/midnight/<contract>/{zkir,compiler}/` from the workspace target dir (walks up 4 levels from `OUT_DIR`). To regenerate artifacts after a code change, you may need `cargo clean -p <contract_crate>` first — incremental builds don't re-run the macro.
- `cargo-midnight build` looks for `./target/midnight/` relative to CWD. Run it from the workspace root, not from an example crate's directory.
