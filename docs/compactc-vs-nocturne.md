# Compactc vs Nocturne

A reference for anyone coming from Compact (or comparing the two toolchains). Covers what's structurally the same, where the two compilers diverge, and what the wire-level consequences are.

Nocturne isn't bound to match compactc; both produce artifacts that midnight-ledger accepts, but the source surface, IR shape, and per-circuit constraint counts often differ. Where it's cheap to match, we do (artifact layout, `contract-info.json` schema); where Rust enables something cleaner, we don't (true sum types, generic wrappers, `if`-as-expression).

## Layers

| Layer | Compactc | Nocturne |
|---|---|---|
| Source language | `.compact` DSL | Rust modules annotated with `#[nocturne::contract]` |
| Mid-level AST | internal to the compactc binary, not serialised to disk | `ExprIR` in [`crates/nocturne-ir`](../crates/nocturne-ir) — same role, also not user-facing |
| Client runtime emit | generated TypeScript (`contract/index.js` + `.d.ts`) | injected Rust submodules (`contract::transcript`, `contract::deploy`) |
| Wire-level emit | `IrSource`/`Instruction` (ZKIR), `Vec<Op>` (transcript), `StateValue` (state) | Same — imported directly from `midnight-zkir`, `midnight-onchain-vm`, `midnight-onchain-state` |

Both compilers also emit `contract-info.json` with the same schema, so downstream tools (TypeScript bindings generators, indexers, deploy scripts) that consume compactc output also work with Nocturne.

The "client runtime emit" row is where the two compilers visibly diverge in the artifact set: compactc ships a TypeScript module that builds transcripts and `ProofPreimage`s at call time, while Nocturne injects equivalent Rust functions into the user's contract module. Both are pure codegen targets — the source AST that drives them stays internal to the respective compiler. A third backend (e.g. TypeScript from Nocturne, or a different host language from compactc) would slot in alongside without changing the AST layer.

## Source surface (different by design)

| Concept | Compactc | Nocturne |
|---|---|---|
| Composition unit | standalone `.compact` file | Rust crate / module |
| Ledger declaration | `ledger x: T;` keyword | wrapper-typed struct field (`Counter`, `Cell<T>`, `Map<K, V>`, ...) |
| Method dispatch | language-built-in on `ledger` declarations | Rust trait dispatch on the wrapper types |
| Stdlib import | `import CompactStandardLibrary;` | `use nocturne::types::*;` |
| Build | `compactc file.compact out/` | `cargo nocturne build` |

The Rust crate model brings ordinary `cargo` workflows: test/format/lint, dependency graphs, doc generation. The trade-off is more boilerplate per contract than the dedicated DSL.

## Mid-level IR

Both compilers have a typed AST of circuit bodies between the parser and the codegen. Compactc's lives inside compactc; Nocturne's is `ExprIR`. They sit at the same abstraction level: control-flow constructs (`If`, `Match`), let bindings, method calls, witness/ledger field access, etc.

Nocturne's two backends (the ZKIR emitter in [`zkir_emitter.rs`](../crates/nocturne-codegen/src/zkir_emitter.rs) and the transcript emitter in [`transcript_codegen.rs`](../crates/nocturne-codegen/src/transcript_codegen.rs)) both consume `ExprIR`. Keeping a structured representation between parsing and codegen avoids re-walking `syn::Expr` twice.

One structural difference is worth knowing: compactc's IR is a hybrid of AST and lowered bytecode. Its `ledger-query` nodes embed the on-chain VM ops (`dup`, `idx`, `push`, `popeq`, ...) inline in the tree, so the IR can drive a transcript builder directly. Nocturne's `ExprIR` is a pure AST; the on-chain ops are derived at lowering time, independently per backend. The trade-off: compactc's IR is a fuller snapshot of the build output, while Nocturne's stays easier to retarget. Adding another backend (say, TypeScript output) is a codegen-layer change for Nocturne, whereas a new compactc backend has to ignore or re-derive the inlined ops.

## Where the IR-level choices show up on-chain

These are the cases where the two compilers produce different ZKIR or transcript output for an equivalent contract. None of them break on-chain compatibility, but they make byte-for-byte verifier-key equivalence impossible beyond the counter contract.

### 1. Mutable boolean storage

| Compactc | Nocturne |
|---|---|
| `ledger b: Boolean;` (dedicated boolean cell with `Cell::write` ops) | `pub b: Cell<bool>` (generic `Push` + `Ins`) |

Same on-chain semantics, different VM opcode sequence. The counter contract avoids this divergence because it doesn't have a boolean cell; the moment a contract uses `Cell<bool>` the verifier keys stop matching.

### 2. Branch zeroing

Both compilers wrap each branch's `DeclarePubInput` in `cond_select(guard, value, ZERO)` so the inactive branch contributes zero to the verifier's PI vector (matching `Op::Noop`'s zero `field_repr`). The difference is optimisation:

- **Compactc** opportunistically reuses values that happen to be zero in the inactive case, saving constraints.
- **Nocturne** always emits the `cond_select` wrap.

Same on-chain transcript; different constraint counts. The invariant both compilers satisfy: the ledger replaces inactive transcript segments with `Op::Noop { n }`, which contributes `n` zero field elements to the verifier's public inputs, so every public input declared inside a conditional branch must evaluate to zero when the branch is inactive.

### 3. `Maybe<T>` / `Vector<N, T>` vs `Option<T>` / `[T; N]`

Compactc has `Maybe<T>` and `Vector<N, T>` as built-in struct types where all fields are always materialised (the tag is just a boolean discriminant; the payloads coexist unconditionally).

Nocturne maps these to plain Rust `Option<T>` and `[T; N]`. The wire shape matches Compact's by design:

- `Option<T>` ↔ `Maybe<T>` ↔ `(Bytes<1>, T)` (via upstream `impl<T: Aligned> Aligned for Option<T>`).
- `[T; N]` ↔ `Vector<N, T>` ↔ N-tuple of T (via upstream `tuple_aligned!`).

Different source surface, different IR variants (`ExprIR` has `ArrayLit` and `Index` for arrays, plus an `EnumPayload` projection that handles `Option` as a synthetic enum-like), but the bytes match. Both encodings ride on upstream `Aligned` impls in midnight-ledger's `base-crypto/src/fab/alignments.rs`; the N ≤ 11 array ceiling comes from the largest `tuple_aligned!` impl upstream provides.

### 4. Sum types

Compactc has no true sum-of-products. It models tagged unions via `Maybe` and `Either` structs where all variants' payloads coexist on chain.

Nocturne has real Rust enums with two encodings shipped:

- **Unit-only** (`enum E { A, B, C }`) → `Bytes<1>` discriminant.
- **Homogeneous payload** (`enum E { A(T), B(T) }` where every variant carries the same `T`) → `(Bytes<1>, T)`.

Heterogeneous-payload enums (`enum E { A(u64), B(Bytes<32>) }`) aren't expressible in Compact and are open in Nocturne pending a decision on the wire shape (compactc-style all-variants-materialized vs a tagged union). The choice affects every downstream consumer, so it needs a written design decision before codegen targets it.

### 5. Environment context (`kernel.self()`, block height, caller)

Compactc lowers these to `Idx` instructions into a designated `kernel` ledger field that the on-chain runtime pre-populates with the live values before transcript replay.

The on-chain VM (`onchain-vm/src/ops.rs` in midnight-ledger) has no dedicated opcode; the slot layout isn't documented externally. Until upstream confirms the canonical field index and the runtime injection contract, Nocturne can't emit a matching `Idx`.

### 6. `if`-as-expression

Compactc treats `if`/`else` as statements: branches can write to state but don't bubble a result back.

Nocturne supports `if`-as-expression: `let x = if cond { a } else { b };` lowers to `cond_select(cond, a, b)` at the ZKIR layer and a Rust `if`-expression on the transcript side. The contract can then bind the multiplexed result and use it downstream, all in plain Rust. No equivalent in Compact's source surface.

## What's identical

The wire boundary stays bit-for-bit upstream:

- `midnight-zkir::{IrSource, Instruction}` for circuit definitions.
- `midnight-onchain-vm::Op` for transcript ops.
- `midnight-base-crypto::fab::AlignedValue` for serialised values.
- `midnight-onchain-state::state::StateValue` for ledger state.
- `midnight-transient-crypto` curves, hashes, and proof helpers.

Whatever IR shape either compiler chooses internally, what eventually goes on-chain is byte-comparable wherever the two compilers happen to make the same encoding choices. The counter contract is the standing proof: both compilers emit verifier keys that diff to zero. See [`tests/golden/counter-increment.verifier`](../tests/golden/counter-increment.verifier).

## How equivalence is tested

The golden test only scales to circuits where the two compilers happen to produce structurally equivalent ZKIR; the divergences above (boolean cells, branch-zeroing optimizations) make byte-level VK equality impossible for anything richer than the counter. Nocturne doesn't chase VK equality there. The general on-chain compatibility gate is the integration test suite in `crates/nocturne/tests/`, which drives Nocturne's artifacts through midnight-ledger's canonical prove/verify path; goldens are a sanity check on the subset where byte equality is feasible. See [`tests/golden/README.md`](../tests/golden/README.md).
