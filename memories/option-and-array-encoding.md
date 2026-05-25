# Option<T> and [T; N] encoding

**Discovered**: 2026-05-20 (commits 3e4a086 + 6601cc8).

## What

Two compactc-equivalent value types reachable from plain Rust syntax:

- `Option<T>` → wire shape `(Bytes<1>, T)`. Same as Compact's `Maybe<T>`.
- `[T; N]` for `1 ≤ N ≤ 11` → wire shape N-tuple of T (`(T, T, ..., T)`). Same as Compact's `Vector<N, T>`.

Both ride on upstream's tuple `Aligned` impl in `reference-repos/midnight-ledger/base-crypto/src/fab/alignments.rs:49` and `:59`. The N=11 ceiling for arrays comes from `tuple_aligned!(A, B, C, D, E, F, G, H, I, J, K)` at line 59 — no upstream impl for tuples of arity ≥ 12. Arrays of `[T; 12+]` need either an upstream extension or a nested-tuple decomposition (out of scope today).

## Why

- `Option<T>` is recognised as a synthetic enum-like in `transcript_codegen.rs::is_enum_like` (via `is_option_type`) and `zkir_emitter.rs::aligned_value_encoding`. Same `(Bytes<1>, T)` composition the homogeneous-payload user-enum path uses. The `None` case synthesises `<T as Default>::default()` for the payload Fr — the payload slot must still produce a wire shape that aligns, even when no payload exists. This is why every type used inside `Option<T>` in a Nocturne contract must implement `Default` (all primitives, Bytes<N>, Field, Uint<N>, MerkleTreeDigest, Boolean already do).
- `[T; N]` is recognised in `aligned_value_encoding`, `witness_fr_layout`, `aligned_value_arg_expr`, and `component_private_push` by an `extract_array_type` helper that pulls `(elem_ty, n)` from `syn::Type::Array` with an integer-literal length. `ExprIR::Index { array, index: u32 }` is the IR variant; the parser only accepts compile-time integer literal indices.

## Implications

### Match on Option

`match witnesses.maybe { Some(x) => ..., None => ... }` lowers via the same machinery as `match w.enum { V(p) => ... }`. The parser uses a synthetic `"Option"` enum_name marker on `ExprIR::EnumPayload` so codegen can short-circuit without consulting `user_enums`. Map-get sugar (`memories/map-get-sugar.md`) runs *before* the generic Option lowering — otherwise it would steal the scrutinee.

### Array indexing in circuit bodies

`witnesses.arr[i]` works when `i` is a literal. For dynamic indices, use `for i in 0..N { ... arr[i] ... }` — `parse_const_for_loop` unrolls the loop body with `i` substituted as a literal, which then parses to `ExprIR::Index { index: <lit> }`. Non-literal indices produce `ExprIR::Unsupported` (compile_error pointing the user at the for-loop workaround).

### Witness allocation is array-wide on first touch

`witness_fr_layout` for `[T; N]` returns `N * len(T_layout)` entries in declaration order. The ZKIR's `WitnessAccess` arm allocates ALL N×len(T) `PrivateInput` slots on first reference to the field — `ExprIR::Index` then offsets into the contiguous block (`first + index * len(T_layout)`). Consequence: even if a circuit only reads `arr[0]`, the prover must provide N×len(T) Fr values in `private_transcript_outputs`. The same is true for `Option<T>` — touching the witness allocates both the disc slot and the payload's slot(s), regardless of which branch the runtime path takes.

### Scope today

Witness-sourced arrays and Cell::set value positions are wired. Let-bound arrays and `Cell<[T; N]>` read paths (`Cell::get` on an array-typed Cell) are NOT — `Cell::get`'s Popeq path doesn't decompose tuple-shape values element-by-element, and the variables map carries no type info to thread an `ExprIR::Index` over a let-bound `arr`.

Mutable indexed writes (`arr[i] = v`) and dynamic indices are out of scope.

### Wire compatibility with Compact

`Option<T>` and `[T; N]` deserialise from compactc-emitted on-chain transcripts (and vice versa) without any glue — they use the upstream `Aligned for Option<T>` and `Aligned for (T1, ..., Tn)` impls directly. Indexers and type generators that already understand Compact's `Maybe<T>` / `Vector<N, T>` need no Nocturne-specific casing.

## Tests

- `option_some_payload_proves_and_verifies`, `option_none_branch_proves_and_verifies` in `crates/nocturne/tests/ledger_integration_test.rs`.
- `array_witness_index_proves_and_verifies` (same file). The test commits to all three `Uint<64>` array elements via `private_transcript_outputs` even though only `arr[1]` is wired into the Cell::set; the ZKIR pre-allocated all 3 slots on first witness touch.

## Related

- [compactc-vs-nocturne-divergences.md](compactc-vs-nocturne-divergences.md) — heterogeneous-payload enums are still open; Option<T>/Vector<N> are now in the "shipped" column.
- [scope-blockers.md](scope-blockers.md) — entries under "What's NOT a blocker (recently shipped)".
- [conditional-branch-cond-select-zeroing.md](conditional-branch-cond-select-zeroing.md) — how branches gate their per-Fr pushes; relevant when an Option's `None` branch is hit at runtime.
