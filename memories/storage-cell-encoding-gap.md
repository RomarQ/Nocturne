# `Cell::set` / `Map::insert` are not on-chain compatible today

**Discovered**: 2026-05-18 (during Stage 0 of Map work)
**Status**: known gap. Helper scaffolding (`AlignedValueEncoding`, `aligned_value_encoding`, `extract_cell_inner_type`, `emit_push_cell`) is in `crates/midnight-codegen/src/zkir_emitter.rs` ready for use; call sites + transcript codegen are the next-stage work.

## What's broken

`emit_ledger_write` in `crates/midnight-codegen/src/zkir_emitter.rs` emits a placeholder 2-declare Push group: `[Push opcode (0x10), value]`. The matching transcript codegen in `crates/midnight-codegen/src/transcript_codegen.rs::generate_op_stmt` for the `"set"` arm emits **no `Op::Push` at all** — just `Op::Idx` followed by `Op::Ins`. The IR and the transcript builder are jointly consistent (both wrong in the same way), so existing local prove+verify passes, but **neither matches what midnight-ledger / compactc expect on-chain**.

## What the on-chain encoding actually looks like

Empirical compactc 0.30.0 emission for `b.write(disclose(true))` where `ledger b: Boolean`:

```
group 1 (count=5): Push storage=false, Cell discriminant, alignment [1, 1], value (encoded as 2)
group 2 (count=5): Push storage=true,  Cell discriminant, alignment [1, 1], value (encoded as 1)
group 3 (count=1): Ins cached=false, n=1  (0x91)
group 4 (count=1): Ins cached=true,  n=1  (0xa1)
```

Two open questions before we can match this:

1. **Why two Pushes?** One has `storage: false`, the other `storage: true`. Probably one pushes the "transient" representation, the other the "storage" representation, and the two `Ins` ops combine them. Need to read `midnight_ledger::onchain_runtime` / `onchain_vm`'s VM execution for `Push` + `Ins` to confirm.

2. **Why are the encoded values different (2 vs 1) for `true`?** Compact may encode Boolean via an enum tag offset, or one of the pushes might carry a type discriminant instead of the literal value. Same investigation as (1).

## What Stage 0 actually landed

- `AlignedValueEncoding` struct, `aligned_value_encoding(ty)` function, `extract_cell_inner_type(ty)` function, and `emit_push_cell(value_var, encoding, storage)` method on `ZkirEmitter`. All currently `#[allow(dead_code)]` — they encode the per-type alignment + value width that the eventual Push emission will need.
- `ZkirEmitter` now carries `field_types: Vec<syn::Type>` parallel to `field_names`, so future call sites can look up the inner `T` of `Cell<T>` (or `K`/`V` of `Map<K, V>`) at the call site.

The helpers only handle 1-Fr value types (Boolean, `u8..u64`, `Uint<N>` for N ≤ 64). Multi-Fr types like `Bytes<32>` are explicitly `None` until we add multi-Fr emission.

## What needs to land next

1. Read the VM exec for `Push` + `Ins` to confirm the two-Push pattern (storage vs transient).
2. Update `transcript_codegen.rs::generate_op_stmt`'s `"set"` arm to emit the matching `Op::Push { ... }` sequence so the runtime transcript carries the right ops.
3. Wire `emit_push_cell` into `emit_ledger_write` with the right pattern.
4. Add a `ledger_integration_test` that proves+verifies a `Cell<bool>::set(true)` circuit through the canonical `ContractCallExt::construct_proof` path — the test I tried to add in this turn (`flag_raise_proves_and_verifies`), reverted pending the encoding fix.
5. Generalize to `Map::insert`, which reuses the same Push-Cell encoding twice (once for the key, once for the value).

## Files

- Helpers: `crates/midnight-codegen/src/zkir_emitter.rs` (search for `AlignedValueEncoding`, `aligned_value_encoding`, `extract_cell_inner_type`, `emit_push_cell`)
- Broken call site (IR): `crates/midnight-codegen/src/zkir_emitter.rs::emit_ledger_write` — has the TODO comment pointing here
- Broken call site (transcript): `crates/midnight-codegen/src/transcript_codegen.rs::generate_op_stmt`, `"set"` arm
- Empirical compactc reference: `/tmp/compact-voting/zkir/end_ballot.zkir` (build with `compactc /tmp/voting.compact /tmp/compact-voting`)
- Related: `memories/map-ledger-field-encoding.md` (uses the same Push pattern, blocked on the same gap)
