# `Cell::set` on-chain encoding — closed for typed primitives

**Discovered**: 2026-05-18 (during Stage 0 of Map work)
**Status** (updated 2026-06-11): closed for typed primitives (`Cell<bool>`, `Cell<UintN/u8..u128>`), `Bytes<N>` including multi-Fr (Push + Popeq), `Field` (see [[field-alignment-encoding]]), and `Map`/`Set` ops including multi-Fr `Bytes<N>` K/V. Custom ADTs (multi-field structs) remain on the non-compatible 2-declare fallback.

## What landed

The on-chain pattern (from empirical compactc 0.30.0 emission) is:

```
Op::Push { storage: false, value: StateValue::Cell(AlignedValue::from(field_idx)) }  // KEY
Op::Push { storage: true,  value: StateValue::Cell(AlignedValue::from(value)) }      // VALUE
Op::Ins  { cached: false, n: 1 }                                                     // arr[key] = value
```

No `Idx` — the contract state is a top-of-stack `StateValue::Array`, and `Ins { n: 1 }` pops `[value, key, container]` and inserts directly. The two `Push` ops differ in `storage`: Weak (false) for the key, Strong (true) for the value. See `reference-repos/midnight-ledger/onchain-vm/src/vm.rs:631` for the strength tagging.

### IR side (`zkir_emitter.rs::emit_ledger_write`)

Emits a `Push` group per the encoding table:
- KEY: `aligned_value_encoding_bytes(1)` → 5 declares: `[0x10, 1 (cell_disc), 1, 1 (alignment), field_idx]`
- VALUE: `aligned_value_encoding(inner_ty)` for known T (Boolean, u8..u128, Uint<N≤253>) → 5 declares: `[0x11, 1, 1, ceil(N/8), value]`. For unknown T → 2-declare fallback `[0x11, value]` (not on-chain compatible).
- Ins: 1 declare `[0x91]`.

### Transcript side (`transcript_codegen.rs`, `"set"` arm)

Emits matching runtime ops:
```rust
ops.push(Op::Push { storage: false, value: StateValue::Cell(Sp::new(AlignedValue::from(field_idx))) });
ops.push(Op::Push { storage: true,  value: StateValue::Cell(Sp::new(AlignedValue::from(value))) });
ops.push(Op::Ins  { cached: false, n: 1 });
```

`arg_to_runtime_expr` materializes the value expression: handles `Literal`, `Disclose`, `WitnessAccess`, `Var`, `MethodCall` (passing through `.into()`/`.value()`), `Reference`.

### Verified by

`crates/nocturne/tests/ledger_integration_test.rs::flag_raise_proves_and_verifies` — a `Cell<bool>::set(true)` circuit that:
1. constructs through `ContractCallExt::construct_proof`
2. `ir.prove(...)` returns PIs matching `[binding_input, comm, ..field_repr(transcript)]`
3. `vk.verify(...)` accepts those ledger-shape PIs.

### Cell::get / Counter::value on-chain reads also landed

The corresponding read path (Dup + Idx + Popeq) had the same shape bug
as `Cell::set` before it: `emit_ledger_read` declared only the Popeq
opcode (1 declare), missing the alignment + value declares. Fixed to
emit the full 4-declare Popeq `[0x0d, segment_count, atom, value]`
with `cached:true` (matching compactc and `Map::contains`' trailing
Popeq).

The transcript builder for circuits with reads now takes
`state: &<LedgerName>` (same as Map::contains needed) so it can
compute the actual Popeq result via `state.<field>.value()` (Counter)
or `state.<field>.get()` (Cell<T>). `primitive_cast_for_type` applies
to the read-result so the runtime AlignedValue alignment atom matches
the IR's encoding for each type.

End-to-end verified by `cell_get_proves_and_verifies` and
`counter_value_proves_and_verifies` in `ledger_integration_test.rs`.

### Cell<Bytes<N>>::set also landed (multi-Fr Push)

`emit_push_cell` now takes `value_vars: &[Index]` instead of a single
`Index`, so multi-Fr values flow through it correctly:

- `aligned_value_encoding(Bytes<N>)` returns
  `{ alignment_atoms: [1, N], value_field_count: ceil(N / 31) }`.
- The Cell::set dispatcher uses `gather_value_vars` to collect the
  contiguous PrivateInput indices the WitnessAccess emitted (relies on
  the invariant that multi-Fr witnesses emit their `ceil(N/31)`
  PrivateInputs contiguously and uninterrupted).
- The transcript codegen `aligned_value_arg_expr` produces
  `*(witness.<f>.clone()...).as_bytes()` for `Bytes<N>` values so
  `AlignedValue::from([u8; N])` runs the same alignment-and-chunking
  the IR's Push declares expect.
- `arg_to_runtime_raw_expr` now handles `MethodCall` directly (was
  falling through to the unwrapping `.value()` path), so chains like
  `.clone()` on a `Bytes<N>` witness preserve the wrapper.

E2E test: `ledger_integration_test::cell_bytes32_set_proves_and_verifies`.

### Cell<Bytes<N>>::get also landed (multi-Fr Popeq)

The read side now mirrors the multi-Fr Push:

- `emit_ledger_read` emits one `PublicInput` per Fr the result occupies
  (driven by `aligned_value_encoding(T).value_field_count`), with
  per-chunk `ConstrainBits` from a new `read_result_fr_layout(ty)`
  helper that mirrors `witness_fr_layout` for read-result types.
- Transcript codegen `get`/`value` arm produces the right
  `AlignedValue::from(...)` expression for the read result: for
  `Bytes<N>` it uses `*(state.<f>.get()).as_bytes()`, otherwise the
  primitive-cast path.

E2E test: `ledger_integration_test::cell_bytes32_get_proves_and_verifies`.

Cell<Bytes<N>> is now fully on-chain compatible end-to-end.

### Map<Bytes<N>, _> also landed (multi-Fr K through Idx + Push)

All four Map primitives (`contains`, `lookup`, `insert`, `remove`) now
support multi-Fr `Bytes<N>` keys and values:

- `emit_map_method` collects `key_vars`/`val_vars` via `gather_n_vars`
  based on each side's `value_field_count`.
- `emit_map_member`/`emit_map_insert`/`emit_map_remove` reuse the
  multi-Fr `emit_push_cell(value_vars: &[Index], ...)` from Cell::set.
- `emit_map_lookup` iterates `key_vars` into its second `Idx`
  (path entry = `[seg_count, ..atoms, ..value_frs]`) and uses
  `read_result_fr_layout` for the multi-Fr Popeq result (same pattern
  as Cell<Bytes<N>>::get).
- Transcript codegen unified to use `aligned_value_arg_expr(expr, ty)`
  for all Map K/V expressions (Bytes<N> → `*<raw>.as_bytes()`,
  primitives → `as u<N>`). `unwrap_to_aligned_primitive` gained a
  `Bytes<N>` arm for `Map::lookup`'s Popeq result.

E2E tests: `ledger_integration_test::map_bytes_{insert,contains,
lookup,remove}_proves_and_verifies` for `Map<Bytes<32>, Uint<64>>`.

## What still needs work

1. **Custom ADTs**: structs with multiple typed fields fall back to 2-declare emission. They are NOT on-chain compatible. Everything else listed in the original gap has landed: multi-Fr `Bytes<N>`, `Cell<Field>` ([[field-alignment-encoding]]), and all four Map primitives including insert/remove (`map-ledger-field-encoding.md`).

## Files

- IR emission: `crates/nocturne-codegen/src/zkir_emitter.rs::emit_ledger_write` + `emit_push_cell` + `aligned_value_encoding` table
- Transcript emission: `crates/nocturne-codegen/src/transcript_codegen.rs`, `"set"` arm + `arg_to_runtime_expr`
- E2E test: `crates/nocturne/tests/ledger_integration_test.rs::flag_raise_proves_and_verifies`
- Empirical compactc reference: `/tmp/compact-voting/zkir/end_ballot.zkir` (build with `compactc /tmp/voting.compact /tmp/compact-voting`)
- Related: `memories/map-ledger-field-encoding.md`
