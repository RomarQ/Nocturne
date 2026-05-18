# `Cell::set` on-chain encoding — closed for typed primitives

**Discovered**: 2026-05-18 (during Stage 0 of Map work)
**Status**: closed for `Cell<bool>` and `Cell<UintN/u8..u128>` via the Push+Push+Ins pattern. Multi-Fr value types (`Bytes<N>`, `Field`, custom ADTs) still fall back to the legacy 2-declare emission.

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

`crates/midnight/tests/ledger_integration_test.rs::flag_raise_proves_and_verifies` — a `Cell<bool>::set(true)` circuit that:
1. constructs through `ContractCallExt::construct_proof`
2. `ir.prove(...)` returns PIs matching `[binding_input, comm, ..field_repr(transcript)]`
3. `vk.verify(...)` accepts those ledger-shape PIs.

## What still needs work

1. **Multi-Fr value types**: `Bytes<N>` for `N*8 > 64`, custom ADTs, and `Field` (which uses `AlignmentAtom::Field`, not `Bytes{N}`) fall back to 2-declare emission. They are NOT on-chain compatible. To support: extend `aligned_value_encoding` to return a `value_field_count > 1`, and update `emit_push_cell` to emit one declare per Fr in the value.

2. **Map::insert** (next stage): reuses the same Push pattern, twice — once for the K-typed key (so the generic `emit_push_cell` already covers it), once for the V-typed value. Just needs the dispatcher to route `insert` to the same emit path with K, V types resolved from the `Map<K, V>` field type. See `map-ledger-field-encoding.md`.

3. **Map::remove / Cell::clear**: uses `Rem` (0x19/0x1a) instead of `Ins`. Smaller surface area.

## Files

- IR emission: `crates/midnight-codegen/src/zkir_emitter.rs::emit_ledger_write` + `emit_push_cell` + `aligned_value_encoding` table
- Transcript emission: `crates/midnight-codegen/src/transcript_codegen.rs`, `"set"` arm + `arg_to_runtime_expr`
- E2E test: `crates/midnight/tests/ledger_integration_test.rs::flag_raise_proves_and_verifies`
- Empirical compactc reference: `/tmp/compact-voting/zkir/end_ballot.zkir` (build with `compactc /tmp/voting.compact /tmp/compact-voting`)
- Related: `memories/map-ledger-field-encoding.md`
