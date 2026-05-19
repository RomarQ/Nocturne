# `Set<T>` ledger field — encoding

**Discovered/implemented**: 2026-05-19 (empirical sweep against compactc 0.22 for `Set<Bytes<32>>`)
**Status**: Implemented end-to-end. Tests: `set_{insert,contains,remove}_proves_and_verifies` in `crates/midnight/tests/ledger_integration_test.rs`.

## On-chain representation

`StateValue` has no dedicated `Set` variant (`onchain-state/src/state.rs:79-98`). Set reuses `StateValue::Map` with `StateValue::Null` as the placeholder value — every set element is stored as `(key, Null)` in the underlying HashMap.

This means the three Set primitives share opcodes with their Map counterparts and differ only in the value being pushed at insert time:

| Op | Set encoding | Same as Map? |
|---|---|---|
| `contains` / `member` | Dup + Idx + Push(Cell(key)) + Member + Popeq(bool) | identical to `Map::contains` |
| `insert` | Idx{push_path:true} + Push(Cell(key)) + **Push(Null)** + Ins + Ins | value Push differs |
| `remove` | Idx{push_path:true} + Push(Cell(key)) + Rem + Ins | identical to `Map::remove` |

## The `Push(Null)` encoding

`StateValue::Null::field_repr` is a single field element `0` (`state.rs:176`). So `Push { storage: true, value: StateValue::Null }` declares as `[0x11, 0]` — **2 declares total**, vs. `[0x11, Cell_disc, ..alignment, ..value_frs]` for a typed value Push.

That's the entire on-chain difference between Set::insert(k) and Map::insert(k, Null).

## Implementation

- **Storage** (`crates/midnight-storage/src/set.rs`): `Set<T: Eq + Hash + Clone>` backed by `HashSet<T>`. HashSet-style API: `contains(&T) -> bool`, `insert(T) -> bool`, `remove(&T) -> bool`.
- **IR** (`crates/midnight-codegen/src/zkir_emitter.rs::emit_set_method`): dispatch by method name; reuses `emit_map_member`/`emit_map_remove`, adds `emit_set_insert` which calls `emit_push_cell(key) + emit_push_null(storage:true)` instead of two `emit_push_cell` calls. `emit_push_null` is a 2-declare helper: `[push_opcode, 0]` + PiSkip{count:2}.
- **Transcript codegen** (`crates/midnight-codegen/src/transcript_codegen.rs`): dispatch by field type. `extract_field_key_type` unifies `Map<K, V> → K` and `Set<T> → T` so `generate_map_contains_block` is reused for both. New `generate_set_insert` and `generate_set_remove` mirror the Map equivalents; `generate_set_insert` emits `Op::Push { storage: true, value: StateValue::Null }` for the value slot.

## Empirical compactc reference

`/tmp/set-experiments/out/zkir/{add,check,erase}.zkir` for the Compact source:

```
ledger members: Set<Bytes<32>>;
export circuit add(k: Bytes<32>): []     { members.insert(disclose(k)); }
export circuit check(k: Bytes<32>): Boolean { return members.member(disclose(k)); }
export circuit erase(k: Bytes<32>): []   { members.remove(disclose(k)); }
```

Reproduce with `compactc /tmp/set-experiments/set.compact /tmp/set-experiments/out` (requires `pragma language_version 0.22` and `import CompactStandardLibrary`).

## Limitations

- Like Map, multi-Fr value types beyond `Bytes<N>` (custom ADTs, `Field`) aren't supported.
- Set::contains/insert/remove inside conditional branches inherits the [[conditional-io-guards]] and [[conditional-branch-cond-select-zeroing]] machinery — not explicitly e2e-tested for Set yet but the same code paths cover it.
