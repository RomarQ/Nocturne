# `Map<K, V>` ledger field — encoding investigation

**Discovered**: 2026-05-18 (empirical sweep against compactc 0.30.0)
**Status**: investigation, not yet implemented. `Map<K, V>` exists as an in-memory `HashMap` stub in `crates/midnight-storage/src/map.rs` with no ZKIR or transcript codegen yet.

## VM opcode reference (subset relevant to Map)

From `reference-repos/midnight-ledger/onchain-vm/src/ops.rs:400-462`:

| Opcode | Op | Field repr |
|---|---|---|
| `0x0c`/`0x0d` | `Popeq { cached, result }` | `[0x0c|0x0d, ..result.field_repr]` |
| `0x10`/`0x11` | `Push { storage: false|true, value }` | `[0x10|0x11, ..value.field_repr]` |
| `0x12` | `Branch { skip }` | `[0x12, skip]` |
| `0x13` | `Jmp { skip }` | `[0x13, skip]` |
| `0x14`/`0x15` | `Add` / `Sub` | `[0x14|0x15]` |
| `0x16`/`0x17` | `Concat { cached, n }` | `[0x16|0x17, n]` |
| `0x18` | `Member` | `[0x18]` |
| `0x19`/`0x1a` | `Rem { cached }` | `[0x19|0x1a]` |
| `0x30 \| n` | `Dup { n }` | `[0x30..0x3f]` (n in low nibble) |
| `0x40 \| n` | `Swap { n }` | `[0x40..0x4f]` |
| `0x50..0x5f` | `Idx { cached=false, push_path=false, len }` | opcode + path entries' field_repr |
| `0x60..0x6f` | `Idx { cached=true, push_path=false, len }` | same |
| `0x70..0x7f` | `Idx { cached=false, push_path=true, len }` | same |
| `0x80..0x8f` | `Idx { cached=true, push_path=true, len }` | same |
| `0x90 \| n` | `Ins { cached=false, n }` | `[0x90 \| n]` |
| `0xa0 \| n` | `Ins { cached=true, n }` | `[0xa0 \| n]` |
| `0xff` | `Ckpt` | `[0xff]` |

## Empirical compactc emission for `Map<Bytes<32>, Uint<64>>`

Source (`/tmp/cond-experiments/map.compact`):

```
ledger m: Map<Bytes<32>, Uint<64>>;
export circuit put(k: Bytes<32>, v: Uint<64>): []     { m.insert(disclose(k), disclose(v)); }
export circuit lookup(k: Bytes<32>): Uint<64>         { return m.lookup(disclose(k)); }
export circuit member(k: Bytes<32>): Boolean          { return m.member(disclose(k)); }
```

### `put` (insert): 5 transcript op groups

```
Idx(push_path=true, key=Bytes<32>)   → group of 4 declares: [0x70, align(2), key(1)]
Push(storage=false, value=...)        → group of 6 declares: [0x10, 0x20, align, value(2)]
Push(storage=true, value=...)         → group of 5 declares: [0x11, 0x08, align, value(1)]
Ins(cached=false, n=1) = 0x91         → 1 declare
Ins(cached=true,  n=1) = 0xa1         → 1 declare
```

The two non-opcode bytes `0x20` and `0x08` are **not** VM opcodes — they're internal discriminants inside `StateValue::field_repr`. Need to look up what the variants mean.

### `lookup` and `member` (read-only): use `Dup + Idx + Popeq` shape

Both circuits follow the same pattern (similar to the existing `emit_ledger_read` in `crates/midnight-codegen/src/zkir_emitter.rs:520`):

```
Dup(n=0) = 0x30                       → 1 declare
Idx(push_path=false, key=Bytes<32>)   → 4 declares: [0x50, align(2), key(1)]
Some additional ops (0x20, 0x18 = Member or similar)
Popeq → reads result via PublicInput
```

## Implementation scope

Per-operation work, ordered by complexity:

1. **`member(k) -> Boolean`** — closest to existing `emit_ledger_read`. Probably ~150 LOC + tests. Uses `Member` (0x18) op which the existing emitter doesn't use.
2. **`lookup(k) -> V`** — similar to member but pops the value via `Popeq` with a typed result. Returns the V value via `PublicInput` from the transcript outputs. Probably ~200 LOC.
3. **`insert(k, v) -> ()`** — significantly more work. Constructs a `StateValue::Cell` for the value (or `StateValue::Null` for the entry slot), pushes via `Push { storage: true|false }`, then `Ins` twice. Needs StateValue construction helpers. Probably ~300 LOC + tests, plus a `StateValue` construction module.
4. **`remove(k) -> ()`** — uses `Rem` (0x19/0x1a). Probably ~150 LOC.

## Cross-cutting work

Beyond per-operation emission, Map needs:

- **Key encoding via `emit_key_field_repr`**: today this only handles `Uint<8>` keys (counter field indices). For Map's user-typed keys (`Bytes<32>`, `Field`, `Uint<N>`, ...), need a generic key-to-field_repr emitter that respects each type's alignment and field width.
- **`StateValue` construction in the IR**: `Push` op carries a `StateValue` whose `field_repr` is what gets declared. Need a small module that takes a Rust value of known type and emits the right LoadImm + DeclarePubInput sequence to match `StateValue::field_repr`.
- **Type tracking through `LedgerAccess`**: the emitter needs to know the K and V types of the Map at the call site to emit correct constraints and key/value encodings. Today, `emit_counter_increment` is hardcoded for Counter. We need a more general `LedgerAccess` dispatcher that consults the ledger field's declared type.

## Recommended staging

| Stage | Scope | Status |
|---|---|---|
| Stage 0 | Generic key encoding (`emit_key_field_repr` for any `K`) + StateValue construction helpers | landed (alongside Cell::set) |
| Stage 1 | `Map::contains(&k) -> bool` end-to-end with ledger integration test | **landed** |
| Stage 2 | `Map::lookup(&k) -> V` end-to-end with ledger integration test | **landed** |
| Stage 3 | `Map::insert(k, v)` end-to-end with ledger integration test | **landed** |
| Stage 4 | `Map::remove(&k)` end-to-end with ledger integration test | **landed** |

`Map::get(&k) -> Option<V>` (Rust HashMap idiom) is not on-chain
representable as a single VM op — `Popeq.as_cell()` rejects
`StateValue::Null`, so a missing key fails the proof rather than
returning `None`. Option-returning semantics is provided as **parser
sugar**: `if let Some(v) = self.map.get(&k) { body }` rewrites to
`if self.map.contains(&k) { let v = self.map.lookup(&k); body }`. See
[[map-get-sugar]].

### Stage 1 status

`Map<K, V>::contains(&k)` is on-chain compatible for single-Fr key types
(`Boolean`, `u8..u128`, `Uint<N≤253>`):

- IR: `emit_map_member` in `crates/midnight-codegen/src/zkir_emitter.rs`
  produces the Dup + Idx + Push + Member + Popeq sequence, reusing
  `emit_push_cell` for the key.
- Transcript: the `"contains"`/`"member"` arm in
  `crates/midnight-codegen/src/transcript_codegen.rs` emits matching
  runtime ops. The Popeq `result` is computed at transcript-build time
  by calling the runtime stub on `state`, so the prover bakes the actual
  Member result into the transcript. Circuits that read state get an
  extra `state: &<LedgerName>` parameter via `circuit_needs_state`
  detection.
- Type-aware AlignedValue casts: `primitive_cast_for_type` maps
  `Uint<64>` → `as u64` etc. so the runtime's
  `AlignedValue::from(<expr> as u64)` produces the `Bytes{8}` alignment
  the IR expects. Without this cast, `u128` (from `.value()`) would
  produce `Bytes{16}` and disagree with the IR's `Uint<64>` encoding.
- E2E test: `ledger_integration_test::map_contains_proves_and_verifies`
  proves+verifies a `Map<Uint<64>, Boolean>::contains` circuit through
  `ContractCallExt::construct_proof`.

### Stage 3 status

`Map<K, V>::insert(k, v)` is on-chain compatible for single-Fr K and V
(same constraints as `contains` — Boolean, integers, Uint<N≤253>):

- IR: `emit_map_insert` in `zkir_emitter.rs` emits the
  Idx{push_path:true} + Push(key) + Push(value) + Ins{cached:false} +
  Ins{cached:true} sequence. The first `Ins` inserts (k, v) into the
  Map; the second `Ins` writes the modified Map back to the contract
  Array (which the `Idx{push_path:true}` kept on the stack underneath).
  Same `emit_push_cell` helper used by Cell::set.
- Transcript: `generate_map_insert` in `transcript_codegen.rs` emits
  matching runtime ops with `primitive_cast_for_type` applied to both
  K and V. Both `"set"` and `"insert"` method names route here when
  the field is a Map (a Cell field still goes to `generate_cell_set`).
- Runtime API: `Map::insert(key: K, value: V) -> Option<V>` added next
  to `set` (HashMap-style). `Map::remove(&K) -> Option<V>` also added
  in anticipation of Stage 4.
- E2E test: `ledger_integration_test::map_insert_proves_and_verifies`
  proves+verifies a `Map<Uint<64>, Uint<64>>::insert(k, v)` circuit
  through `ContractCallExt::construct_proof`. Insert returns no value
  so the test has no Popeq — purely the 5-op sequence.

### Stage 2 status

`Map<K, V>::lookup(&k) -> V` is on-chain compatible for single-Fr K and V.
Matches compactc 0.30.0's emission for `m.lookup(k)`:

```text
Dup{n:0}                                                    → [0x30]
Idx{cached:false, push_path:false, [Bytes<1>(field_idx)]}   → [0x50, 1, 1, field_idx]
Idx{cached:false, push_path:false, [Key::Value(key)]}        → [0x50, 1, K-align, K-value]
Popeq{cached:false, result: AlignedValue<V>}                 → [0x0c, 1, V-align, value]
```

`lookup` is **assert-exists**: missing keys land `StateValue::Null` on
the stack at the second Idx, then `Popeq.as_cell()` fails. Callers that
might not have the key should `contains` first.

Empirical compactc reference: `/tmp/cond-experiments/map_out/zkir/lookup.zkir`.

Implementation notes:
- The second Idx is the key-by-value step (path entry is `Key::Value(AlignedValue::from(key))`).
- Popeq uses `cached:false` (0x0c), not `cached:true` like Map::contains,
  because the read actually happens here. (Compactc agrees.)
- `unwrap_to_aligned_primitive` in `transcript_codegen.rs` unwraps the
  V-type result for `AlignedValue::from`: `Boolean → .value()`,
  `Uint<N> → .value() as u<N>`.
- Runtime helper `Map::lookup` added in `crates/midnight-storage/src/map.rs`,
  panicking if the key is absent (mirrors the VM behavior at proof time).
- E2E test: `ledger_integration_test::map_lookup_proves_and_verifies`.

### Stage 4 status

`Map<K, V>::remove(&k)` is on-chain compatible for single-Fr K. The
return value (`Option<V>` at runtime) is currently discarded at the
circuit level — plumbing it through waits for Stage 2's Option alignment
encoding work.

Encoding (4 ops):

```text
Idx  { cached: false, push_path: true, [Bytes<1>(field_idx)] }  → [0x70, 1, 1, field_idx]
Push { storage: false, Cell(key) }                               → [0x10, 1, K-align, K-value]
Rem  { cached: false }                                            → [0x19]
Ins  { cached: true,  n: 1 }                                      → [0xa1]  restore parent Array
```

`Rem` pops `[key, container]` and pushes back the modified container in
one step (vs. insert which needs Push(value) + first Ins). The trailing
`Ins{cached:true}` does the same parent-restoration job as in insert.

E2E test: `ledger_integration_test::map_remove_proves_and_verifies`.

### Multi-Fr K/V status (Bytes<N> in Map<K, V>)

All four Map primitives (`contains`/`lookup`/`insert`/`remove`) now
support multi-Fr keys and values end-to-end, matching compactc's
reference `Map<Bytes<32>, Uint<64>>` example. The wiring:

- IR (`zkir_emitter.rs::emit_map_method`) computes each method's K/V
  encoding via `aligned_value_encoding`, then collects the contiguous
  `value_field_count` PrivateInputs into `key_vars`/`val_vars` slices
  via `gather_n_vars`. Relies on the multi-Fr WitnessAccess invariant
  that PrivateInputs are emitted contiguously and uninterrupted.
- `emit_map_member`/`emit_map_insert`/`emit_map_remove` use
  `emit_push_cell(value_vars: &[Index], ...)` (already multi-Fr-aware
  from Cell::set Phase B), so the Push declares one `DeclarePubInput`
  per Fr the key/value occupies.
- `emit_map_lookup` iterates `key_vars` directly into its second `Idx`
  (no Cell discriminant on the path entry, just
  `[seg_count, ..atoms, ..value_frs]`). The Popeq result now uses
  `read_result_fr_layout` per-chunk handling for multi-Fr V (same
  pattern as `emit_ledger_read` for Cell<Bytes<N>>::get).
- Transcript codegen (`transcript_codegen.rs`) now uses
  `aligned_value_arg_expr(expr, k_ty)` for keys across `contains`,
  `insert`, `lookup`, `remove`. For Bytes<N> keys this expands to
  `*<raw>.as_bytes()`; primitives still get `as u<N>` casts.
- `unwrap_to_aligned_primitive` extended with a `Bytes<N>` arm
  (`*(expr).as_bytes()`) so `Map::lookup`'s Popeq result computation
  unwraps the wrapper for `AlignedValue::from`.
- E2E tests in `ledger_integration_test.rs` for `Map<Bytes<32>,
  Uint<64>>::{insert, contains, lookup, remove}` proves+verifies all
  four through `ContractCallExt::construct_proof`.

### Stages remaining

All four primitives Compact exposes for Map (`member`/`lookup`/`insert`/
`remove`) are now on-chain compatible end-to-end in Nocturne, with both
single-Fr K/V and multi-Fr `Bytes<N>` K/V supported. The Rust
HashMap-style `Map::get → Option<V>` is still missing — see the note
above the staging table. The next Map-related work is therefore either
that Option<V> expansion or moving on to other ledger primitives
(Set/MerkleTree, Field cells, custom ADT alignment).

### Wider key types (2026-05-19)

`Map<Field, V>` and `Map<MerkleTreeDigest, V>` now work end-to-end.
Both share `AlignmentAtom::Field` (`[1, -2]`, 1 Fr) — `MerkleTreeDigest`
is a Field-aligned newtype that carries the full 32-byte LE Fr (Phase E).

Two narrow gaps fixed:

- `aligned_value_encoding` in `zkir_emitter.rs` extended to recognize
  `MerkleTreeDigest` as the same encoding as `Field`.
- `aligned_value_arg_expr` in `transcript_codegen.rs` extended with a
  `MerkleTreeDigest` arm: lifts the digest to `Fr` via
  `Fr::from_le_bytes(&d.as_le_bytes()).unwrap()` (NOT through
  `.field().value()`, which would truncate to u128).

E2E coverage: `Map<Field, Uint<64>>::{insert, contains}`,
`Map<MerkleTreeDigest, Uint<64>>::{insert, contains}`.

Other key shapes still untested: tuple/struct keys (compactc supports
record-typed keys), `Map<Boolean, V>` (technically legal but unusual).
`Bytes<N>` keys for `N != 32` compile but lack dedicated e2e tests —
the encoding is the same shape so single-Fr `Bytes<N>` (N ≤ 31) should
work mechanically.

## References

- VM opcodes: `reference-repos/midnight-ledger/onchain-vm/src/ops.rs:95-462`
- Existing `emit_ledger_read` (Counter read pattern, simplest analogue): `crates/midnight-codegen/src/zkir_emitter.rs:520`
- Existing key encoding (limited): `crates/midnight-codegen/src/zkir_emitter.rs::emit_key_field_repr`
- Empirical compactc outputs: `/tmp/cond-experiments/map_out/zkir/{put,lookup,member}.zkir`
