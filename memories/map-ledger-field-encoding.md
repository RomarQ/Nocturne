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

| Stage | Scope | Effort |
|---|---|---|
| Stage 0 | Generic key encoding (`emit_key_field_repr` for any `K`) + StateValue construction helpers | M |
| Stage 1 | `Map::member(k)` end-to-end with ledger integration test | M |
| Stage 2 | `Map::lookup(k)` end-to-end | M |
| Stage 3 | `Map::insert(k, v)` end-to-end | L |
| Stage 4 | `Map::remove(k)` end-to-end | S |

Stage 0 is shared infrastructure for everything that follows (and would also benefit `Cell<T>` for arbitrary T, MerkleTree, custom ADTs). Best to start there.

## References

- VM opcodes: `reference-repos/midnight-ledger/onchain-vm/src/ops.rs:95-462`
- Existing `emit_ledger_read` (Counter read pattern, simplest analogue): `crates/midnight-codegen/src/zkir_emitter.rs:520`
- Existing key encoding (limited): `crates/midnight-codegen/src/zkir_emitter.rs::emit_key_field_repr`
- Empirical compactc outputs: `/tmp/cond-experiments/map_out/zkir/{put,lookup,member}.zkir`
