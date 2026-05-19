# `Cell<Field>` and `AlignmentAtom::Field` encoding

**Discovered/implemented**: 2026-05-19 (Phase A of the staged MerkleTree plan)
**Status**: Implemented end-to-end. Tests: `cell_field_{set,get}_proves_and_verifies` in `crates/midnight/tests/ledger_integration_test.rs`. Prerequisite landed for the `MerkleTree::checkRoot` work documented in [[merkle-tree-encoding]].

## What changed

The IR's `AlignedValueEncoding::alignment_atoms` switched from `Vec<u32>` to `Vec<i32>` so it can carry `AlignmentAtom::Field`'s `-2` encoding alongside `Bytes{N}`'s positive lengths. `Fr::from(*atom)` then routes through `derive_signed!` in `transient-crypto/src/curve.rs:275` to produce the correct on-chain value (`Fr::ORDER - 2` for `-2`).

The `aligned_value_encoding` table gained a `Field` arm:

```rust
if ty_str == "Field" {
    return Some(AlignedValueEncoding {
        alignment_atoms: vec![1, -2],   // seg_count=1, AlignmentAtom::Field=-2
        value_field_count: 1,
    });
}
```

Transcript codegen routes Field values through `Fr::from((<expr>).value())` and then `AlignedValue::from(Fr)` — which picks Field alignment via the `impl Aligned for Fr` at `transient-crypto/src/curve.rs:291`. Both the write side (`aligned_value_arg_expr`) and the read side (the `get`/`value` arm in `transcript_codegen.rs`) carry the Field arm.

## On-chain shape

For `Cell<Field>::set(v)` — Push declares are 5 total: `[0x11, 1, 1, -2, value_fr]`. Same shape as `Cell<Bytes<N>>::set` for single-Fr N, just with `-2` (Field atom) in place of `N` (byte length).

For `Cell<Field>::get()` — Popeq declares are 4 total: `[0x0d, 1, -2, value_fr]`.

## Why the `Field` user-side type stays a `u128` wrapper

`midnight-types::Field` is currently `pub struct Field(u128)` with a "test mode" comment. On-chain `Fr` is BLS12-381's scalar field (~254 bits), so `u128` only covers a strict subset. For Phase A's purposes the subset is enough:

- The transcript codegen converts our `Field` to `Fr` via `Fr::from(field.value())` (u128 → Fr).
- A Cell<Field> witnessed from the user's `Field` value round-trips through prove+verify because both the IR's PrivateInput and the runtime's AlignedValue see the same `Fr::from(u128)` value.

Future work to expand Field to full 254-bit Fr is independent of the alignment work landed here.

## Required substrate that landed

- `Fr` has both `impl Aligned for Fr` (`transient-crypto/src/curve.rs:291`) and `impl From<Fr> for ValueAtom` (`transient-crypto/src/fab.rs:205`), which together satisfy the `impl<T: DynAligned> From<T> for AlignedValue where Value: From<T>` blanket impl at `base-crypto/src/fab/conversions.rs:251`. So `AlignedValue::from(fr_value)` builds a Field-aligned AlignedValue directly — no manual `AlignedValue::new(value, alignment)` construction needed.
- `Fr::from(i32)` works via `derive_signed!` and produces `Fr::ORDER - 2` for `-2`.

## Implications for MerkleTree

`MerkleTree::checkRoot(MerkleTreeDigest)` requires pushing a `Cell(Field)` (the user-supplied root) onto the VM stack and comparing it against the tree's `Root`. The Push side of that op is now expressible via `emit_push_cell(value_vars, encoding=Field, storage=false)` — exactly the same machinery this Phase A landed.

What's still missing for checkRoot:
- The `Root` opcode (`0x0a`) emission in IR + transcript.
- The `Eq` opcode (`0x02`) emission in IR + transcript.
- The 2-element Array storage shape for `MerkleTree<H, T>` ledger fields.
- A constructor emission that initializes the Array.
- A `MerkleTreeDigest` user-facing type.

See [[merkle-tree-encoding]] for the full staged plan (Phases B/C/D/E).
