# Witness type support

**Discovered**: 2026-05-18 (during witness coverage work)
**Status**: Boolean / Field / Uint<N> supported. Bytes<N> rejected at parse time pending multi-Fr witness emission.

## Supported witness types

| Type | `value()` returns | `Fr::from(...)` | Type constraint emitted |
|---|---|---|---|
| `Boolean` | `bool` | `Fr::from(bool)` | `ConstrainToBoolean { var }` |
| `Field` | `u128` | `Fr::from(u128)` | none (Field is unrestricted) |
| `Uint<N>` | `u128` | `Fr::from(u128)` | `ConstrainBits { var, bits: N }` |
| `Bytes<N>` | n/a | n/a | (would need multi-Fr emission) |

## How witnesses flow through codegen

- **Macro-generated witness struct**: each field's type is preserved as the user wrote it. `Bytes<N>` fails Rust's `Copy` check when accessed by value, which is a hint of the deeper issue.
- **Transcript builder** (`crates/midnight-codegen/src/transcript_codegen.rs`): for every `WitnessAccess` in the body, emits `private_transcript.push(Fr::from(witnesses.<field>.value()));`. The `Fr::from(...)` resolves via `From<bool>` / `From<u128>` impls in midnight-transient-crypto's `curve.rs`. The previous `value() as u64` cast silently truncated `Field` and large `Uint<N>` — fixed 2026-05-18.
- **ZKIR emitter** (`crates/midnight-codegen/src/zkir_emitter.rs::emit_type_constraint`): dispatches on the stringified type to emit `ConstrainBits` (for Uint/Bytes) or `ConstrainToBoolean` (for Boolean). `Field` gets no constraint.

## Bytes<N> rejection

`crates/midnight-ir/src/parse.rs::parse_witnesses_struct` checks each field type and returns `MIDNIGHT-001 InvalidType` with a message pointing to this memory when the user declares a `Bytes<N>` witness. This is intentional: until we have multi-Fr witness emission, letting `Bytes<N>` through produces either a confusing macro-expansion error or, worse, silently-wrong serialization.

### What "multi-Fr witness emission" needs

A `Bytes<N>` value's canonical field representation (via `FieldRepr`) uses `ceil(N * 8 / FR_BITS_STORED)` field elements. Adding support requires:

1. **Transcript codegen**: dispatch on witness type, emit `<T as FieldRepr>::field_repr(&witnesses.<field>, &mut private_transcript)` instead of a single `push`.
2. **ZKIR emitter**: emit one `PrivateInput { guard }` per Fr the witness produces, not just one. Probably need a new `WitnessAccess` lowering that knows the witness type and unrolls into the right number of `PrivateInput` instances.
3. **Type constraint**: `ConstrainBits` per Fr (or skip if the constraint isn't expressible per-Fr).

This is a real refactor — not a one-line fix. Leave the parse-time rejection in place until someone needs Bytes witnesses.

## Tests

- `crates/midnight/tests/witness_types_test.rs::multi_witness_struct_constructs` — multi-typed witness struct compiles.
- `each_witness_type_builds_transcript` — Boolean/Field/Uint witnesses serialize correctly, and `Field::from(u128::MAX)` survives the round trip (would have failed under the old `as u64` cast).
- `bytes_witness_is_rejected_at_parse_time` — Bytes<N> witness produces the documented `MIDNIGHT-001` error.
