# Witness type support

**Discovered**: 2026-05-18 (during witness coverage work)
**Updated**: 2026-05-19 (multi-Fr `Bytes<N>` witness emission landed)
**Status**: Boolean / Field / Uint<N> / Bytes<N> all supported as witnesses.

## Supported witness types

| Type | Frs emitted | Per-Fr serialization | Type constraint emitted |
|---|---|---|---|
| `Boolean` | 1 | `Fr::from(bool)` via `.value()` | `ConstrainToBoolean { var }` |
| `Field` | 1 | `Fr::from(u128)` via `.value()` | none (Field is unrestricted) |
| `Uint<N>` | 1 | `Fr::from(u128)` via `.value()` | `ConstrainBits { var, bits: N }` |
| `Bytes<N>` | `ceil(N / 31)` | `AlignedValueExt::value_only_field_repr` of `AlignedValue::from(*as_bytes())` | per-chunk `ConstrainBits` (8 bits for the first emitted chunk when `N % 31 == 1`, etc.; full chunks are 248 bits) |

## How witnesses flow through codegen

- **Macro-generated witness struct**: each field's type is preserved as the user wrote it.
- **Transcript builder** (`crates/nocturne-codegen/src/transcript_codegen.rs`):
  for single-Fr witnesses, emits `private_transcript.push(Fr::from(witnesses.<field>.value()));`.
  For `Bytes<N>`, emits
  ```
  let __av = AlignedValue::from(*witnesses.<field>.as_bytes());
  __av.value_only_field_repr(&mut private_transcript);
  ```
  which pushes the right number of Frs in the same order the IR's
  PrivateInputs expect (high-bytes chunk first after `.rev()`).
- **ZKIR emitter** (`crates/nocturne-codegen/src/zkir_emitter.rs`): the
  `WitnessAccess` arm consults `witness_fr_layout(ty)` to decide how many
  `PrivateInput` instructions to emit and what `ConstrainBits` bit width
  to apply to each. For non-Bytes types it falls back to
  `emit_type_constraint` (Boolean → `ConstrainToBoolean`, etc.).

## How the chunk order works for `Bytes<N>`

`AlignmentAtom::Bytes{N}.field_repr_unchecked` uses
`bytes.chunks(31).rev()`. For `Bytes<32>`, that's
`[bytes[31..32], bytes[0..31]]` — the high byte first (constrained to 8
bits), then the low 31 bytes (constrained to 248 bits). This matches
compactc 0.30.0's emission for `Bytes<32>` circuit inputs.

For general `Bytes<N>`:
- `chunks = ceil(N / 31)`.
- First emitted chunk has `if N % 31 == 0 { 31 } else { N % 31 }` bytes.
- All later chunks have 31 bytes.

## Tests

- `crates/midnight/tests/witness_types_test.rs::multi_witness_struct_constructs` — multi-typed witness struct compiles.
- `each_witness_type_builds_transcript` — Boolean/Field/Uint witnesses serialize correctly.
- `bytes_witness_is_accepted` — `Bytes<32>` witness contract parses cleanly.
- `crates/midnight/tests/ledger_integration_test.rs::bytes32_witness_proves_and_verifies` — `Bytes<32>` witness round-trips through `ContractCallExt::construct_proof` + prove + verify.
