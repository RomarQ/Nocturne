# `do_communications_commitment` must always be true

**Discovered**: 2026-05-18

Every circuit emitted by Nocturne must have `do_communications_commitment: true` in its `IrSource`. Setting it to `false` produces a verifier key that's incompatible with the on-chain ledger's verify path, even for circuits without a return value.

## Why

`midnight_ledger::verify::ContractCall::public_inputs` (ledger-8, `ledger/src/verify.rs:1869-1883`) unconditionally pushes the `communication_commitment` as the second public input:

```rust
pub fn public_inputs(&self, binding_com: Pedersen) -> Vec<Fr> {
    let mut res = vec![self.binding_input(binding_com)];
    res.push(self.communication_commitment);
    if let Some(guaranteed) = self.guaranteed_transcript.as_ref() {
        for op in guaranteed.program.iter() {
            op.field_repr(&mut res);
        }
    }
    ...
}
```

`ContractCall::communication_commitment` is `Fr` (not `Option<Fr>`) — every on-chain call carries one (`ledger/src/construct.rs:559-562`). The verifier always feeds it as `public_inputs[1]`.

If a circuit was generated with `do_communications_commitment: false`, its verifier key only reserves slots for `[binding_input, ..transcript]`. The ledger feeds `[binding_input, comm, ..transcript]` — Plonk verify fails with a PI count mismatch.

## How to apply

- `crates/midnight-codegen/src/zkir_emitter.rs` sets the flag unconditionally to `true`. **Do not** make it conditional on return type or anything else.
- The invariant is asserted in `crates/midnight-codegen/src/zkir_tests.rs::every_circuit_emits_communications_commitment_slot`.
- Any `ProofPreimage` constructed for our circuits must set `communications_commitment: Some((comm, opening))` with a valid commitment. Use `transient_commit::<[Fr]>(&[inputs..outputs], opening)` to compute. A `(Fr(0), Fr(0))` placeholder works only when `inputs ++ outputs` is empty AND `transient_hash(&[0]) == 0` — both rarely true, so don't rely on it.

## Tests that catch a regression

- `every_circuit_emits_communications_commitment_slot` — unit test on the emitter.
- `counter_ledger_constructed_preimage_proves_and_verifies` in `crates/midnight/tests/ledger_integration_test.rs` — goes through the canonical `ContractCallExt::construct_proof` path and would fail at verify time.
