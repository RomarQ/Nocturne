# On-chain verifier PI layout

**Discovered**: 2026-05-18

The on-chain ledger constructs the verifier's public-input vector as:

```
[binding_input, communication_commitment, ..field_repr(transcript_with_noops_interleaved)]
```

## Protocol flow

1. **User submits** a `ContractCall<ProofPreimageMarker>` whose transcript is the **active-branch-only** sequence of `Op` instances (what the contract actually executed).

2. **`ledger::prove::ContractCall::prove`** (`ledger/src/prove.rs:263-289`) calls `ProvingProvider::check(preimage)` → `Vec<Option<usize>>` (the `pi_skips`). For each `Some(n)` entry, it splices an `Op::Noop { n }` into the transcript at the corresponding position.

   ```rust
   for op in old_transcript {
       while let Some(Some(skip)) = remaining_active_calls.first() {
           transcript.push(Op::Noop { n: *skip as u32 });
           remaining_active_calls = &remaining_active_calls[1..];
       }
       transcript.push(op.clone());
       remaining_active_calls = &remaining_active_calls[1..];
   }
   ```

3. **`Op::Noop { n }`'s `field_repr`** (`onchain-vm/src/ops.rs:403`) is `vec![0u8.into(); n]` — `n` zero field elements.

4. **`ledger::verify::ContractCall::public_inputs`** (`ledger/src/verify.rs:1869`) iterates `guaranteed_transcript.program.iter()` and field-repr's each op into the PI vector. After the binding_input + commitment prefix.

5. **`VerifierKey::verify`** (`transient-crypto/src/proofs.rs:545`) takes the PIs as an iterator and feeds them directly to Plonk. **No `pi_skips` parameter at this layer.**

## Implication for the ZKIR emitter

The circuit's `prove()` returns a `pis` vector that must match what the ledger reconstructs from the on-chain transcript. Specifically:

- Length: `2 + sum of all field_repr widths across active ops + sum of n for each Op::Noop` (one Noop per `Some(n)` in `pi_skips`).
- Values at inactive positions (filled by Op::Noop): **must be zero**, because `Op::Noop`'s `field_repr` contributes zeros.

If Nocturne's emitter has `DeclarePubInput` ops that push non-zero values for inactive branches (which is what `midnight-zkir`'s preprocess at `zkir/src/ir_vm.rs:339-342` does — it unconditionally pushes `memory[var]` regardless of guard), the on-chain verify will fail on value mismatch.

This is why every conditional-branch `DeclarePubInput` must go through `cond_select(guard, value, ZERO)`. See [conditional-branch-cond-select-zeroing.md](conditional-branch-cond-select-zeroing.md).

## Tests that exercise the full path

- `counter_ledger_constructed_preimage_proves_and_verifies` (non-conditional case, currently passes).
- `voting_pi_count_diverges_from_active_transcript` (conditional case, asserts the divergence we currently produce; will need to flip assertion direction once the cond_select fix lands).
