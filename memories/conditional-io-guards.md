# Conditional `PrivateInput` / `PublicInput` must carry the branch guard

**Discovered**: 2026-05-19 (during conditional-branches edge-case sweep)
**Status**: Implemented in `crates/nocturne-codegen/src/zkir_emitter.rs` via the `current_io_guard()` helper. Regression tests: `conditional_map_contains_{active,inactive}_proves_and_verifies`, `conditional_cell_set_proves_and_verifies`, `nested_conditional_proves_and_verifies`, `no_else_conditional_false_proves_and_verifies`, `voting_verifies_else_active` in `crates/nocturne/tests/ledger_integration_test.rs`.

Companion to [[conditional-branch-cond-select-zeroing]]: that fix handles `DeclarePubInput`-side zeroing for the verifier-PI shape; this one handles the prover-side transcript-consumption shape.

## What

Every `Instruction::PrivateInput { guard }` and `Instruction::PublicInput { guard }` emitted inside a conditional branch must set `guard = Some(self.guard)` (the branch's effective guard, the same one feeding `cond_select` zeroing). Outside conditionals, `guard: None` is correct.

In `zkir_emitter.rs`, the chokepoint is the `current_io_guard()` helper:

```rust
fn current_io_guard(&self) -> Option<Index> {
    if self.in_conditional { Some(self.guard) } else { None }
}
```

All 5 `PrivateInput`/`PublicInput` emission sites (WitnessAccess, the two Popeq branches in `emit_ledger_read`, `emit_map_member`, `emit_map_lookup`) route their guard through this.

## Why

Per `zkir/src/ir_vm.rs:325-355`:

```rust
I::PublicInput { guard } => {
    let val = match guard {
        Some(guard) if !idx_bool(&memory, *guard)? => 0.into(),
        _ => {
            public_transcript_outputs_idx += 1;
            preimage.public_transcript_outputs.get(...)
                .ok_or(anyhow!("Ran out of public transcript outputs"))?
        }
    };
    memory.push(val);
}
```

`PrivateInput` mirrors this with `private_transcript`. When the guard evaluates to 0 (inactive branch), the VM pushes `0` to memory **without** advancing the transcript index. When the guard is `None` (or 1), it consumes one entry.

The transcript builder only emits ops for the active branch, so `public_transcript_outputs` and `private_transcript` only contain entries for active-branch reads. Without the guard, an inactive-branch `PrivateInput`/`PublicInput` would still try to consume a transcript entry that wasn't produced, and prove fails with **"Ran out of public/private transcript outputs"**.

Conversely, if the prover *does* put inactive-branch witnesses into the transcript (incorrectly), prove fails with **"Transcripts not fully consumed"** because the IR's guarded ops won't advance the index past them.

## How to apply

- When emitting any `PrivateInput`/`PublicInput` inside a branch (including nested branches), use `self.current_io_guard()` for the `guard` field, not `None`.
- On the test/prover side, only include AlignedValues in `private_transcript_outputs` for witnesses whose IR reads are *active*. Inactive-branch witnesses must be omitted — the IR won't consume their slot.
- The transcript codegen's `WitnessAccess` arm already does the right thing (it emits `private_transcript.push(...)` inside the conditional's runtime `if`, so inactive branches don't push).

## Side effects

- VK size for conditional circuits is unchanged from before (same number of instructions, guards are just Index references).
- The fix is orthogonal to [[conditional-branch-cond-select-zeroing]]: that one keeps `DeclarePubInput` *values* aligned with the verifier's Noop-padded transcript shape; this one keeps the prover's *transcript reads* aligned with the active-only transcript shape. Both are required for any conditional circuit that reads witnesses or state inside a branch.
