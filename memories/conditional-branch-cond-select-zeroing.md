# Conditional-branch DeclarePubInput zeroing

**Discovered**: 2026-05-18 (after empirical sweep of compactc behavior)

Inside a conditional branch, every value passed to `DeclarePubInput` must be zero when the branch is inactive. The fix is to route the value through `cond_select(branch_guard, active_value, ZERO)` before declaring it.

## Why

Per [ledger-pi-layout.md](ledger-pi-layout.md), the ledger replaces inactive transcript segments with `Op::Noop { n }`, which contributes `n` zero field elements via `field_repr`. The circuit's prove must agree: inactive slots must be zero. midnight-zkir's `DeclarePubInput` pushes `memory[var]` unconditionally (`zkir/src/ir_vm.rs:339-342`), so the zeroing must happen at emit time by feeding it a `cond_select`-multiplexed value.

## How compactc does it

Empirically verified by running compactc on 5 conditional patterns (same-IMM, different-field, different-ops, no-else, nested). For each `DeclarePubInput` in a branch, compactc emits:

```
LoadImm <zero>          // common zero, loaded once and reused
LoadImm <active_value>
CondSelect { bit, a=<active>, b=<zero> }
DeclarePubInput { var: result_of_cond_select }
PiSkip { count, guard: bit }
```

`cond_select(bit, a, b)` returns `mem[b]` when `mem[bit] == 0`, `mem[a]` otherwise (see `zkir/src/ir_vm.rs::synthesize` around line 603, which uses `is_zero` to negate before passing to `std.select`). With `bit = branch_guard`, this yields `active_value` when the branch is active and `zero` when inactive.

Compactc optimizes by reusing values that happen to be zero in the inactive case (e.g., a witness's value of 1 happens to match Counter alignment count). That's optional; the minimum-correct fix is unconditional `cond_select` wrapping.

## How Nocturne should do it

In `crates/midnight-codegen/src/zkir_emitter.rs`:

- Wrap every conditional-branch `DeclarePubInput` emission in a helper:

  ```rust
  fn declare_pub_input_guarded(&mut self, value: Index, guard: Index) {
      let zero = self.emit_load_imm(Fr::from(0));
      let muxed = self.emit_cond_select(guard, value, zero);
      self.instructions.push(Instruction::DeclarePubInput { var: muxed });
  }
  ```

- Use it for every `DeclarePubInput` emitted inside the then/else branches of a conditional.
- Keep direct `DeclarePubInput { var }` for unconditional declares (outside any conditional).
- Keep `PiSkip { guard, count }` with the same branch guard.

## Side effects

- The IR will have more `LoadImm`/`CondSelect` ops, growing the circuit slightly. Verifier keys will be larger than the no-cond_select baseline but **on-chain compatible** (which the current emission is not).
- Voting VK will not byte-match compactc unless we also implement compactc's value-reuse optimizations. Don't aim for VK equality with compactc for conditional circuits — aim for on-chain verify success.
- `voting_pi_count_diverges_from_active_transcript` in `tests/ledger_integration_test.rs` will need its assertion flipped after the fix: prove's pis length will equal ledger's active-shape pis length (each inactive slot contributes zero, matching the Noop interleave).

## Open before implementing

1. **Nested guards**: for `if outer { if inner { … } }`, the inner branch's effective guard is `outer AND inner`. Check whether compactc emits an explicit `And` instruction or threads a precomputed combined guard. Look at case 5 (`/tmp/cond-experiments/05_nested.compact`).
2. **No-else case**: the empty else branch has no DeclarePubInputs to zero. Confirm compactc emits only the then-branch's wrapping (case 4).
