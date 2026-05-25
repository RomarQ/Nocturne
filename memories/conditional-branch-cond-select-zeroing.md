# Conditional-branch DeclarePubInput zeroing

**Discovered**: 2026-05-18 (after empirical sweep of compactc behavior)
**Status**: Implemented 2026-05-18 in `crates/nocturne-codegen/src/zkir_emitter.rs`. Regression test: `voting_verifies_with_ledger_shape_pis` in `crates/nocturne/tests/ledger_integration_test.rs`.

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

## How Nocturne does it

In `crates/nocturne-codegen/src/zkir_emitter.rs`:

- `ZkirEmitter` tracks `in_conditional: bool` and a cached `zero_var: Option<Index>`.
- `push_declare_pub_input(value)` is the single chokepoint. When `in_conditional == true`, it wraps the value in `CondSelect { bit: self.guard, a: value, b: zero }` before pushing the `DeclarePubInput`. Outside conditionals (top-level circuit body), it emits the `DeclarePubInput` directly.
- All 13 prior `self.instructions.push(Instruction::DeclarePubInput { var: X })` sites were converted to `self.push_declare_pub_input(X)`.
- The `ExprIR::If` handler composes nested guards: the then-branch's effective guard is `cond_select(cond, outer_guard, 0)` (== `outer AND cond`) and the else-branch's is `cond_select(cond, 0, outer_guard)` (== `outer AND NOT cond`). At top level, just `cond` and `!cond`. `in_conditional` is set true for the duration of the branches and restored on exit.

## Side effects realized

- IR is slightly larger inside conditional branches (extra `LoadImm 0` and `CondSelect` per declared value). Verifier keys for conditional circuits grow accordingly. **On-chain compatible**: voting `cast_vote` now verifies via the canonical ledger PI shape.
- Voting VK does NOT byte-match compactc — compactc applies value-reuse optimizations we don't. Don't pursue VK equality with compactc for conditional circuits.
- Counter (no conditionals) is unchanged: the counter golden in `tests/golden/counter-increment.verifier` still byte-matches compactc.

## Empirical confirmations from compactc

- **Nested guards** (`/tmp/cond-experiments/05_nested.compact`): compactc composes guards via `cond_select` — no explicit `And` instruction. We mirror this exactly.
- **No-else case** (`/tmp/cond-experiments/04_no_else.compact`): only the then-branch's declares get cond_select-zeroed; the absent else branch needs no handling. Our `ExprIR::If` arm skips else-branch emission when `else_branch` is None.
