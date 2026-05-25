# Compactc vs Nocturne: structural divergences

**Discovered**: 2026-05-18

Tracking the encoding differences between compactc 0.30.0 and Nocturne's emitter that prevent byte-level VK equivalence beyond the counter contract. Counter happens to match because it's structurally trivial.

## Storage layouts

| Construct | Compactc | Nocturne | On-chain compat? |
|---|---|---|---|
| `Counter` | `ledger x: Counter;` | `Counter` field on `#[nocturne(ledger)]` struct | Same |
| Mutable boolean | `ledger b: Boolean;` (raw cell) | `Cell<bool>` field on ledger struct | **Different**: different VM opcodes (`Cell::write` ops vs raw `Push` + `Ins`). VK won't match compactc even for non-conditional access. |
| `Map<K, V>` | `ledger m: Map<K, V>;` | not yet implemented | n/a |

## Branching strategies

Per [conditional-branch-cond-select-zeroing.md](conditional-branch-cond-select-zeroing.md), compactc and Nocturne both emit per-branch `DeclarePubInput`s. The difference is whether values are zeroed in the inactive branch:

- **Compactc**: every `DeclarePubInput` value is `cond_select(guard, active_value, ZERO)`. Compactc also opportunistically reuses values that happen to be zero in the inactive case to save constraints.
- **Nocturne (current, pre-fix)**: declares `memory[var]` directly, which holds non-zero LoadImm values in the inactive case. **Not on-chain compatible.**
- **Nocturne (post-fix)**: same `cond_select` wrapping as compactc, but without the value-reuse optimizations. On-chain compatible; VKs won't byte-match compactc.

## Implications for the compactc-golden test

The golden test (`tests/golden/counter-increment.verifier`) is a useful cross-compiler check but only scales to circuits where Nocturne and compactc produce structurally-equivalent ZKIR. Today that's: counter (no branches, no `Cell<bool>`, no `Map`). Adding more goldens requires either:

1. Matching compactc's optimizations 1:1 (high effort, low value — we'd be reimplementing compactc's optimizer).
2. Limiting goldens to the matching-structure subset and using the midnight-ledger integration test (`crates/nocturne/tests/ledger_integration_test.rs`) as the general on-chain compatibility gate.

Default to option 2. The ledger integration test is the real gate; goldens are a sanity check on the subset where they're feasible.
