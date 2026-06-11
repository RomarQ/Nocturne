# Uint arithmetic: unconstrained in-circuit, panicking off-chain

**Discovered/decided: 2026-06-11** (review-fixes Chunk 5, Task 5.1)

## What

In-circuit `Uint<N>` arithmetic is UNCONSTRAINED field arithmetic; the off-chain `Uint<N>` type (`crates/nocturne-types/src/uint.rs`) panics on overflow/underflow past `2^N` so test mode surfaces what the circuit would silently get wrong.

## Why (the evidence)

The ZKIR emitter lowers `+`, `-`, `*` straight to field instructions with no range constraint on the result (`crates/nocturne-codegen/src/zkir_emitter.rs`, `ExprIR::BinaryOp` arm, currently lines ~821-831):

- `BinOp::Add` → `Instruction::Add { a, b }`
- `BinOp::Sub` → `Instruction::Neg` + `Instruction::Add` (field subtraction)
- `BinOp::Mul` → `Instruction::Mul { a, b }`

`ConstrainBits(N)` is applied where a `Uint<N>` *enters* the circuit (witness/public input declaration), not to arithmetic *results*. So in-circuit, `Uint<8>: 255 + 1` is the field element `256`, not `0` — there is no wraparound at `2^N` and no overflow check. A proof over that value verifies fine.

The old off-chain behavior (`wrapping_add` + mask to `N` bits) therefore *diverged* from the circuit: off-chain `255 + 1 == 0`, in-circuit `255 + 1 == 256`. A `#[nocturne::test]` exercising the wrap would pass while the real circuit computed something else. Panicking is the only off-chain semantic that can't silently disagree with the circuit.

Also fixed here: the guard in `Uint::new` was the tautology `N <= 128 || value <= max` (always true for every constructible `N`), so out-of-range constructor values were silently masked even in debug builds. It's now `N >= 128 || value <= max`.

## Implications

- Off-chain `Add`/`Sub`/`Mul` for `Uint<N>` panic with "Uint<N> overflow/underflow; the circuit would not constrain this — restructure". Contract authors must restructure (e.g. guard with a comparison) instead of relying on wraparound.
- The panic is conservative for INTERMEDIATE values: `(max + b) - b` is circuit-valid (field elements don't wrap at `2^N`; only constrained entry points matter) but panics off-chain on the `max + b` step. The workaround there is to reorder the expression or widen the type for the intermediate; a comparison guard doesn't cover this case.
- `Uint<N>` now const-asserts `1 <= N <= 128` in `new()`/`zero()`, so a `Uint<200>` fails at monomorphization instead of silently saturating to 128 bits.
- This is a deliberate divergence from Compact, which has checked arithmetic semantics in-circuit. Nocturne does not yet emit overflow constraints; whether to emit a checked-constrain (range-check the result of each `Uint` op in ZKIR) is an **open decision**. Until that lands, the divergence is documented (here and in the `Uint` rustdoc), not silent.
- `Uint<N>` is backed by `u128`; widths above 128 are not representable. Don't reintroduce doc claims of `Uint<256>`.
- Tests that want wraparound must do it on raw integers (`x.value().wrapping_mul(2)`) before re-wrapping in `Uint`, and stay within `2^N`.

## Related

- [witness-type-support.md](witness-type-support.md) — where `ConstrainBits(N)` IS applied (witness entry points).
- [compactc-vs-nocturne-divergences.md](compactc-vs-nocturne-divergences.md) — other deliberate divergences from compactc.
