# Golden files: equivalence with `compactc`

This directory holds the artifacts compactc produces for a small contract.
CI verifies that Nocturne's `cargo nocturne build` + `keygen` pipeline
produces the **same verifier key** (byte-for-byte) for the same contract.

If they match, the two compilers emit mathematically identical Plonk
circuits, even though the intermediate ZKIR may differ in cosmetic ways
(variable numbering, instruction ordering, hex case).

## Files

- `counter.compact` — Compact source. Equivalent to `examples/counter-contract/src/lib.rs`.
- `counter-increment.verifier` — verifier key produced by `compactc 0.30.0`.

## Regenerating

Requires `compactc` on `$PATH` (`~/.compact/bin/compactc` on a default install).

```sh
compactc tests/golden/counter.compact /tmp/compact-counter-out
cp /tmp/compact-counter-out/keys/increment.verifier tests/golden/counter-increment.verifier
```

Bump the compactc version in this README whenever the golden is regenerated.
