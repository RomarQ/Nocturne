# `Map::get(&K) -> Option<V>` — parser-level contains+lookup sugar

**Discovered/implemented**: 2026-05-19
**Status**: Implemented. The parser detects `if let Some(v) = self.<map>.get(&k) { body }` and rewrites the IR to `if self.<map>.contains(&k) { let v = self.<map>.lookup(&k); body }`. Tests: `map_get_sugar_{present,absent}_proves_and_verifies` and the underlying `safe_get_{present,absent}` in `crates/midnight/tests/ledger_integration_test.rs`.

## Why `Map::get` can't be a single opcode

The on-chain VM has no `Option<V>` primitive. `Popeq.as_cell(StateValue)` panics on `StateValue::Null` (`onchain-vm/src/vm.rs`), so a missing-key `Map::lookup` aborts proof construction with `ReadMismatch` rather than returning `None`. To get `Option<V>` semantics, the circuit has to do the existence check explicitly via `Member` (cached:true Popeq → bool), then conditionally `Idx`-and-`Popeq` to read the value.

## Parser rewrite

In `crates/midnight-ir/src/parse.rs`, the `Expr::If` arm calls `match_if_let_some_get(cond)` before falling through to the regular `if` path. The matcher returns `Some((v_ident, map_field_ident, key_expr))` when it sees:

```rust
if let Some(<v>) = self.<map_field>.get(<key>) { body }
```

…and the surrounding `if` is rewritten to a `contains`-then-`lookup` shape, with a synthetic `Let { name: v, value: lookup(k) }` prepended to the original then-branch. The else-branch is preserved verbatim.

## Why the user-source still compiles as plain Rust

The macro keeps the user's original module intact (it only adds the `transcript` submodule alongside). The user's `if let Some(v) = self.map.get(&k)` is plain Rust against `Map::get -> Option<V>` from `crates/midnight-storage/src/map.rs`. Type-checking happens normally; the rewrite only affects the generated transcript builder and the ZKIR emission.

## Required substrate

This sugar only works because both halves of the conditional-branch story are in place:

- [[conditional-branch-cond-select-zeroing]] keeps the inactive-branch `DeclarePubInput`s zero (verifier-PI shape).
- [[conditional-io-guards]] keeps the inactive-branch `PrivateInput`/`PublicInput` from consuming transcript entries (prover-transcript shape).

Without either, the `lookup`-inside-conditional pattern fails: either the verifier rejects (PI mismatch) or the prover panics ("Ran out of transcript outputs" / "Transcripts not fully consumed").

## Limitations

- The matcher only recognizes `if let Some(v) = ...`; `match` and `let-else` aren't supported yet.
- The scrutinee must be exactly `self.<field>.get(<key>)` — chained or wrapped calls (`(self.map.get(&k)).clone()`) won't trigger the rewrite.
- The else-branch can't access `v` (it's only bound inside the then-branch).
- The user-source still needs the storage-layer `Map::get` method (`crates/midnight-storage/src/map.rs`) so the Rust type check passes; we deliberately don't strip it.
