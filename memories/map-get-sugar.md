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

## Supported shapes

- `if let Some(v) = self.<map>.get(&k) { ... }` (no else).
- `if let Some(v) = self.<map>.get(&k) { ... } else { ... }` (else branch preserved verbatim).
- `match self.<map>.get(&k) { Some(v) => ..., None => ... }` (arms in either order, `None` arm can also be `_`).

All four shapes lower to the same `if contains(k) { let v = lookup(k); ... } else { ... }` IR.

## Verified key/value type matrix

The sugar composes cleanly with multi-Fr key and value encodings — no fixes were needed beyond the existing [[conditional-io-guards]] and multi-Fr Map work. Tests in `crates/midnight/tests/ledger_integration_test.rs`:

| K | V | Tests |
|---|---|---|
| `Uint<64>` | `Uint<64>` | `map_get_sugar_{present,absent}`, `if_let_else_absent_runs_else`, `match_get_{present,absent,reversed_arms}` |
| `Bytes<32>` (multi-Fr K) | `Uint<64>` | `bytes_get_sugar_{present,absent}` |
| `Uint<64>` | `Bytes<32>` (multi-Fr V) | `bytes_v_get_sugar_{present,absent}` |

Each test exercises both the active path (key present → lookup fires) and the inactive path (key absent → lookup branch's PIs guard out without consuming transcript entries).

## Limitations

- `let-else` (`let Some(v) = self.map.get(&k) else { return; }`) isn't supported yet.
- The scrutinee must be exactly `self.<field>.get(<key>)` — chained or wrapped calls (`(self.map.get(&k)).clone()`) won't trigger the rewrite.
- The else / None arm can't access `v` (it's only bound inside the Some/then branch).
- Match arms with guards (`Some(v) if pred(v) =>`) aren't recognized — a guard could refuse the lookup despite contains=true, breaking the soundness of the rewrite.
- Only the binary Some+None match is supported; richer patterns (`Some(0) => ..., Some(_) => ..., None => ...`) fall through to `Unsupported`.
- The user-source still needs the storage-layer `Map::get` method (`crates/midnight-storage/src/map.rs`) so the Rust type check passes; we deliberately don't strip it.
