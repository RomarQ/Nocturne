# Scope blockers for "complex contracts" feature work

**Last revisited**: 2026-05-20

The features below are documented here so future contributors don't redo the
investigation. Each entry lists what blocks the work, why it can't be done
in-session, and what would unblock it.

## Environment context: `kernel.self()`, block height, caller

**Blocker**: no dedicated on-chain opcodes.

The on-chain VM (`reference-repos/midnight-ledger/onchain-vm/src/ops.rs`) has
no `Self`, `BlockHeight`, or `Caller` instruction. Compactc threads these
through a `kernel` ledger field at a fixed slot — every contract is assumed to
have a `kernel: Kernel` field at a designated position, and `kernel.self()`
lowers to an Idx into that slot. The on-chain runtime injects the live values
into the slot before transcript replay.

Faithfully mirroring this in Nocturne requires upstream coordination with the
Midnight Foundation on the exact slot layout (which field-index Kernel sits at,
how the runtime pre-populates it for a given contract call). Without that, any
implementation would be a guess that breaks compatibility with the actual
chain.

**Unblocker**: confirmation from `midnight-foundation` of the canonical Kernel
slot index + the on-chain runtime injection contract.

## Enum sum types with HETEROGENEOUS payloads

**Status**: homogeneous-payload variants landed in commit 27c8228.
`enum Action { Mint(Uint<64>), Burn(Uint<64>) }` (same `T` in every variant)
encodes as `(Bytes<1>, T)` on-chain. The heterogeneous case below is still
open.

**Blocker**: no agreed encoding for heterogeneous variants.

`enum Action { Mint(Uint<64>), Burn(Bytes<32>) }` has variants with different
payload shapes. Compactc's approach is to NOT have true sum-of-products — it
provides `Maybe<T>` and `Either<A, B>` as structs where all fields are always
materialized (the tag is a boolean discriminant, the payloads coexist
unconditionally). True payload-carrying variants would need either that same
all-fields-always-allocated layout (which wastes wire space for unused
variants) or a runtime-discriminated union (which compactc doesn't have on
chain).

Nocturne could pick either, but the wire-layout decision affects every
downstream tool (midnight-rs, indexers, the verifier). It should be a project
decision, not a session-time call.

**Unblocker**: a written ADR picking the encoding (compactc-style
all-fields-always vs. tagged-union) so the codegen has a target to hit.

**Also landed (commit b35b580)**: match-on-payload binding (`match a { Action::Mint(x) => f(x), Action::Burn(y) => g(y) }`). The parser lowers tuple-struct patterns with an ident binding to an `ExprIR::EnumPayload` projection prepended to the arm body. ZKIR returns the scrutinee's wire shifted by the discriminant width (offset 1); transcript codegen emits an inline `match` over the user enum — same shape as user-facing pattern matching. The `.payload()` synthetic accessor is gone; Rust enums don't have one and the codebase no longer pretends they do.

## Cross-contract calls

**Blocker**: large scope, multi-week.

Touches contract addressing, call ABI encoding, recursive verification, and
state isolation guarantees. Not a single-session change.

**Unblocker**: a dedicated work plan + design doc.

## ZKIR v3 / ZKIR optimization

**Blocker**: needs upstream ZKIR v3 release.

The midnight-zkir crate is at v2. v3 changes the IR opcode layout. Until v3
ships, optimization passes have no stable target.

**Unblocker**: midnight-zkir v3 release notes + upgrade guide.

## What's NOT a blocker (recently shipped)

These were on prior "remaining items" lists and were resolved in-tree:

- User unit-variant enums + match-on-enum (commit 75498c3).
- Counter::increment_by(N) for const N (commit b7530c3).
- Counter::set(_) with witness values (commit fd0f123) — supersedes the
  long-standing `Counter::increment_by(witness)` request.
- Constructor-driven `deploy::initial_state(_)` with parameter forwarding
  (commits 6be6652 + 6e831c3).
- let-bindings carrying witness reads, witness arithmetic, and ledger
  reads (commits f53d5e9 + f2ac5bf + 9a07b66).
- `as` cast as a transparent IR passthrough (commit fd0f123).
- `nocturne::disclose` runtime stub + `ExprIR::Tuple` arg lowering (commit
  b612508).
- `Uint<N>` audit for `64 < N ≤ 128` (commit 3efaeb5). The codegen was
  already generic; the commit added the `as u128` cast branch + a
  pipeline test (`uint128_pipeline_proves_and_verifies`).
- `Option<T>` as a synthetic homogeneous-payload enum-like (commit
  3e4a086). Wire shape `(Bytes<1>, T)` matches Compact's `Maybe<T>`
  via `impl<T: Aligned> Aligned for Option<T>`. `match` on `Some`/`None`
  with payload binding works without a synthetic accessor. Supersedes
  the "Maybe<T> wrapper" entry from earlier lists.
- `[T; N]` arrays (`N ≤ 11`) (commit 6601cc8) via new `ExprIR::Index`
  variant. Wire shape: N-tuple of T (same as Compact's `Vector<N, T>`).
  Scoped to witness-sourced arrays today — let-bound and ledger-stored
  arrays still need the variables-map type-carrying refactor; see
  `memories/option-and-array-encoding.md`.
- `if`-as-expression (commit 96bfdf9). `let x = if c { a } else { b };`
  multiplexes branch result wires via ZKIR `cond_select` and emits a
  Rust `if`-expression on the transcript side. Statement-only branches
  keep the prior if-as-statement behaviour.
- Crate rename `midnight-* → nocturne-*` (commits c35e9fa + this
  commit). Stage A renamed the ten internal crates and dropped the
  upstream `midnight-storage` collision. Stage B renamed the umbrella
  crate `midnight → nocturne`, the `#[midnight(...)]` attribute
  namespace to `#[nocturne(...)]`, the `cargo midnight` subcommand to
  `cargo nocturne`, and the `target/midnight/` artifact directory to
  `target/nocturne/`.
