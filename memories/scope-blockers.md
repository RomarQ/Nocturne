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

## Crate rename `midnight-* → nocturne-*`

**Blocker**: explicit project policy.

`CLAUDE.md` says: "When editing manifests, leave the name as-is — don't
preemptively rename." The rename is sequenced by the project owner; don't
start it autonomously.

**Unblocker**: explicit owner instruction.

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

**Also deferred**: match-on-payload binding (`match a { Action::Mint(x) => f(x) }`).
Users access the payload via the generated `.payload()` accessor today;
match-binding needs a new `ExprIR` shape and a parse_match enhancement.

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
- `midnight::disclose` runtime stub + `ExprIR::Tuple` arg lowering (commit
  b612508).
