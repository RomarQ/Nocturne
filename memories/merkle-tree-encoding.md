# `MerkleTree<H, T>` ledger field — encoding investigation

**Discovered**: 2026-05-19 (empirical sweep against compactc 0.30.0 for `MerkleTree<10, Bytes<32>>`)
**Status**: investigation only, **not yet implemented**. This memory captures the full encoding so future sessions can implement in stages.

## TL;DR

`MerkleTree<H, T>` is the most complex Compact ledger primitive — substantially bigger than `Map`, `Set`, or `Cell`. It needs:

- A new storage shape: the ledger field is internally a 2-element `StateValue::Array` of `[BoundedMerkleTree<()>, Cell<u64>]`.
- A constructor that initializes the Array (other primitives default to `Null`).
- Two new VM opcodes: `Root` (`0x0a`) and `Eq` (`0x02`).
- `AlignmentAtom::Field` encoding (`LoadImm -2`) — same missing machinery as the deferred `Cell<Field>` work.
- `persistent_hash` with the `"mdn:lh"` domain separator (`0x6D646E3A6C68`) for leaf hashing.
- A `MerkleTreeDigest` user-facing type (newtype around `Field`).
- `Dup{n:k}` for arbitrary `k` (today only `n:0` is used).
- `Ins{cached:true, n:2}` for multi-level write-back.

Plus the `MerkleTreePath` / `MerkleTreePathEntry` / `merkleTreePathRoot` machinery from the Compact standard library, if/when path proofs are needed.

## Storage shape: 2-element Array

A `ledger entries: MerkleTree<10, Bytes<32>>` compiles to a contract-state entry whose `StateValue` is:

```
StateValue::Array([
    StateValue::BoundedMerkleTree(MerkleTree<()>::blank(10)),   // height-10 tree, () values
    StateValue::Cell(Cell<u64>(0)),                              // next-index counter
])
```

Verified by the compactc-generated TypeScript runtime stub (`/tmp/mt-experiments/out/contract/index.js:191-195`):

```js
StateValue.newArray()
    .arrayPush(StateValue.newBoundedMerkleTree(new StateBoundedMerkleTree(10)))
    .arrayPush(StateValue.newCell({ value: descriptor_4.toValue(0n), alignment: descriptor_4.alignment() }))
```

`BoundedMerkleTree(MerkleTree<()>)` is the upstream variant from `onchain-state/src/state.rs:79-98`. The element type `T` of the user-facing `MerkleTree<H, T>` only ever lives as a *leaf hash* (Field element) at the on-chain level — `T`'s alignment is irrelevant to the on-chain encoding.

### Constructor emission

Other primitives (`Counter`, `Cell`, `Map`, `Set`) default to `StateValue::Null` and don't need a constructor IR. `MerkleTree` does, because it carries height information that must be initialized at deploy. The compactc constructor for `entries` emits:

```
Push { storage: false, Cell(field_idx=0) }
Push { storage: true,  Array { [BoundedMerkleTree(H), Cell(0_u64)] } }
Ins  { cached: false, n: 1 }
```

The `Push(Array)` declare is non-trivial: `StateValue::Array.field_repr` writes `[3 | (len << 4), ..elements]` (`state.rs:191`), then each element's `field_repr` (for BoundedMerkleTree: `[4 | (height << 4) | (entries << 12), ..entries]`).

## `MerkleTree::insert(leaf)` — 10 ops

From `/tmp/mt-experiments/out/zkir/add.zkir` and `index.js:204-242`:

```text
Idx  { cached:false, push_path:true,  [Bytes<1>(field_idx)] }   // navigate to entries field
Idx  { cached:false, push_path:true,  [Bytes<1>(0)] }            // navigate into entries[0] (BoundedMerkleTree)
Dup  { n: 2 }                                                     // copy entries Array from stack pos 2
Idx  { cached:false, push_path:false, [Bytes<1>(1)] }            // read entries[1] (next-index Cell<u64>)
Push { storage:true, Cell(leafHash(leaf)) }                       // hashed leaf, encoded as Cell(Bytes<32>) — see leafHash below
Ins  { cached:false, n: 1 }                                       // insert (next_index, leaf_hash) into BMT
Ins  { cached:true,  n: 1 }                                       // write modified BMT back to entries[0]
Idx  { cached:false, push_path:true,  [Bytes<1>(1)] }            // navigate to entries[1]
Addi { immediate: 1 }                                              // increment counter
Ins  { cached:true,  n: 2 }                                       // write back counter, 2 levels deep
```

The trailing `Ins { cached:true, n:2 }` is unusual — every other ledger op uses `n:1`. The `n` parameter is the number of `Idx{push_path:true}` levels to unwind when writing back. For `entries[1]` we navigated two levels deep (`entries` field, then `[1]`), so the write-back unwinds both.

### `leafHash` domain separator

Compactc emits `persistent_hash` with the immediate `0x6D646E3A6C68` (ASCII `"mdn:lh"` = midnight:leafhash) as the domain-separator input, followed by the leaf bytes:

```text
persistent_hash {
    alignment: [Bytes{6}, Bytes{32}],   // domain prefix + leaf
    inputs: [imm("mdn:lh"), leaf_chunk_0, leaf_chunk_1]
}
```

The result is a single Fr that's then pushed as `Cell(Bytes<32>)` (the leaf hash, with 32-byte alignment matching the original leaf's type).

## `MerkleTree::checkRoot(MerkleTreeDigest)` — 7 ops

From `/tmp/mt-experiments/out/zkir/check_root.zkir` and `index.js:244-268`:

```text
Dup  { n: 0 }                                                    // dup contract state
Idx  { cached:false, push_path:false, [Bytes<1>(field_idx)] }   // navigate to entries field
Idx  { cached:false, push_path:false, [Bytes<1>(0)] }            // navigate to entries[0] (BoundedMerkleTree)
Root                                                              // pop BMT, push its root as AlignedValue<Field>
Push { storage:false, Cell(Field(user_root_digest.field)) }      // push user-supplied digest
Eq                                                                // pop 2 Cells, push bool
Popeq { cached:true, result: bool }                               // yield bool to verifier
```

Two new opcodes used:

- `Root` (`0x0a`): pops a `BoundedMerkleTree`, pushes `AlignedValue::from(tree.root())` as a Cell. From `onchain-vm/src/vm.rs:562-577`.
- `Eq` (`0x02`): pops two `Cell`s, pushes `(a == b).into()` as a Cell-encoded bool. From `vm.rs:408-413`.

## `AlignmentAtom::Field` encoding

`AlignmentAtom::Field` encodes as the field element `-2` (i.e., `Fr::ORDER - 2`). Verified by `transient-crypto/src/fab.rs:600-612`:

```rust
impl FieldRepr for AlignmentAtom {
    fn field_repr<W>(&self, writer: &mut W) {
        match self {
            AlignmentAtom::Bytes { length } => writer.write(&[(*length).into()]),
            AlignmentAtom::Compress => writer.write(&[(-1).into()]),
            AlignmentAtom::Field => writer.write(&[(-2).into()]),
        }
    }
}
```

In the IR this surfaces as `LoadImm -2` (the `"-02"` we see in `check_root.zkir`). Our existing `aligned_value_encoding` table only knows about `Bytes{N}` atoms — supporting Field requires extending the encoding helper to accept a negative-value Fr.

This is the same machinery the deferred `Cell<Field>` work needs. **Implementing Field cells is a natural prerequisite for `MerkleTree::checkRoot`.**

## User-facing types

From `compact/compiler/standard-library.compact:50-60`:

```compact
export struct MerkleTreeDigest { field: Field; }

export struct MerkleTreePathEntry {
    sibling: MerkleTreeDigest;
    goes_left: Boolean;
}

export struct MerkleTreePath<#n, T> {
    leaf: T;
    path: Vector<n, MerkleTreePathEntry>;
}

export circuit merkleTreePathRoot<#n, T>(path: MerkleTreePath<n, T>): MerkleTreeDigest { ... }
```

The Nocturne API would mirror these as Rust types. `MerkleTreeDigest` is just a newtype around `Field`; `MerkleTreePath` is a generic-height struct that uses `persistent_hash` to compute roots from sibling chains.

`merkleTreePathRoot` is a pure circuit (no ledger access) — it's a chain of `persistent_hash` calls that the user calls on a witness-provided path to verify inclusion. The election example uses it for nullifier proofs.

## Implementation staging

A reasonable phased implementation, smallest first:

| Phase | Scope | Substrate needed | Status |
|---|---|---|---|
| **A** | `Cell<Field>` — single AlignmentAtom::Field test | Field alignment encoding in `aligned_value_encoding`, `LoadImm` for negative Fr values | **landed** ([[field-alignment-encoding]]) |
| **B** | `MerkleTree<H, T>` storage type + `MerkleTreeDigest` type | `MerkleTree<H, T>: LedgerType { requires_init = true, ... }`; off-chain root() that matches on-chain Root opcode semantics | **landed** (see below) |
| **C** | `MerkleTree::checkRoot` end-to-end | Phase A + B; `Root` and `Eq` opcodes in zkir_emitter / transcript_codegen; e2e test with empty tree | **landed** (see below) |
| **D** | `MerkleTree::insert` end-to-end | `Dup{n:k}` for arbitrary k; `Ins{cached:true, n:2}`; `persistent_hash` with `"mdn:lh"` domain separator; multi-level Idx chains; e2e test | **landed** (see below) |
| **E** | `MerkleTreePath<H, T>` + `merkleTreePathRoot` | Pure circuit primitive; uses existing `persistent_hash` machinery; user-side witness type | pending |

Each phase is roughly the scope of the Set or Cell::set work we've already shipped — together they're 3-5 sessions of focused work.

### Phase B notes

Implemented 2026-05-19:

- `midnight-storage::MerkleTree<const HEIGHT: usize, T>` wraps the upstream `midnight_transient_crypto::merkle_tree::MerkleTree<()>` plus a `next_index: u64` counter, mirroring the on-chain 2-element Array shape. Insertion drives `next_index` and forwards to `try_update_hash`; `root()` lazily rehashes before reading.
- `midnight-types::MerkleTreeDigest { field: Field }` mirrors Compact's stdlib struct. Conversion from the upstream `MerkleTreeDigest(Fr)` truncates to the low 128 bits because our `Field` is still a u128 wrapper — same accepted limitation as Phase A.
- New `MerkleLeaf` trait (in midnight-storage) bridges `T` to `[u8]` so the upstream `leaf_hash` (with the `"mdn:lh"` domain separator) consumes it. Impls for `[u8; N]` and `Bytes<N>`. This sidesteps the orphan-rule issue with adding `BinaryHashRepr` to `Bytes<N>` directly.
- `LedgerType::requires_init()` returns `true` for MerkleTree — first ledger primitive to do so. Constructor IR emission (the actual `Push(Array)` op sequence) is **deferred to Phase D** because today our codegen does not emit constructor IR for any ledger field. None of the e2e tests exercise the deploy path; they build state via Rust constructors and prove against circuits, so requiring constructor IR isn't blocking other phases.

Five storage-layer unit tests cover empty/insert/check_root/Bytes<N> leaves/requires_init.

### Phase C notes

Implemented 2026-05-19:

- IR (`zkir_emitter.rs::emit_merkle_tree_check_root`): emits the full 7-op encoding (Dup + Idx + Idx + Root + Push(Cell(Field)) + Eq + Popeq). Reuses Phase A's `emit_push_cell` with the Field encoding to push the user-supplied digest. The `Root` (`0x0a`) and `Eq` (`0x02`) opcodes are 1-declare each (`[opcode]` + PiSkip{count:1}).
- Transcript codegen (`transcript_codegen.rs::generate_merkle_tree_check_root`): emits matching `Op::Root` / `Op::Eq` runtime ops and computes the bool result via `state.<field>.check_root(&__digest)`. `circuit_needs_state` extended to recognize `check_root` so the transcript fn gets the `state` parameter.
- `MerkleTreeDigest` is now a recognized witness type: the witness push reads `.field().value()` (vs. the usual `.value()`) since it's a newtype around `Field`. Detection via `is_merkle_tree_digest` in transcript codegen, mirroring `is_bytes_witness`.
- Storage refactor: `check_root` and `root` are `&self` (rehash happens eagerly on `insert`). Required because the transcript codegen passes `state: &<LedgerName>`, not `&mut`.

E2E tests:
- `mt_check_root_matches_empty_tree_proves_and_verifies` — digest equals the empty-tree root, Popeq result is `true`
- `mt_check_root_mismatch_proves_and_verifies` — bogus digest, Popeq result is `false`; the proof still constructs because `check_root` is a query, not an assertion

Both prove+verify through `ContractCallExt::construct_proof`. The PIs match the on-chain ledger-shape PIs declare-for-declare.

### Phase D notes

Implemented 2026-05-19:

- IR (`zkir_emitter.rs::emit_merkle_tree_insert`): emits the full 10-op encoding matching compactc 0.30.0. Three new opcodes/encodings landed:
  - `Dup{n:2}` = `0x32` (first non-zero `n` we've emitted; the encoding is `0x30 | n`).
  - `Ins{cached:true, n:2}` = `0xa2` (multi-level write-back — `n` is the number of `Idx{push_path:true}` levels to unwind when writing back).
  - `Persistent_hash` with alignment `[Bytes{6}, Bytes{32}]` and the `"mdn:lh"` domain separator (literal `0x686C3A6E646D` little-endian) computes the leaf hash. The hash output is 2 Frs (32 bytes chunked into 2 Bytes<32> chunks).

  Also fixed `instruction_output_count` to return `2` for `PersistentHash` — the upstream `ir_vm.rs:419` pushes `hash.field_vec()` to memory which is 2 Frs for the 32-byte HashOutput. The previous default-1 was a dormant bug (no test exercised indices beyond the hash).

- Transcript codegen (`transcript_codegen.rs::generate_merkle_tree_insert`): emits matching runtime ops. The leaf hash is computed via `midnight_transient_crypto::merkle_tree::leaf_hash(leaf.as_bytes())`, whose output is `HashOutput([u8; 32])`; passing the inner `[u8; 32]` to `AlignedValue::from` gives the Bytes<32>-aligned AlignedValue the IR's Push declares expect. Routed through the existing `"insert"` dispatcher arm alongside Map/Set/Cell.

E2E test: `mt_insert_proves_and_verifies` — inserts a single `Bytes<32>` leaf into an empty `MerkleTree<10, Bytes<32>>` and confirms the 10-op transcript proves and verifies via the canonical ledger preimage path.

Constructor IR for the initial `Array<BoundedMerkleTree, Cell<u64>>` state is still deferred — the e2e tests build state through Rust's `MerkleTree::empty()` (which mirrors the on-chain initial shape via the upstream `MerkleTree<()>` wrapper), and `construct_proof` doesn't execute on-chain VM ops, so insert proves+verifies against the canonical preimage path without explicit constructor emission.

## Files implicated for any implementation

- `crates/midnight-storage/src/merkle_tree.rs` — storage type (`pub struct MerkleTree`, with `insert`, `check_root`, `root` methods)
- `crates/midnight-codegen/src/zkir_emitter.rs` — `emit_merkle_tree_method` dispatcher; `emit_merkle_tree_insert`, `emit_merkle_tree_check_root`; new `emit_push_array` for the constructor; new `emit_load_imm_field_atom` for `LoadImm -2`
- `crates/midnight-codegen/src/transcript_codegen.rs` — `generate_merkle_tree_insert`, `generate_merkle_tree_check_root`; constructor emission for the initial Array state
- `crates/midnight-types/src/merkle_tree.rs` — `MerkleTreeDigest`, `MerkleTreePath`, `MerkleTreePathEntry`
- `crates/midnight-ir/src/parse.rs` — recognize `MerkleTree<H, T>` field type (parse H as const generic)
- `crates/midnight/tests/ledger_integration_test.rs` — phase-specific e2e tests

## Empirical compactc references

- Source: `/tmp/mt-experiments/mt.compact`
- ZKIR: `/tmp/mt-experiments/out/zkir/{add,check_root}.zkir`
- TS runtime stub: `/tmp/mt-experiments/out/contract/index.js`
- contract-info: `/tmp/mt-experiments/out/compiler/contract-info.json`
- Reproduce: `compactc /tmp/mt-experiments/mt.compact /tmp/mt-experiments/out`

## Upstream protocol references

- `onchain-state/src/state.rs:79-98` — `StateValue::BoundedMerkleTree` variant
- `onchain-state/src/state.rs:191-205` — `StateValue::Array` and `BoundedMerkleTree` field_repr
- `onchain-state/src/state.rs:359` — `BoundedMerkleTree` constructor via `MerkleTree::blank(height)`
- `onchain-vm/src/vm.rs:562-577` — `Root` op behavior
- `onchain-vm/src/vm.rs:408-413` — `Eq` op behavior
- `onchain-vm/src/ops.rs:405,413` — `Eq=0x02`, `Root=0x0a` field_repr
- `transient-crypto/src/fab.rs:600-612` — `AlignmentAtom::Field` → `-2` encoding
- `compact/compiler/standard-library.compact:50-90` — user-facing types and `merkleTreePathRoot`
