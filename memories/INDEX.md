# Memories index

Durable findings about Nocturne's interaction with midnight-ledger. Read before assuming, write after discovering. See `../CLAUDE.md` for conventions.

| File | One-line hook |
|---|---|
| [project-scope.md](project-scope.md) | Nocturne is an authoring eDSL — its job ends at producing compileable artifacts. Deploy/call/wallet/node belong in downstream tools. |
| [do-communications-commitment-required.md](do-communications-commitment-required.md) | Every emitted circuit must set `do_communications_commitment: true` — the ledger feeds the commitment slot unconditionally. |
| [ledger-pi-layout.md](ledger-pi-layout.md) | The on-chain ledger builds verifier PIs as `[binding_input, commitment, ..field_repr(transcript_with_noops)]` and interleaves `Op::Noop { n }` for inactive branches. |
| [conditional-branch-cond-select-zeroing.md](conditional-branch-cond-select-zeroing.md) | Inside a conditional branch, every `DeclarePubInput` value must be zero when the branch is inactive. Achieve via `cond_select(guard, value, ZERO)`. |
| [conditional-io-guards.md](conditional-io-guards.md) | Inside a conditional branch, `PrivateInput`/`PublicInput` must carry `guard = Some(branch_guard)` so the VM skips transcript consumption on inactive paths. Companion to cond-select-zeroing — together they make conditional reads (Map::contains, Cell::get) on-chain compatible. |
| [map-get-sugar.md](map-get-sugar.md) | Parser rewrites `if let Some(v) = self.map.get(&k) { body }` to `if self.map.contains(&k) { let v = self.map.lookup(&k); body }` — the canonical contains+lookup shape for on-chain Option<V> semantics. |
| [set-ledger-field-encoding.md](set-ledger-field-encoding.md) | `Set<T>` reuses `Map`'s on-chain ops with `StateValue::Null` as the placeholder value. contains/remove identical to Map; insert differs only in pushing Null (`[0x11, 0]`) instead of `Cell(value)`. |
| [merkle-tree-encoding.md](merkle-tree-encoding.md) | Investigation memory + phased plan for `MerkleTree<H, T>`. Phases A+B+C+D landed (Cell<Field>, storage, MerkleTreeDigest, check_root, insert); E pending (MerkleTreePath inclusion proofs). |
| [field-alignment-encoding.md](field-alignment-encoding.md) | `Cell<Field>` on-chain compatible via `AlignmentAtom::Field` (`-2` encoding). Phase A of the MerkleTree plan; alignment_atoms switched to `Vec<i32>` so positive Bytes lengths and negative Field atoms coexist. Prerequisite for `MerkleTree::checkRoot`. |
| [compactc-vs-nocturne-divergences.md](compactc-vs-nocturne-divergences.md) | Storage and branching encoding differences between compactc and Nocturne that limit cross-compiler VK equivalence beyond the counter contract. |
| [where-to-find-things-in-midnight-ledger.md](where-to-find-things-in-midnight-ledger.md) | Reference map: which crate/file/function implements which part of the protocol. |
| [witness-type-support.md](witness-type-support.md) | Boolean/Field/Uint<N>/Bytes<N> witnesses all supported. `Bytes<N>` uses multi-Fr emission (`ceil(N/31)` PrivateInputs with per-chunk ConstrainBits). |
| [map-ledger-field-encoding.md](map-ledger-field-encoding.md) | Empirical compactc emission for `Map<K, V>` insert/lookup/member, opcode reference. All four Compact primitives (contains/lookup/insert/remove) on-chain compatible for both single-Fr and multi-Fr `Bytes<N>` K/V. Option<V>-returning `Map::get` deferred — Popeq can't represent Null. |
| [storage-cell-encoding-gap.md](storage-cell-encoding-gap.md) | All Cell ops (`set`/`get`) on-chain compatible for typed primitives and `Bytes<N>` (multi-Fr Push + Popeq). Counter::value too. Map<Bytes<N>, _> and `Field` cells still pending. |
