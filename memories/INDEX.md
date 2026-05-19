# Memories index

Durable findings about Nocturne's interaction with midnight-ledger. Read before assuming, write after discovering. See `../CLAUDE.md` for conventions.

| File | One-line hook |
|---|---|
| [project-scope.md](project-scope.md) | Nocturne is an authoring eDSL — its job ends at producing compileable artifacts. Deploy/call/wallet/node belong in downstream tools. |
| [do-communications-commitment-required.md](do-communications-commitment-required.md) | Every emitted circuit must set `do_communications_commitment: true` — the ledger feeds the commitment slot unconditionally. |
| [ledger-pi-layout.md](ledger-pi-layout.md) | The on-chain ledger builds verifier PIs as `[binding_input, commitment, ..field_repr(transcript_with_noops)]` and interleaves `Op::Noop { n }` for inactive branches. |
| [conditional-branch-cond-select-zeroing.md](conditional-branch-cond-select-zeroing.md) | Inside a conditional branch, every `DeclarePubInput` value must be zero when the branch is inactive. Achieve via `cond_select(guard, value, ZERO)`. |
| [compactc-vs-nocturne-divergences.md](compactc-vs-nocturne-divergences.md) | Storage and branching encoding differences between compactc and Nocturne that limit cross-compiler VK equivalence beyond the counter contract. |
| [where-to-find-things-in-midnight-ledger.md](where-to-find-things-in-midnight-ledger.md) | Reference map: which crate/file/function implements which part of the protocol. |
| [witness-type-support.md](witness-type-support.md) | Boolean/Field/Uint<N>/Bytes<N> witnesses all supported. `Bytes<N>` uses multi-Fr emission (`ceil(N/31)` PrivateInputs with per-chunk ConstrainBits). |
| [map-ledger-field-encoding.md](map-ledger-field-encoding.md) | Empirical compactc emission for `Map<K, V>` insert/lookup/member, opcode reference. All four Compact primitives (contains/lookup/insert/remove) on-chain compatible. Option<V>-returning `Map::get` deferred — Popeq can't represent Null. |
| [storage-cell-encoding-gap.md](storage-cell-encoding-gap.md) | All Cell ops (`set`/`get`) on-chain compatible for typed primitives and `Bytes<N>` (multi-Fr Push + Popeq). Counter::value too. Map<Bytes<N>, _> and `Field` cells still pending. |
