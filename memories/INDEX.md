# Memories index

Durable findings about Nocturne's interaction with midnight-ledger. Read before assuming, write after discovering. See `../CLAUDE.md` for conventions.

| File | One-line hook |
|---|---|
| [do-communications-commitment-required.md](do-communications-commitment-required.md) | Every emitted circuit must set `do_communications_commitment: true` — the ledger feeds the commitment slot unconditionally. |
| [ledger-pi-layout.md](ledger-pi-layout.md) | The on-chain ledger builds verifier PIs as `[binding_input, commitment, ..field_repr(transcript_with_noops)]` and interleaves `Op::Noop { n }` for inactive branches. |
| [conditional-branch-cond-select-zeroing.md](conditional-branch-cond-select-zeroing.md) | Inside a conditional branch, every `DeclarePubInput` value must be zero when the branch is inactive. Achieve via `cond_select(guard, value, ZERO)`. |
| [compactc-vs-nocturne-divergences.md](compactc-vs-nocturne-divergences.md) | Storage and branching encoding differences between compactc and Nocturne that limit cross-compiler VK equivalence beyond the counter contract. |
| [where-to-find-things-in-midnight-ledger.md](where-to-find-things-in-midnight-ledger.md) | Reference map: which crate/file/function implements which part of the protocol. |
| [witness-type-support.md](witness-type-support.md) | Boolean/Field/Uint<N> witnesses supported. Bytes<N> rejected at parse time pending multi-Fr witness emission. |
