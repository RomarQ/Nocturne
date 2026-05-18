# Where to find things in midnight-ledger

**Discovered**: 2026-05-18 (continuously updated)

Reference map for the `ledger-8` branch: https://github.com/midnightntwrk/midnight-ledger/tree/ledger-8 (local mirror at `reference-repos/midnight-ledger/`).

## Crate layout

| Crate | What it owns |
|---|---|
| `zkir` | ZKIR data structures (`IrSource`, `Instruction`), preprocessing (`ir_vm.rs::preprocess` → builds `pis` + `pi_skips`), Plonk synthesis (`ir_vm.rs::synthesize`). |
| `onchain-vm` | The on-chain VM: `Op` enum (the transcript opcodes), `field_repr` for each Op, gas cost model, VM execution. |
| `onchain-runtime` | Contract execution context: `Transcript<D>` struct, `Effects<D>`, `ContractOperation`, `EntryPointBuf`. |
| `transient-crypto` | `Fr`, `ProofPreimage`, `VerifierKey`, `transient_commit` (Poseidon-based), `Zkir` trait, `ProvingProvider` trait. |
| `base-crypto` | `MidnightDataProvider` (Plonk params fetching), `RunningCost`, `AlignedValue` (fab module). |
| `coin-structure` | `ContractAddress`, coin/token types. |
| `ledger` | Transaction-level: `ContractCallPrototype`, `ContractCallExt::construct_proof`, `Intent::add_call`, `ContractCall::prove` (Noop interleaving lives here), `ContractCall::public_inputs` (verifier PI builder), `verify` module. |
| `storage` | `Array`, `Sp` (smart pointers for storable types), DB abstractions (`DefaultDB`, `InMemoryDB`). |

## Key file:line references

| Topic | File | Lines |
|---|---|---|
| `do_communications_commitment` flag definition | `zkir/src/ir.rs` | 41 |
| Preprocess: `DeclarePubInput` pushes to `pis` unconditionally | `zkir/src/ir_vm.rs` | 339-342 |
| Preprocess: `PiSkip` semantics (`Some(guard) if !idx_bool…`) | `zkir/src/ir_vm.rs` | 421-427 |
| Preprocess: `CondSelect` semantics (`is_zero` + `select`) | `zkir/src/ir_vm.rs` | 603-610 |
| Preprocess: communications commitment check (`Communications commitment mismatch`) | `zkir/src/ir_vm.rs` | 484-498 |
| Synthesis: `DeclarePubInput` always constrains as public input | `zkir/src/ir_vm.rs` | 626-628 |
| Synthesis: `PiSkip` is a no-op at synthesis (metadata only) | `zkir/src/ir_vm.rs` | 629 |
| Synthesis: communications commitment Poseidon constraint | `zkir/src/ir_vm.rs` | 768-786 |
| `Op::Noop`'s `field_repr` writes zeros | `onchain-vm/src/ops.rs` | 403 |
| Op enum (Branch, Jmp, Noop, etc.) | `onchain-vm/src/ops.rs` | 95+ |
| Branch/Jmp execution in VM | `onchain-vm/src/vm.rs` | 1009-1027 |
| `Transcript<D>` struct (`gas`, `effects`, `program`, `version`) | `onchain-runtime/src/transcript.rs` | 44-49 |
| `ContractCallPrototype` struct | `ledger/src/construct.rs` | 486-497 |
| `ProofPreimage::construct_proof` (canonical preimage builder) | `ledger/src/construct.rs` | 509-565 |
| `Intent::add_call` (sets `communications_commitment: Some(...)` unconditionally) | `ledger/src/construct.rs` | 590-611 |
| Communications commitment definition (`transient_commit(input ++ output, rand)`) | `ledger/src/construct.rs` | 912-914 |
| `ContractCall<P,D>` struct | `ledger/src/structure.rs` | 2381-2390 |
| `ContractCall::prove` Noop interleaving | `ledger/src/prove.rs` | 263-289 |
| `ContractCall::public_inputs` (verifier-side PI builder) | `ledger/src/verify.rs` | 1869-1883 |
| `ContractCall::binding_input` (hash over address/entry_point/gas/effects/etc.) | `ledger/src/verify.rs` | 1885+ |
| Contract proof verify call site | `ledger/src/verify.rs` | 1845-1851 |
| `VerifierKey::verify` (calls into `midnight_zk_stdlib::verify`) | `transient-crypto/src/proofs.rs` | 545-558 |
| `ProvingProvider` trait | `transient-crypto/src/proofs.rs` | 674-686 |
| `transient_commit` (Poseidon over `[opening, ..value]`) | `transient-crypto/src/hash.rs` | 84-88 |

## How to verify a file:line ref is still current

The branch is `ledger-8` and the crate versions on crates.io are at v8.1.0 (ledger) / v3.1.0 (onchain-runtime) as of 2026-05-18. If you're checking against a different upstream version, line numbers will drift. Grep for the symbol name first; trust the symbol over the line number.
