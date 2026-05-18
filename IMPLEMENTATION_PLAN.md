# Implementation Plan -- midnight-edsl

See [SPEC.md](./SPEC.md) for the full design specification.

---

## Completed Work (38 tests, 0 warnings)

### Core Pipeline ✓

**End-to-end proven:** Rust contract → ZKIR → keygen → transcript → prove → **verify ✓**

- Counter increment produces a 2528-byte Plonk proof that passes verification in 100ms.

### IR Parser ✓

`ContractIR`, `LedgerIR`, `WitnessIR`, `CircuitIR`, `ExprIR` (15 variants). Attribute parsing, structural validation, expression tree, witness detection by parameter name.

### Types + Storage ✓

`Field`, `Boolean`, `Bytes<N>`, `Uint<N>`, `Cell<T>`, `Counter`, `Map<K,V>`, `MerkleTree<DEPTH>`. Test-mode backing for `cargo test`.

### ZKIR Emitter ✓

Encodes transcript VM ops as `DeclarePubInput` + `PiSkip`. Conditional branches use guard variables. Public circuit arguments set `num_inputs`. Return values emit `Output` + `do_communications_commitment`. 7 `IrSource::check()` tests pass.

### Transcript Codegen ✓

Generates `build_X_transcript()` functions returning `Vec<Op<ResultModeVerify>>` using midnight-ledger types directly. Field representation matches ZKIR's declared public inputs.

### Deploy Codegen ✓

`deploy::initial_state()` generates `StateValue::Array` from ledger field types.

### cargo-midnight CLI ✓

- `build`: compiles contracts, writes ZKIR + contract-info.json to `target/midnight/`
- `keygen`: generates real Plonk prover/verifier key files (`.prover`, `.verifier`)
- `test`: runs `cargo test`

### contract-info.json ✓

Matches Compact's schema: `compiler-version`, `language-version`, `runtime-version`, `circuits`, `witnesses` (with `private$` prefix), `contracts`.

### Example Contract ✓

`examples/counter-contract/` with 3 tests (logic, transcript, deploy).

### Proof Generation + Verification ✓

Full prove → verify cycle for counter increment circuit.

---

## Remaining Work

### Phase A: Robustness

| # | Task | Size | Notes |
|---|---|---|---|
| A.1 | `ConstrainBits` for `Uint<N>` circuit arguments | S | Emit `ConstrainBits { var, bits: N }` after input allocation |
| A.2 | `ConstrainToBoolean` for `Boolean` arguments | S | Emit after input allocation |
| A.3 | Proper `Popeq` result values in transcript builder | M | Use actual `AlignedValue` from state read, not placeholder |
| A.4 | Nested expression support (method chains, complex conditions) | M | Currently only handles simple patterns |
| A.5 | Error on unsupported Rust patterns | M | Reject closures, async, trait objects with `MIDNIGHT-3xx` errors |
| A.6 | Multiple witness fields in `PrivateInput` ordering | M | Ensure field order matches witness struct declaration |

### Phase B: Complex Contracts

| # | Task | Size | Notes |
|---|---|---|---|
| B.1 | MerkleTree operations (insert, member proof) | L | Needs correct alignment for `PersistentHash` on Merkle leaves |
| B.2 | Map operations (get, set, contains) | M | Key encoding in transcript ops |
| B.3 | Cell with typed values (not just u64) | M | `AlignedValue` construction for different types |
| B.4 | Custom ADTs (`#[midnight(state_type)]`) | L | Enum/struct → `StateValue` encoding |
| B.5 | `for` loop unrolling (const bounds) | L | Detect `for i in 0..N`, unroll |
| B.6 | `match` on enums | L | Cascaded `CondSelect` |
| B.7 | Proof generation test for voting contract with witnesses | M | Validates conditional branch proving |

### Phase C: Deployment — **out of scope**

Deployment, transaction building, wallet handling, and node interaction are
**not** Nocturne's responsibility. Nocturne is an eDSL for *authoring*
Midnight contracts — it ends at producing artifacts (ZKIR, `.prover`,
`.verifier`, `contract-info.json`) that downstream tooling can consume.

On-chain compatibility of those artifacts is validated by going through the
canonical `midnight-ledger` code paths in
`crates/midnight/tests/ledger_integration_test.rs` — no real node needed.

Tools that deploy/call Nocturne-compiled contracts:

- [`midnight-rs`](https://github.com/RomarQ/midnight-rs) (Rust SDK)
- Compact's own TypeScript runtime
- Anything else that targets `midnight-ledger`'s `ContractDeploy` /
  `ContractCall` formats

### Phase C (new): Authoring depth

| # | Task | Size | Notes |
|---|---|---|---|
| C.1 | `Map<K, V>` ledger field | L | Key encoding in transcript ops, `get`/`set`/`contains`/`remove` |
| C.2 | `MerkleTree<DEPTH>` insert + membership proof | L | Needs correct alignment for `PersistentHash` on leaves |
| C.3 | `Cell<T>` for arbitrary `T` (not just `u64`/`bool`) | M | `AlignedValue` construction for user types |
| C.4 | Custom ADTs (`#[midnight(state_type)]`) | L | Enum/struct → `StateValue` encoding |
| C.5 | `for` loop unrolling (const bounds) | L | Detect `for i in 0..N`, unroll |
| C.6 | `match` on enums | L | Cascaded `CondSelect` |
| C.7 | `Bytes<N>` as witness (multi-Fr emission) | L | See `memories/witness-type-support.md` |

### Phase D: Advanced

| # | Task | Size |
|---|---|---|
| D.1 | ZKIR optimization (compactc-style value reuse to shrink VKs) | L |
| D.2 | ZKIR v3 support (symbolic names) | M |
| D.3 | Cross-contract calls (artifact emission only — no submission) | L |
| D.4 | Environment context (`block_height`, `caller`) accessible from circuit body | M |

---

## Architecture

```
midnight-edsl/
  crates/
    midnight/           Umbrella (re-exports runtime types)
    midnight-macro/     #[midnight::contract], #[midnight::test]
    midnight-ir/        Internal IR (parse + validate)
    midnight-codegen/   ZKIR emitter + transcript codegen + deploy codegen
    midnight-types/     Field, Boolean, Bytes<N>, Uint<N>
    midnight-storage/   Cell, Counter, Map, MerkleTree
    midnight-metadata/  contract-info.json
    midnight-env/       (stub) Environment context
    midnight-engine/    (stub) Test engine
    midnight-e2e/       (stub) E2E framework
    midnight-primitives/(stub) Field arithmetic
  tools/
    cargo-midnight/     Build/keygen/test CLI
  examples/
    counter-contract/   Example contract with tests
```

Dependencies on midnight-ledger (crates.io):
- `midnight-zkir` — IrSource, Instruction
- `midnight-transient-crypto` — Fr, ProofPreimage, Zkir trait, FieldRepr
- `midnight-base-crypto` — Alignment, AlignedValue, MidnightDataProvider
- `midnight-onchain-vm` — Op, Key, ResultModeVerify
- `midnight-onchain-state` — StateValue
