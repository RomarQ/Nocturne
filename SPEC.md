# SPEC.md -- midnight-edsl: A Rust eDSL for Midnight Smart Contracts

## 1. Vision and Goals

### 1.1 What is midnight-edsl?

midnight-edsl is a Rust eDSL for writing smart contracts targeting the Midnight network. Rust procedural macros transform annotated Rust code into the artifacts required for contract deployment and interaction on Midnight.

midnight-edsl is a **peer to Compact**. Both are frontends that produce the same outputs: ZKIR circuits for proof generation, contract metadata, and runtime logic for transcript construction. midnight-edsl replaces Compact's restricted frontend language with Rust's type system and metaprogramming, and replaces Compact's TypeScript runtime output with Rust runtime code.

### 1.2 How Midnight Contracts Work

A Midnight contract has three layers:

1. **ZKIR circuits** -- Plonk constraint systems (one per circuit function). Define the zero-knowledge proof: what is asserted, what is public, what is private. Compiled to prover/verifier keys by the `zkir` tool.

2. **Transcript programs** -- Sequences of stack-based VM operations (`Op`) that read/write contract state. Built at runtime when a user calls a circuit. The transcript is submitted on-chain as part of the transaction and re-executed by validators.

3. **Contract state** -- `StateValue` tree stored on-chain (Cell, Map, Array, BoundedMerkleTree). Updated atomically when a proof verifies.

**End-to-end flow:**

```
Developer writes contract
    ↓ (compile-time)
ZKIR files + contract-info.json + runtime Rust code
    ↓ (keygen)
Prover/verifier keys (via `zkir compile`)
    ↓ (deploy)
ContractState stored on-chain with verifier keys per entry point
    ↓ (call)
Client builds ProofPreimage:
  - Collects witness values (private)
  - Executes circuit logic off-chain
  - Builds transcript (VM ops for state transitions)
  - Generates ZK proof using prover key
    ↓ (submit)
ContractCall transaction: address + entry_point + transcripts + proof
    ↓ (verify on-chain)
  1. Compute public_inputs = binding_input + comm_commitment + field_repr(transcript ops)
  2. Verify proof against stored verifier key + public_inputs
  3. Re-execute transcript VM program to validate effects
  4. Apply state changes
```

### 1.3 What Compact Produces (Reference)

The Compact compiler outputs:
- `zkir/<circuit>.zkir` -- ZKIR v2 JSON per circuit (IrSource format)
- `compiler/contract-info.json` -- metadata (circuit signatures, witness declarations, types)
- `contract/index.js` + `.d.ts` -- TypeScript runtime that builds transcripts and calls the prover

midnight-edsl replaces all three:
- ZKIR files -- generated from annotated Rust via proc macros
- contract-info.json -- generated from the contract IR
- Rust runtime module -- generated instead of TypeScript, providing typed transcript building and proof generation

### 1.4 Design Principles

1. **Privacy as a first-class concern.** The dual public/private state model is structural: `#[midnight(ledger)]` for public state, `#[midnight(witnesses)]` for private state.

2. **Rust-native.** Developers write valid Rust. Standard tooling works. No TypeScript, no Scheme, no external compiler.

3. **Correct ZKIR generation.** The emitted ZKIR must produce valid Plonk proofs. We use midnight-ledger's own `IrSource` and `Instruction` types directly to guarantee format compatibility.

4. **ZK-awareness without ZK expertise.** The type system rejects non-ZK-compatible patterns at compile time.

### 1.5 Ecosystem Dependencies

- **midnight-ledger** (crates.io) -- The only runtime dependency. Provides:
  - `midnight-zkir`: `IrSource`, `Instruction` types for ZKIR construction
  - `midnight-transient-crypto`: `Fr` field type, hashing primitives
  - `midnight-base-crypto`: `Alignment` types for `PersistentHash`
  - `midnight-onchain-state`: `StateValue` for contract state representation
  - `midnight-onchain-vm`: `Op` types for transcript VM operations

- **midnight-rs** (reference) -- Rust SDK being developed in parallel. Its interpreter executes a higher-level Circuit IR format. midnight-edsl can optionally emit Circuit IR for midnight-rs integration, but this is not the primary output.

### 1.6 Non-Goals

- Compact source code compatibility.
- TypeScript/JavaScript output.
- IDE visual tools.

---

## 2. Developer Experience

### 2.1 Example: Counter Contract

```rust
#[midnight::contract]
mod counter {
    use midnight::types::*;

    #[midnight(ledger)]
    pub struct CounterState {
        count: Counter,
    }

    impl CounterState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self { count: Counter::zero() }
        }

        #[midnight(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }

        #[midnight(query)]
        pub fn get_count(&self) -> u64 {
            self.count.value()
        }
    }
}
```

### 2.2 Example: Private Voting Contract

```rust
#[midnight::contract]
mod ballot {
    use midnight::types::*;

    #[midnight(ledger)]
    pub struct Ballot {
        votes_for: Counter,
        votes_against: Counter,
        voters: MerkleTree<32>,
    }

    #[midnight(witnesses)]
    pub struct BallotWitnesses {
        pub voter_secret: Field,
        pub vote_choice: Boolean,
    }

    impl Ballot {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                votes_for: Counter::zero(),
                votes_against: Counter::zero(),
                voters: MerkleTree::empty(),
            }
        }

        #[midnight(circuit)]
        pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
            let commitment = persistent_hash(&witnesses.voter_secret);
            assert_member(&self.voters, &commitment);
            if witnesses.vote_choice.into() {
                self.votes_for.increment();
            } else {
                self.votes_against.increment();
            }
        }

        #[midnight(circuit)]
        pub fn register_voter(&mut self, commitment: Bytes<32>) {
            self.voters.insert(&commitment);
        }

        #[midnight(query)]
        pub fn get_tally(&self) -> (u64, u64) {
            (self.votes_for.value(), self.votes_against.value())
        }
    }
}
```

---

## 3. Macro System

### 3.1 Attributes

| Attribute | Applies To | Description |
|---|---|---|
| `#[midnight::contract]` | `mod` | Marks a module as a contract |
| `#[midnight(ledger)]` | `struct` | Public on-chain state |
| `#[midnight(witnesses)]` | `struct` | Private off-chain state |
| `#[midnight(circuit)]` | `fn` in impl | Transition function (generates proof) |
| `#[midnight(constructor)]` | `fn` in impl | Contract deployment initializer |
| `#[midnight(query)]` | `fn` in impl | Read-only view (no proof) |
| `#[midnight(state_type)]` | `struct`/`enum` | Custom ADT for ledger/circuits |

### 3.2 Validation Rules

1. Exactly one `#[midnight(ledger)]` struct.
2. At most one `#[midnight(witnesses)]` struct.
3. At least one `#[midnight(circuit)]` or `#[midnight(constructor)]`.
4. Witness parameters must use the declared witnesses struct.
5. Ledger fields must use `midnight::types` types.
6. Witness fields must be ZK-representable.
7. Queries take `&self` only.
8. Constructors return `Self`.

---

## 4. Type System

### 4.1 Primitive Types

| Rust Type | ZKIR | Notes |
|---|---|---|
| `Boolean` | `ConstrainToBoolean` | Field element 0 or 1 |
| `Field` | Native `Fr` | BLS12-381 scalar |
| `Bytes<N>` | `Alignment::Bytes(N)` | Fixed-size byte array |
| `Uint<N>` | `ConstrainBits(N)` | N-bit unsigned integer |

### 4.2 Ledger Types

| Rust Type | `StateValue` | VM Ops |
|---|---|---|
| `Cell<T>` | `Cell(AlignedValue)` | `Idx`, `Ins` |
| `Counter` | `Cell(AlignedValue)` | `Idx`, `Addi`, `Ins` |
| `Map<K, V>` | `Map(HashMap)` | `Idx`, `Ins`, `Member` |
| `MerkleTree<D>` | `BoundedMerkleTree` | `Root`, `Ins`, `Idx` |
| `Array<T, N>` | `Array(Vec)` | `Idx`, `Ins` |

### 4.3 Constraints

- No heap allocation, floating point, dynamic dispatch.
- All types fixed-size at compile time.
- Arithmetic on `Field`/`Uint<N>` maps to ZKIR `Add`/`Mul`/`Neg`.

---

## 5. Compilation Pipeline

### 5.1 Compile-Time (Proc Macro)

The `#[midnight::contract]` macro:

1. **Parses** the module into internal IR (`ContractIR`, `LedgerIR`, `WitnessIR`, `CircuitIR`, `ExprIR`).
2. **Validates** against Section 3.2 rules.
3. **Generates ZKIR** -- one `IrSource` per circuit function, serialized to `.zkir` JSON.
4. **Generates contract-info.json** -- metadata matching Compact's schema.
5. **Generates Rust runtime module** -- typed functions for building transcripts and `ProofPreimage`s.
6. **Emits test-mode code** -- strips midnight attributes, provides test-mode types for `cargo test`.

### 5.2 Artifacts

```
target/midnight/<contract>/
  zkir/
    <circuit>.zkir              # ZKIR v2 JSON (IrSource)
  compiler/
    contract-info.json          # Metadata (same schema as Compact)
```

After `cargo midnight keygen`:
```
  keys/
    <circuit>.prover            # Plonk prover key
    <circuit>.verifier          # Plonk verifier key
```

### 5.3 ZKIR Generation

Each `#[midnight(circuit)]` function compiles to an `IrSource`:

```rust
IrSource {
    num_inputs: u32,                    // Field elements from circuit arguments
    do_communications_commitment: bool, // Whether outputs are committed
    instructions: Vec<Instruction>,     // Constraint system
}
```

**Instruction mapping:**

| Rust | ZKIR Instruction | Outputs |
|---|---|---|
| `a + b` | `Add { a, b }` | 1 (sum) |
| `a * b` | `Mul { a, b }` | 1 (product) |
| `-a` | `Neg { a }` | 1 (negation) |
| `!a` | `Not { a }` | 1 (boolean negation) |
| `a == b` | `TestEq { a, b }` | 1 (boolean) |
| `a < b` | `LessThan { a, b, bits }` | 1 (boolean) |
| `assert!(c)` | `Assert { cond }` | 0 |
| `assert_eq!(a, b)` | `ConstrainEq { a, b }` | 0 |
| `if c { a } else { b }` | `CondSelect { bit, a, b }` | 1 (selected) |
| `42u64` | `LoadImm { imm: Fr }` | 1 (constant) |
| `witnesses.field` | `PrivateInput { guard }` | 1 (witness value) |
| Public argument | `PublicInput { guard }` | 1 (public value) |
| `persistent_hash(&x)` | `PersistentHash { alignment, inputs }` | 1 (hash) |
| `transient_hash(&x)` | `TransientHash { inputs }` | 1 (hash) |
| `midnight::disclose(v)` | `DeclarePubInput { var }` + `PiSkip` | 0 |
| `Uint<N>` constraint | `ConstrainBits { var, bits: N }` | 0 |
| `Boolean` constraint | `ConstrainToBoolean { var }` | 0 |
| Circuit output | `Output { var }` | 0 (adds to comm. commitment) |

### 5.4 ZKIR Memory Model

Linear memory indexed by `u32`. Starts with `num_inputs` pre-allocated slots. Each instruction that produces output(s) appends to memory.

```
Index 0: [input 0]
Index 1: [input 1]
Index 2: LoadImm { imm: 1 }        // memory[2] = 1
Index 3: Add { a: 0, b: 2 }        // memory[3] = input_0 + 1
...
```

### 5.5 Transcript Construction (Runtime)

At call time, the generated Rust runtime code:

1. Collects witness values from the caller.
2. Reads current ledger state.
3. Builds a transcript `Vec<Op>` encoding the state transition:
   - `Idx { path }` to navigate state
   - `Addi { immediate }` for counter increments
   - `Ins { n }` to write values back
   - `Dup`, `Popeq` for reads
   - `Branch`/`Jmp` for conditionals
4. Collects public/private transcript vectors for the `ProofPreimage`.
5. Computes `communication_commitment = transient_commit(inputs ++ outputs, randomness)`.
6. Calls `IrSource::prove()` with the `ProofPreimage` and prover key.
7. Assembles `ContractCall` transaction.

### 5.6 contract-info.json

Matches Compact's schema:

```json
{
  "compiler-version": "midnight-edsl 0.1.0",
  "language-version": "1.0",
  "runtime-version": "1.0",
  "circuits": [
    {
      "name": "increment",
      "pure": false,
      "proof": true,
      "arguments": [],
      "result-type": { "type-name": "Tuple", "types": [] }
    }
  ],
  "witnesses": [
    {
      "name": "voter_secret",
      "arguments": [],
      "result type": { "type-name": "Field" }
    }
  ]
}
```

---

## 6. Privacy Model

### 6.1 Two Worlds

- **Ledger** (`#[midnight(ledger)]`): on-chain, public, updated via verified transcripts.
- **Witnesses** (`#[midnight(witnesses)]`): off-chain, private, consumed during proof generation via `PrivateInput` ZKIR instructions.

### 6.2 Proving Flow

1. Witness values enter the ZKIR circuit via `PrivateInput` -- they are part of the `ProofPreimage.private_transcript` and never appear on-chain.
2. Public values enter via `PublicInput` -- they come from `ProofPreimage.public_transcript_outputs` and are included in the on-chain transcript.
3. `Assert`/`ConstrainEq` enforce relationships between public and private values without revealing the private ones.
4. `Output` instructions contribute to the communications commitment, binding circuit outputs to the proof.

### 6.3 Selective Disclosure

`midnight::disclose(value)` emits `DeclarePubInput` + `PiSkip`, making a computed value part of the public inputs that validators can see.

### 6.4 Hashing

- `persistent_hash(&x)` -- `PersistentHash { alignment, inputs }`. Deterministic, used for Merkle tree leaves and commitments. Requires `Alignment` metadata.
- `transient_hash(&x)` -- `TransientHash { inputs }`. Circuit-local, used within a single proof.

---

## 7. Crate Architecture

```
midnight-edsl/
  crates/
    midnight/              # Umbrella (re-exports)
    midnight-macro/        # #[midnight::contract], #[midnight::test]
    midnight-ir/           # Internal IR (parse + validate)
    midnight-codegen/      # ZKIR emitter, transcript builder codegen, metadata
    midnight-types/        # Field, Boolean, Bytes<N>, Uint<N>
    midnight-storage/      # Cell, Counter, Map, MerkleTree
    midnight-env/          # Environment context (block height, caller)
    midnight-metadata/     # contract-info.json generation
    midnight-engine/       # Off-chain test engine
    midnight-e2e/          # E2E tests against Midnight node
    midnight-primitives/   # Field arithmetic, hashing (wraps transient-crypto)
  tools/
    cargo-midnight/        # Build/keygen/deploy CLI
```

### 7.1 Key Crate: midnight-codegen

- `zkir_emitter` -- Builds `midnight_zkir::IrSource` per circuit. Uses midnight-ledger types directly.
- `transcript_codegen` -- Generates Rust code for runtime transcript construction (replaces Compact's TypeScript output).
- `codegen` -- Orchestrates all emitters.

### 7.2 Dependencies on midnight-ledger

```
midnight-codegen → midnight-zkir (IrSource, Instruction)
midnight-codegen → midnight-transient-crypto (Fr)
midnight-codegen → midnight-base-crypto (Alignment)
midnight-primitives → midnight-transient-crypto (field arithmetic, hashing)
```

---

## 8. Testing

### 8.1 Test Mode

`#[midnight::test]` provides a simulated environment. The macro strips midnight attributes and passes the module through so `cargo test` works with test-mode types (real Rust values, no proof generation).

### 8.2 Future: ZKIR Validation

Test helpers that load generated `.zkir` files and run `IrSource::check()` to verify circuit satisfiability with test witness values.

---

## 9. Error Handling

Compile-time errors with source spans and categorized codes:

- `MIDNIGHT-0xx`: Type violations (non-ZK type in circuit)
- `MIDNIGHT-1xx`: Structure violations (missing ledger, duplicate witnesses)
- `MIDNIGHT-2xx`: Privacy violations (witness type mismatch)
- `MIDNIGHT-3xx`: Circuit violations (unsupported loop, recursion)

---

## 10. Control Flow Restrictions

- **`if/else`**: Allowed. Both branches evaluated (ZK semantics). `CondSelect` in ZKIR.
- **`for` loops**: Only with compile-time constant bounds. Unrolled.
- **`while`/`loop`**: Not allowed.
- **`match`**: Allowed on ADT enums. Cascaded `CondSelect`.
- **Recursion**: Not allowed.
- **Function calls**: Inlined at ZKIR level.

---

## 11. Future Considerations

- Circuit optimization (constant propagation, dead constraint elimination)
- Cross-contract calls (communications commitment)
- ZKIR v3 support (symbolic variable names)
- Circuit IR emission for midnight-rs interpreter integration
- Formal verification
