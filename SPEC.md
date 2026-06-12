# Nocturne language and compiler reference

Reference manual for the `#[nocturne::contract]` eDSL: contract structure, type system, expression-to-ZKIR mapping, compilation pipeline, privacy model, and the `contract-info.json` schema. For the build workflow see [`docs/compiling.md`](docs/compiling.md); for per-artifact details see [`docs/artifacts.md`](docs/artifacts.md).

## 1. Background: how Midnight contracts work

A Midnight contract has three layers:

1. **ZKIR circuits**: Plonk constraint systems, one per circuit function. They define the zero-knowledge proof: what is asserted, what is public, what is private. Compiled to prover/verifier keys.
2. **Transcript programs**: sequences of stack-based VM operations (`Op`) that read/write contract state. Built at runtime when a user calls a circuit, submitted on-chain as part of the transaction, and re-executed by validators.
3. **Contract state**: a `StateValue` tree stored on-chain (Cell, Map, Array, BoundedMerkleTree). Updated atomically when a proof verifies.

On verification, the ledger computes the public inputs as `binding_input + communication_commitment + field_repr(transcript ops)`, verifies the proof against the stored verifier key, re-executes the transcript VM program, and applies the state changes.

Nocturne emits all three layers from one Rust module. The minimal contract:

```rust
use nocturne::types::*;

#[nocturne::contract]
pub mod counter {
    use super::*;

    #[nocturne(ledger)]
    pub struct CounterState {
        pub count: Counter,
    }

    impl CounterState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self { count: Counter::zero() }
        }

        #[nocturne(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }
    }
}
```

## 2. Contract structure

### 2.1 Attributes

| Attribute | Applies to | Description |
|---|---|---|
| `#[nocturne::contract]` | `mod` | Marks a module as a contract |
| `#[nocturne(ledger)]` | `struct` | Public on-chain state |
| `#[nocturne(witnesses)]` | `struct` | Private off-chain state (fields and parametric methods) |
| `#[nocturne(circuit)]` | `fn` in impl | Transition function (generates proof) |
| `#[nocturne(constructor)]` | `fn` in impl | Contract deployment initializer |
| `#[nocturne(query)]` | `fn` in impl | Read-only view (plain Rust, no proof, never on-chain) |
| `#[nocturne(private)]` | ledger field | Sets `exported: false` in `contract-info.json` (the field still lives on-chain; all ledger state is public on Midnight) |

Plain `pub struct` / `pub enum` declarations inside the module are picked up as user types. Free `fn` items are helpers: they are inlined into any circuit that calls them, mirroring compactc's no-annotation lowering rule.

### 2.2 Validation rules

The macro rejects the module at compile time unless:

1. Exactly one `#[nocturne(ledger)]` struct is declared.
2. At most one `#[nocturne(witnesses)]` struct is declared.
3. At least one `#[nocturne(circuit)]` or `#[nocturne(constructor)]` exists.
4. Witness parameters use the declared witnesses struct.
5. Ledger fields use `nocturne::types` types.
6. Witness fields are ZK-representable.
7. Queries take `&self` only.
8. Constructors return `Self` or the ledger struct name.

### 2.3 Error codes

Violations produce compile errors with source spans and categorized codes (see `crates/nocturne-ir/src/error.rs`):

- `MIDNIGHT-0xx`: type system violations (invalid type, non-ZK type in circuit)
- `MIDNIGHT-1xx`: contract structure violations (missing ledger, duplicate witnesses, invalid constructor return, mutable query)
- `MIDNIGHT-2xx`: privacy model violations (witness type mismatch)
- `MIDNIGHT-3xx`: circuit constraint violations (unsupported expression, unbounded loop, recursion)

### 2.4 Control flow restrictions

- `if`/`else`: allowed, as statement or expression. Both branches are evaluated (ZK semantics); expression form lowers to `CondSelect`.
- `match`: allowed on user enums and `Option`, with payload binding. Lowers to guard-multiplexed branches.
- `for` loops: only with compile-time constant bounds; unrolled at parse time.
- `while` / `loop`: not allowed.
- Recursion: not allowed (including through helpers; the helper call graph must be acyclic).
- Function calls: helper `fn`s in the contract module are inlined at the IR level.

## 3. Type system

### 3.1 Primitive types

| Rust type | ZKIR constraint | Notes |
|---|---|---|
| `Boolean` | `ConstrainToBoolean` | Field element 0 or 1 |
| `Field` | native `Fr` | BLS12-381 scalar; the Rust-side value is the low 128 bits |
| `Uint<N>`, N ≤ 128 | `ConstrainBits(N)` | N-bit unsigned integer |
| `Bytes<N>` | per-chunk `ConstrainBits` | Fixed-size byte array, chunked into ceil(N/31) Frs when N > 31 |

Composite value types (`Option<T>`, `[T; N]` for N ≤ 11, tuples up to arity 11, user structs, homogeneous-payload enums) and their wire shapes are tabulated in [`docs/compiling.md`](docs/compiling.md).

### 3.2 Ledger types

| Rust type | `StateValue` | VM ops |
|---|---|---|
| `Cell<T>` | `Cell(AlignedValue)` | `Idx`, `Ins`, `Popeq` |
| `Counter` | `Cell(AlignedValue)` | `Idx`, `Addi`, `Ins` |
| `Map<K, V>` | `Map(HashMap)` | `Idx`, `Ins`, `Member`, `Rem` |
| `Set<T>` | `Map(HashMap)` with `Null` values | `Idx`, `Ins`, `Member`, `Rem` |
| `MerkleTree<HEIGHT, T>` | `Array [BoundedMerkleTree, Cell<u64>]` | `Root`, `Eq`, `Ins`, `Idx`, `Dup`, `Addi` |

### 3.3 Constraints

- No heap allocation, floating point, or dynamic dispatch in circuit bodies.
- All types are fixed-size at compile time.
- In-circuit `Uint<N>` arithmetic is field arithmetic: `+`/`-`/`*` do not wrap and are not overflow-checked in the circuit. The off-chain `Uint` type panics on overflow/underflow so test mode surfaces the divergence instead of masking it.

## 4. Expression-to-ZKIR mapping

Each `#[nocturne(circuit)]` function compiles to a `midnight_zkir::IrSource`:

```rust
IrSource {
    num_inputs: u32,                    // field elements from circuit arguments
    do_communications_commitment: bool, // always true (see §6.2)
    instructions: Vec<Instruction>,
}
```

### 4.1 Instruction mapping

| Rust | ZKIR instruction(s) |
|---|---|
| `a + b` | `Add` |
| `a - b` | `Neg` + `Add` |
| `a * b` | `Mul` |
| `-a` | `Neg` |
| `!a` | `Not` |
| `a == b` | `TestEq` |
| `a != b` | `TestEq` + `Not` |
| `a < b` | `LessThan { bits }` (bits from the operand type) |
| `a > b` | `LessThan` with operands swapped |
| `a <= b` / `a >= b` | swapped/plain `LessThan` + `Not` |
| `a && b` | `Mul` |
| `a \|\| b` | `a + b - a*b` (`Mul`, `Add`, `Neg`, `Add`) |
| `assert!(c)` | `Assert` |
| `assert_eq!(a, b)` | `ConstrainEq` |
| `if c { a } else { b }` (expression) | `CondSelect` |
| literal (`42u64`) | `LoadImm` |
| `witnesses.field`, `witnesses.method(args)` | `PrivateInput` (one per Fr of the value's layout) |
| public circuit argument | `PublicInput` |
| `persistent_hash(&x)` | `PersistentHash { alignment, inputs }` |
| `transient_hash(&x)` | `TransientHash` |
| `nocturne::disclose(v)` | none (marker; the value's wire passes through) |
| `Uint<N>` constraint | `ConstrainBits { bits: N }` |
| `Boolean` constraint | `ConstrainToBoolean` |
| circuit output | `Output` (adds to the communications commitment) |
| ledger method call | op-specific `DeclarePubInput` sequence + `PiSkip` (mirrors the transcript op's `field_repr`) |

### 4.2 Memory model

ZKIR uses linear memory indexed by `u32`. It starts with `num_inputs` pre-allocated slots; each instruction that produces output(s) appends to memory.

```
Index 0: [input 0]
Index 1: [input 1]
Index 2: LoadImm { imm: 1 }        // memory[2] = 1
Index 3: Add { a: 0, b: 2 }        // memory[3] = input_0 + 1
```

### 4.3 Conditional branches

Inside a conditional branch, every value fed to `DeclarePubInput` is routed through `cond_select(branch_guard, value, ZERO)` first, and `PrivateInput`/`PublicInput` carry the branch guard. The on-chain ledger replaces inactive transcript segments with `Op::Noop { n }`, which contributes `n` zero field elements to the verifier's public inputs, so the circuit's inactive-branch slots must be zero or verification fails. Nested guards compose via `cond_select` (logical AND of the guard chain).

## 5. Compilation pipeline

### 5.1 Compile time (proc macro)

The `#[nocturne::contract]` macro:

1. **Parses** the module into internal IR (`ContractIR`, `LedgerIR`, `WitnessIR`, `CircuitIR`, `ExprIR`).
2. **Validates** against the rules in §2.2.
3. **Emits ZKIR**: one `IrSource` per circuit function, serialized to `zkir/<circuit>.zkir` (JSON, ZKIR v2).
4. **Emits `compiler/contract-info.json`**: the contract's external surface (§7).
5. **Injects runtime Rust**: `transcript` and `deploy` submodules into the user's module (typed functions for building the on-chain transcript and the initial `StateValue`).
6. **Strips its own attributes** so the module compiles as plain Rust and circuit methods are directly callable from tests.

The ZKIR emitter and the transcript codegen are two backends over the same `ExprIR`. The order of private inputs is derived from a single shared walk (`nocturne-codegen`'s private-event walk), which keeps the circuit's `PrivateInput` allocation and the builder's `private_transcript` pushes in lockstep by construction.

### 5.2 Artifact layout

```
target/nocturne/<crate>/<contract>/
  zkir/<circuit>.zkir               # ZKIR v2 JSON (IrSource), one per circuit
  compiler/contract-info.json       # contract surface metadata
  keys/<circuit>.prover             # after `cargo nocturne keygen`
  keys/<circuit>.verifier
```

`<crate>` is the `CARGO_CRATE_NAME` the macro expanded in; keying by crate and contract keeps equally named contract modules in different crates from clobbering each other. See [`docs/artifacts.md`](docs/artifacts.md) for the per-artifact reference.

### 5.3 Transcript construction (runtime)

At call time, the generated `transcript::build_<circuit>_transcript(...)` function:

1. Collects witness values from the caller (the function takes `&Witnesses` if the circuit touches witnesses, `&State` if it reads ledger state).
2. Builds the transcript `Vec<Op>` encoding the state transition (`Idx` to navigate, `Push`/`Ins`/`Addi` to write, `Dup`/`Popeq` for reads, plus type-specific ops like `Member`, `Rem`, `Root`, `Eq`). Conditionals compile to a Rust `if` in the builder, so only the active branch's ops are emitted; the ledger pads inactive segments with `Noop` when computing public inputs.
3. Returns the ops plus the private-input Frs in the same order the circuit's `PrivateInput`s were allocated.

Proving, `ProofPreimage` assembly, and transaction construction are downstream concerns (midnight-rs or equivalent).

## 6. Privacy model

### 6.1 Two worlds

- **Ledger** (`#[nocturne(ledger)]`): on-chain, public, updated via verified transcripts.
- **Witnesses** (`#[nocturne(witnesses)]`): off-chain, private, consumed during proof generation via `PrivateInput` instructions. Witness values are part of the proof's private transcript and never appear on-chain.

`Assert`/`ConstrainEq` enforce relationships between public and private values without revealing the private ones. `Output` instructions bind circuit outputs to the proof via the communications commitment.

### 6.2 Communications commitment

Every emitted circuit sets `do_communications_commitment: true`. The on-chain verify path (`midnight-ledger` ledger-8, `ledger/src/verify.rs`, `ContractCall::public_inputs`) unconditionally feeds the communication commitment as the second public input, so a circuit built without the commitment slot fails verification with a public-input count mismatch.

### 6.3 Witness determinism contract

Witness methods (parametric witnesses like `witnesses.derive(x)`) must be deterministic. The generated builder may invoke a method more than once for the same call site (once for the private transcript entry, once where the value feeds an op); a method returning different values per invocation desyncs the private transcript from the ops and fails at prove time.

### 6.4 Selective disclosure

`nocturne::disclose(value)` is a marker, not an emission: the value's wire passes through unchanged, and the value becomes publicly visible through the transcript operation that consumes it (a ledger write, a circuit output). Disclosure-analysis enforcement (rejecting undisclosed witness flows into public positions, as compactc does) is **not yet implemented**.

### 6.5 Hashing

- `persistent_hash(&x)`: `PersistentHash { alignment, inputs }`. Deterministic across proofs, used for Merkle tree leaves and commitments. Requires `Alignment` metadata.
- `transient_hash(&x)`: `TransientHash { inputs }`. Circuit-local, used within a single proof.

## 7. contract-info.json

One file per contract. The schema matches compactc's `contract-info.json`, so downstream type generators, indexers, and deploy scripts consume either compiler's output:

```json
{
  "compiler-version": "nocturne 0.1.0",
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
      "name": "private$voter_secret",
      "arguments": [],
      "result-type": { "type-name": "Field" }
    }
  ],
  "ledger": [
    {
      "name": "count",
      "index": 0,
      "exported": true,
      "type": { "type-name": "Counter" }
    }
  ],
  "contracts": []
}
```

- `circuits[]`: one entry per `#[nocturne(circuit)]`. `pure` is `false` for state-mutating circuits (`&mut self`), `true` for read-only ones.
- `witnesses[]`: declared witness fields and parametric witness methods, named with a `private$` prefix.
- `ledger[]`: one entry per ledger struct field in declaration order. `index` is the on-chain slot index; `exported` is `false` for fields marked `#[nocturne(private)]`.
- `contracts[]`: reserved for cross-contract call metadata (**not yet implemented**).

## 8. Testing

`#[nocturne::test]` is currently equivalent to `#[test]`; it is reserved for future environment setup (e.g. wiring up a simulated ledger before the test body runs). Because the macro strips its own attributes, circuit methods are plain Rust functions callable directly from tests, and the injected `transcript::build_*` builders can be asserted on without going through prove/verify. On-chain compatibility itself is gated by the integration tests in `crates/nocturne/tests/`, which drive the emitted artifacts through `midnight-ledger`'s canonical prove/verify path.
