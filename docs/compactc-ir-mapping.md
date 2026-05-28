# Compactc IR vs Nocturne ExprIR

Comparison built from compactc's compiled IR for the gateway contract, dumped into `contract-info.json` by [the contract-info-extensions branch](https://github.com/RomarQ/compact/tree/feat/contract-info-extensions). Goal: see what compactc's internal representation looks like at the same layer as our [`ExprIR`](../crates/nocturne-ir/src/expr.rs), and figure out where we have gaps, where we have an advantage, and where we're carrying weight we don't need.

This complements [`compactc-vs-nocturne.md`](compactc-vs-nocturne.md), which is the higher-level "what's the same / different" overview. This document focuses on the IR layer specifically.

## Compactc IR shape

The branch above adds an `ir.body` field to each `circuits[]` entry and a `result` field to each `helpers[]` entry. The tree is a single recursive shape:

```json
{ "op": "<tag>", ...op-specific fields }
```

The full set of `op` tags found in the gateway dump:

- **Source-level expressions**: `lit`, `var`, `field`, `index`, `vector-index`, `tuple`, `new`, `cast`, `default`, `let-expr` (+ `let`), `if-expr`, `seq` (+ `expr-stmt`), `call-pure`, `call-witness`, `assert`
- **Arithmetic / comparison**: `add`, `addi`, `neg`, `eq`, `neq`, `ge`, `gt`, `le`
- **Ledger access**: `ledger-query` (wraps the on-chain op sequence)
- **On-chain VM ops embedded inline**: `dup`, `swap`, `branch`, `idx`, `ins`, `push`, `popeq`, `member`

The on-chain ops appear inside the IR tree (typically inside `ledger-query.ops`). That's the headline structural choice: **compactc's IR is a hybrid AST + lowered bytecode.** Our `ExprIR` is a pure AST and emits the on-chain ops at lowering time.

The contract-info.json also carries `ledger[]` (storage fields with `index`, `exported`, `storage` slot type), `structs[]` (catalog of user-defined struct types), `helpers[]` (pure helper functions, 23 of them in gateway), `witnesses[]`, and `contracts[]`.

## Op-level mapping

| Compactc op | Our ExprIR | Notes |
|---|---|---|
| `lit` | `Literal` | ✓ Equivalent. |
| `var` | `Var` | ✓ Equivalent. |
| `field` | (no direct equivalent) | Compactc has a generic struct-field access op. We split it: `self.x` → `LedgerAccess`, `witnesses.x` → `WitnessAccess`, `s.x` on user-struct values is handled in codegen via tuple projection (no IR node). **Latent gap** if we ever need nested struct access. |
| `index` | `Index` | ✓ |
| `vector-index` | `Index` | Compactc distinguishes typed Vector indexing from raw array indexing. We unify; saves a node type. |
| `tuple` | `Tuple` | ✓ |
| `new` | `StructInit` | Compactc's `new` is a constructor; our struct literal does the same thing. |
| `cast` | (transparent in IR) | We drop casts at parse time per the `as cast is transparent IR passthrough` design (see `memories/scope-blockers.md`). |
| `default` | (synthesized at codegen) | Compactc has a `default` op; we generate `<T as Default>::default()` from codegen for the Option `None` payload synthesis. |
| `let-expr` + `let` | `Let` | ✓ Compactc nests a body inside the let; we use a Block. |
| `if-expr` | `If` | ✓ Both expression-valued (since our recent if-as-expression commit). |
| `seq` + `expr-stmt` | `Block` | We don't wrap statements explicitly. |
| `call-pure` | `FnCall { path, args }` | ✓ We carry the full `syn::Path` (since the path-preserving fix); compactc carries only `name`. |
| `call-witness` | `WitnessAccess { field }` | **Different model.** Compactc: parametric witness calls (`ownPublicKey()`, `createZswapOutput(args...)`). We: witnesses are struct fields with no arguments. **Real gap** for parametric witnesses. |
| `ledger-query` | `LedgerAccess { field, method, args }` | Both wrap state access. Compactc emits the on-chain `dup`/`idx`/`push`/`popeq` ops inline inside the IR; we emit a method call and lower to ops at codegen time. |
| `assert` | `Assert` | ✓ |
| `add`/`eq`/`ge`/`gt`/`le`/`neq` | `BinaryOp { op: …, lhs, rhs }` | We unify under one node. |
| `neg` | `UnaryOp { op: Neg, expr }` | ✓ |
| `addi` | (handled at lowering for `Counter::increment_by(N)`) | Compactc has the addi opcode as a first-class IR node. |
| `dup` / `swap` / `branch` / `idx` / `ins` / `push` / `popeq` / `member` | (emitted at lowering, not in IR) | These are on-chain VM ops; we don't carry them in the AST. |

Things in our IR that compactc has no equivalent for:

- `EnumPayload { scrutinee, enum_name }` — synthetic node for match-arm payload binding. Compactc doesn't have true algebraic enums (it models tagged unions via structs), so it has no equivalent.
- `ArrayLit { elements }` — explicit array-literal node. Compactc reaches array values through `vector-index` reads and `tuple` literals.
- `Disclose { value }` — dedicated node for `disclose(_)`. Compactc routes through `call-pure`.
- `Reference { expr }` — Rust `&expr`; transparently forwarded. No analog needed in compactc.
- `Return { value }` — circuit return. Compactc circuits in this dump are all `()`-returning; no equivalent visible.
- `Path { path }` — multi-segment paths like `Status::Open` or `Self::CONST`. Compactc uses `var` for everything.

## Architectural difference

The biggest design difference is what's IN the IR.

| | Compactc | Nocturne |
|---|---|---|
| Source-level AST nodes | Yes | Yes |
| On-chain VM ops embedded inline | Yes (under `ledger-query` and elsewhere) | No |
| Implication for backends | Tightly coupled to the on-chain VM bytecode. Adding a backend means rewriting the lowered ops. | Backends lower the AST independently; the on-chain ops are computed per backend. |
| Implication for serialisation | The IR can drive a transcript builder directly (the ops are already there). | We have to re-derive ops at codegen; serialising the AST alone isn't sufficient to recreate the on-chain transcript. |
| Implication for retargeting | A TypeScript or other backend needs to ignore the inlined ops and re-derive them, or replicate compactc's lowering. | A TypeScript or other backend slots in alongside the existing Rust emitter, walking the same AST. |

Neither approach is strictly better. Compactc's approach makes the IR a fuller snapshot of the build output (you can ship the IR and a runtime ingests it). Ours keeps the IR loose, which is easier to retarget and easier to optimise — the lowering pass can choose different op sequences for different scenarios without rewriting the IR.

## What we're missing

Cases where compactc's IR captures something we don't:

1. **Parametric witnesses.** Compactc's `call-witness` takes arguments: `ownPublicKey()` (no args), `createZswapOutput(amount, salt, …)` (with args). Our `WitnessAccess` is a field read with no arguments. Contracts that need parameterised witnesses (which gateway uses) can't be expressed today. **Real gap.**

2. **User-struct field access on values.** Compactc's `field` op works on any expression. Ours handles `self.x` and `witnesses.x` as dedicated arms; user-struct `.x` access is handled in codegen helpers (e.g., `aligned_value_arg_expr`'s user-struct-fields arm projects through `__t.field_name`). We have no AST node for `(some_expr).field` on a user-struct-typed value. Works in the common cases but is a latent miscompile risk for nested access patterns.

3. **Helper functions catalog.** Compactc emits `helpers[]` separately from circuits — 23 entries in gateway (chain constants, signature verification, range checks). We have no equivalent. Users can write `fn` items in their contract module, but the proc macro doesn't see them and they can't currently be called from circuit IR (only inlined). **Real gap** for non-trivial contracts.

4. **`exported` markers on ledger fields.** Compactc tags each ledger field with `exported: true|false`. Downstream tools (indexers, off-chain readers) use this to discover what's publicly queryable. We don't model this.

5. **`Opaque` types with TS-side names.** Compactc declares `Opaque<JubjubPoint, tsType: "JubjubPoint">` for types whose representation is owned by the host runtime. We have no equivalent — everything has to be a recognised wire type today.

6. **`Alias` type wrappers.** Compactc has `type-name: "Alias"` for named type aliases. We rely on Rust `type` aliases, which the macro doesn't track in the IR.

7. **Field-index tracking on ledger fields.** Compactc records `index: 0..N` explicitly. We use declaration order implicitly (same information, but not first-class).

## What we don't need

Compactc carries some things ours doesn't have to:

1. **Inline on-chain VM ops.** Their `ledger-query.ops`, `dup`, `branch`, `push`, etc. live inside the AST. Ours lowers to these at codegen. We pay nothing for what we don't carry.

2. **`expr-stmt` wrapping.** Compactc explicitly wraps expressions used as statements. Our `Block { stmts: Vec<ExprIR> }` carries any expression directly.

3. **Separate `vector-index` and `index`.** Compactc distinguishes typed Vector indexing from raw array indexing. We unify under `Index` — both produce the same wire offset arithmetic.

4. **`default` as a node.** We generate `<T as Default>::default()` at codegen for Option-None. No IR variant needed.

5. **`addi` as a first-class node.** Compactc treats `Counter::increment_by(N)` as a dedicated `addi` op in the IR. We dispatch on the `LedgerAccess { method: "increment_by", args: [Literal(N)] }` shape at lowering time.

6. **`new` as a constructor op.** We use struct literals (`StructInit`) which subsume what `new` would do for the cases we hit.

## What we're doing better

1. **Path-preserving FnCall.** We carry `syn::Path` (full path with generic arguments) on every function call. Compactc carries only the short name, so its lowering has to reconstruct paths from a separate name table. Net: `Uint::<64>::from(0u64)` lowers verbatim for us; theirs needs a lookup.

2. **No bytecode bake-in.** Source-level AST and on-chain op sequence stay separated. Adding a backend (e.g., TypeScript from Nocturne, or a different host runtime altogether) is a codegen-layer change, not an IR rewrite.

3. **Algebraic enums with native matching.** Our `EnumPayload` lets `match e { V(p) => use(p) }` lower to a clean payload projection. Compactc has no algebraic enums and emulates them via structs (its `Maybe` is `{ is_some: Boolean, value: T }`). Concretely from gateway: compactc's `Maybe<ValidatorSignature>` always materialises a dummy `value` even when `is_some` is false. We don't.

4. **First-class `if`-as-expression with `cond_select` multiplex.** Both compilers expression-value if/else, but ours integrates with `cond_select` for ledger-side branching automatically (see [`memories/conditional-branch-cond-select-zeroing.md`](../memories/conditional-branch-cond-select-zeroing.md)).

5. **Cleaner separation of static vs dynamic.** Compactc treats `helpers[]` as a separate catalog and inlines on-chain ops. We treat helpers as Rust functions (limited today — see "missing" above) and emit on-chain ops at lowering. The cost is the gap on helpers; the win is less node duplication.

## How we could do better

Worth-considering changes ranked rough-fast-to-slow:

1. **Add an `exported` marker on `#[nocturne(ledger)]` struct fields** (attribute, not source-language change). Plumb through to `contract-info.json` so indexers / off-chain readers can discover queryable fields. Low effort, no codegen impact.

2. **Add a generic `FieldAccess { expr, field }` IR node** so `(some_expr).x` lowers cleanly for any user-struct value, not just witnesses / self. Eliminates a latent miscompile risk for nested-struct patterns.

3. **Parametric witnesses.** Extend `#[nocturne(witnesses)]` to support method declarations (`fn ownPublicKey(&self, salt: Bytes<32>) -> PublicKey`) alongside fields. Update IR: `WitnessAccess { field, args: Vec<ExprIR> }` (or a new `WitnessCall` variant). Codegen: pass args through to the witness invocation. Unblocks gateway-style contracts that need witnessed computation, not just witnessed values.

4. **Helpers catalog.** Recognise `#[nocturne(helper)]` annotations on `fn` items in the contract module and emit them into a helpers section. The IR for helpers is exactly the same as for circuits minus the `proof: true` flag and the on-chain Op emission. Lets contracts factor pure logic out of circuits without losing IR visibility.

5. **Type-aliases as first-class IR**. Today contracts use Rust `type` aliases (e.g., `type JubjubPoint = …`) and the macro doesn't see them. Track aliases in `ContractIR` and emit them to `contract-info.json` so the schema is self-describing.

6. **Opaque type registration**. Add a `#[nocturne(opaque)]` attribute for types whose serialisation is owned by the host runtime (TS, etc.). Carry the runtime-side name through to `contract-info.json`. Useful precondition for an FFI to JubjubPoint-style types.

None of these are urgent; the existing ExprIR handles every contract in `examples/` and the integration test suite. They become urgent the moment Nocturne is asked to compile a real contract on the gateway's scale and shape.

## Quick reference: compactc IR types

Type tags inside the IR (under `type`, `result-type`, etc.):

`Boolean`, `Bytes` (with `length: N`), `Enum` (with name), `Field`, `Opaque` (with `name`/`tsType`), `Struct` (with `name`, optional `elements[]` inline), `Tuple` (with `types[]`), `Uint` (with `maxval`), `Vector` (with `length` + element), `Void`, `Alias` (with `name` + inner type).

Ours, for reference:

`Boolean`, `Bytes<N>` (N ≤ 32), `Field`, `Uint<N>` (N ≤ 128), tuples up to arity 11, user structs (named), user enums (unit-only or homogeneous payload), `Option<T>`, `[T; N]` (N ≤ 11), `MerkleTreeDigest`, `MerkleTreePath<H, T>`. No `Opaque`, no `Alias`, no `Void` (we use `()`).
