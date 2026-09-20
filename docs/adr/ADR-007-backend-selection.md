# ADR-007: Backend selection

## Status

Accepted.

## Context

Applications choose a backend in two different ways, and both are legitimate:

- **Statically.** Most applications pick one backend, deploy it, and would
  rather the compiler inline the whole path and catch mistakes at compile time.
- **Dynamically.** Benchmarking tools, multi-tenant provers, migration periods
  and CLI utilities need to choose at runtime, sometimes per request.

Optimising only for the first makes a benchmark harness awkward. Optimising only
for the second imposes a vtable on every application - inside a library where
the surrounding operation is measured in seconds of proving, but where losing
concrete adapter methods is a real ergonomic loss.

There is also a feature-flag question: which backends a build even contains, and
what happens when an application asks for one that is not compiled in.

## Decision

**Static by default, dynamic by opt-in.**

### Static (default)

```rust
pub struct ZkHostRunner<B> { /* ... */ }
impl<B: BackendAdapter> ZkHostRunner<B> { /* ... */ }
```

Monomorphized, no vtable, and the concrete adapter stays reachable through
`runner.backend() -> &B` - which is how inherent methods like
`Sp1Backend::build_program` and `supported_proof_kinds()` remain usable.

### Dynamic (opt-in)

```rust
pub type DynBackend = alloc::boxed::Box<dyn BackendAdapter>;
```

Core implements `BackendAdapter` for the boxed form, so `ZkHostRunner<DynBackend>`
works with no special support in the runner. Selecting dynamically is therefore
a type annotation, not a different API.

### Feature gating and discovery

Each backend has a cargo feature (`BackendId::feature_name()`). Adapters are
separate crates, so enabling a backend is a dependency decision.
`unified_zkvm::available_backends()` returns only backends whose feature is
enabled **and** whose adapter exists - and asking for an absent one yields
`ZkVmError::BackendNotEnabled`, which is deliberately clearer than a confusing
import error.

`BackendDescriptor` carries backend metadata for tooling that wants to display
the set of options.

## Consequences

### Positive

- The common case costs nothing at runtime and inlines fully.
- Backend-specific methods stay available without downcasting.
- Dynamic dispatch is available without a second API, a second runner type, or a
  registry.
- A missing backend is a clear, named error rather than a compile mystery or a
  panic.
- Capability checks happen against the actual adapter in both modes.

### Negative

- **Dynamic mode loses inherent methods.** `DynBackend` exposes the trait
  surface only, so `build_program` must be called on the concrete adapter before
  boxing. This surprises people and is documented in the host guide and the
  migration guide.
- Generic `ZkHostRunner<B>` appears in user type signatures, which is more
  verbose than an opaque type would be.
- Monomorphization duplicates code per backend - irrelevant against an SDK's
  size, but real.
- Compiling several adapters into one binary pulls several full SDK trees, with
  the build time that implies.
- Feature flags and adapter crates are two knobs for one concept; the facade's
  feature table has to explain both.

## Alternatives considered

**Always dynamic.** Simpler signatures, at the cost of a vtable for everyone and
the loss of concrete adapter methods for the majority who do not need runtime
selection.

**A global registry with runtime registration.** Convenient for plugins, but it
adds global mutable state, defers errors to runtime, and makes it unclear from a
build which backends are present.

**An enum of all backends.** Nice ergonomics, but core would have to depend on
every adapter - inverting the dependency direction ADR-001 establishes and
forcing every user to compile every SDK.

**Environment-variable selection.** Convenient and dangerous: proving backend is
a security-relevant choice, and it should be visible in code, not in an ambient
variable. The RISC Zero `bonsai` situation is the cautionary example.
