# ADR-002: Isolated backend adapters

## Status

Accepted.

## Context

Support for several proving systems can be structured in three ways: a
feature-gated module inside one crate, a plugin loaded at runtime, or a separate
crate per backend implementing a shared trait.

The constraints are concrete:

- Each SDK pulls a very large dependency tree, and some need host tools
  (`protoc` for SP1) or platform toolchains (Metal on macOS for RISC Zero).
- SDKs move fast and break compatibility; they must be pinnable independently.
- Adapter code is security-relevant: it decides whether a proof is accepted.
- A user of one backend should not compile another's dependencies.

## Decision

One crate per backend, each implementing `BackendAdapter`:

```rust
pub trait BackendAdapter: Send + Sync {
    fn backend_id(&self) -> BackendId;
    fn capabilities(&self) -> CapabilitySet;
    fn execute(&self, program: &ProgramArtifact, input: &[u8]) -> Result<ExecutionResult, ZkVmError>;
    fn prove(&self, program: &ProgramArtifact, input: &[u8], options: &ProvingOptions) -> Result<ZkProof, ZkVmError>;
    fn verify(&self, proof: &ZkProof, program: &ProgramArtifact) -> Result<(), ZkVmError>;
    fn aggregate(&self, _proofs: &[ZkProof]) -> Result<ZkProof, ZkVmError> { /* unsupported by default */ }
    fn backend_version(&self) -> String { /* default */ }
}
```

With these rules:

1. Adapter crates carry their own `[workspace]` table and are in the root
   `exclude` list.
2. Each pins its SDK to an exact version and documents every non-default feature
   and the reason for it.
3. `capabilities()` reports only what the adapter implements **and tests**.
4. `verify()` must call the SDK's real verifier, after `verify_binding`.
5. Program identity must be the value the SDK's verifier binds to.
6. `aggregate` defaults to unsupported, so a new adapter cannot accidentally
   claim it.

Core reserves `BackendId` discriminants for backends that have no adapter
(`Jolt`, `OpenVm`, `Pico`). That is a name-and-number reservation, not a
dependency; `integration_status()` reports the truth.

## Consequences

### Positive

- Dependency isolation is total: not using a backend means not compiling it.
- SDK versions are pinned per adapter and bumped independently.
- A new backend is an additive change - no core modification beyond an enum
  variant.
- Adapters are individually auditable, which matters because they are the code
  that accepts proofs.
- Vendor build prerequisites stay confined to the crate that needs them.

### Negative

- ~~**Excluded crates miss the default `cargo check`**; a core change can break
  an adapter silently until backend CI runs.~~ Resolved in 0.1.0: the adapters
  are workspace members and a core change that breaks one fails immediately. See
  the amendment to [ADR-001](ADR-001-workspace-architecture.md). Crate
  *isolation*, which is what this ADR is actually about, is unchanged.
- More crates to publish, version and release in order.
- Some duplication across adapters (bincode handling, error mapping, `Instant`
  timing). Accepted: premature sharing here would push backend specifics into a
  common layer, which is the coupling this ADR exists to prevent.
- The trait is a lowest common denominator; anything backend-specific needs the
  `runner.backend()` escape hatch.
- Users must add a second dependency to use a real backend.

## Alternatives considered

**Feature-gated modules in one crate.** Single dependency for users, but every
SDK's build requirements become the main crate's build requirements, and feature
combinations multiply into a matrix nobody tests completely.

**Runtime plugin loading (dynamic libraries).** Backends without recompilation,
at the cost of ABI stability problems, a much worse security story for the code
that accepts proofs, and no compile-time capability checking. Rejected firmly.

**Wrapping one SDK and shimming others onto it.** Inherits one vendor's model as
the universal one, which is precisely the lock-in this project exists to avoid.
