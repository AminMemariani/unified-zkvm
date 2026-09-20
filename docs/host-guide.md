# Host guide

The host builds the program artifact, supplies input, proves, verifies, and acts
on the result. `ZkHostRunner` is the front door.

## Runner

```rust
use unified_zkvm_host::{RunnerConfig, ZkHostRunner};
use unified_zkvm_mock::MockBackend;

let backend = MockBackend::new();
let program = backend.build_program(b"guest-elf-bytes")?;

let runner = ZkHostRunner::builder()
    .backend(backend)
    .config(RunnerConfig::development())
    .build()?;
```

`ZkHostRunner::new(backend)` is the one-liner when defaults suffice. The builder
exists for configuration; `build()` returns `Result` because a runner without a
backend is a configuration error, not a panic.

### Methods

| Method | Signature |
|---|---|
| `execute` | `fn execute<I: Serialize + ?Sized>(&self, program: &ProgramArtifact, input: &I) -> Result<ExecutionResult, ZkVmError>` |
| `prove` | `fn prove<I: Serialize + ?Sized>(&self, program: &ProgramArtifact, input: &I) -> Result<ZkProof, ZkVmError>` |
| `prove_with` | `fn prove_with<I: Serialize + ?Sized>(&self, program: &ProgramArtifact, input: &I, options: &ProvingOptions) -> Result<ZkProof, ZkVmError>` |
| `verify` | `fn verify(&self, proof: &ZkProof, program: &ProgramArtifact) -> Result<VerifiedPublicValues, ZkVmError>` |
| `prove_and_verify` | `fn prove_and_verify<I: Serialize + ?Sized>(&self, program: &ProgramArtifact, input: &I) -> Result<(ZkProof, VerifiedPublicValues), ZkVmError>` |
| `backend_id` / `capabilities` / `config` / `backend` | accessors |

`execute` runs the guest **without proving**. Its `ExecutionResult::public_values`
are *not proven* — they are the output of a local, unattested run. Useful for
cycle counts and debugging; never for trusting a result.

### Verification returns the values

```rust
let proof = runner.prove(&program, &input)?;
let verified = runner.verify(&proof, &program)?;
let output: MyOutput = verified.decode()?;
```

Note the signature **requires the program**. There is deliberately no
`verify(&proof)` that infers identity from the proof itself — that would check a
proof against whatever program the proof claims, which is no check at all.

`VerifiedPublicValues` is obtainable only through verification: `into_verified()`
requires a `VerificationWitness`, which only a backend adapter can mint on the
success path of its `verify()`. The compiler, not a convention, enforces it —
see [security-model.md](security-model.md#the-type-system-as-a-guardrail).
If you genuinely need unverified values, `PublicValues::decode_unverified` says
so in its name.

## Configuration

```rust
use unified_zkvm_core::{FallbackPolicy, ProofKind};
use unified_zkvm_host::RunnerConfig;

let config = RunnerConfig::default()
    .with_proof_kind(ProofKind::Compressed)
    .with_fallback(FallbackPolicy::Deny);
```

| Field | Default | Why |
|---|---|---|
| `proving` | `ProvingOptions::default()` — no kind imposed | follow the backend's default rather than impose one |
| `verify_after_prove` | `false` | verification is not free; bulk provers should not pay twice |
| `artifacts` | `ArtifactPolicy::InMemory` | the library does not choose paths or write files on your behalf |
| `telemetry.spans_enabled` | `true` | spans carry backend and program identity only |
| `telemetry.log_public_values` | `false` | not secret, but large and log-bloating |
| `telemetry.log_guest_input` | `false` | **this is the private witness** |

`RunnerConfig::development()` only turns on `verify_after_prove`. Despite the
name it enables **no insecure mode** — there is no configuration in this library
that weakens verification.

`RunnerConfig` is `#[non_exhaustive]`, so new options are not breaking changes
for callers who construct it with `..Default::default()` or the builders.

## Proving options

```rust
use unified_zkvm_core::{ProofKind, ProvingOptions};

let opts = ProvingOptions::new(ProofKind::Compressed)
    .with_cycle_limit(1 << 24);

let proof = runner.prove_with(&program, &input, &opts)?;
```

`FallbackPolicy::Deny` is the default: if the requested kind is unavailable you
get `UnsupportedProofKind` rather than a silent downgrade. A downgrade changes
proof size, verification cost and on-chain compatibility — all things a caller
chose deliberately when they named a kind. `FallbackPolicy::AllowNative` opts
into falling back to the backend's native proof.

`ProvingOptions::backend_default()` requests whatever the backend prefers.
`resolve_kind(backend, &supported)` performs the resolution, treating the first
entry of `supported_proof_kinds()` as the default.

## Capability gating

Every runner call gates first:

```rust
if runner.capabilities().supports(Capability::Prove) { /* ... */ }
```

Unsupported operations fail with `UnsupportedCapability { backend, capability }`
before any backend work happens. `require_capability` in core is the shared
implementation. See [backend-compatibility.md](backend-compatibility.md) for
what each backend actually claims.

## Aggregation

`ProofAggregator` is blanket-implemented for every `BackendAdapter` and gated on
`CapabilitySet::AGGREGATION`, which no shipped backend sets — so `aggregate()`
returns `UnsupportedCapability`. It also rejects an empty set and refuses to mix
backends. Read [aggregation.md](aggregation.md) before designing around it.

## Proof persistence

```rust
use unified_zkvm_core::container;

container::save(&proof, "proof.bin")?;          // std feature
let proof = container::load("proof.bin")?;
let bytes = container::to_bytes(&proof)?;
let proof = container::from_bytes(&bytes)?;
```

Container layout: `UZKVMPRF` ‖ u16 version ‖ u16 backend ‖ u32 body len ‖
postcard body. Version 1. `read_header` inspects a header without decoding the
body, so a hostile length prefix is refused before anything is allocated.

## The escape hatch

The abstraction covers the portable part. When you need something
backend-specific, reach through:

```rust
let sdk_specific = runner.backend();   // &B — the concrete adapter
```

This is intentional, and it is better than the alternative of bloating the
common trait with a union of every vendor feature. Code past the escape hatch is
no longer portable; keep it in one clearly named module so the boundary stays
visible.

## Static vs dynamic dispatch

`ZkHostRunner<B>` is generic, so the normal path is monomorphized — no vtable,
full inlining, and the concrete adapter's inherent methods (like
`Sp1Backend::build_program`) remain reachable through `runner.backend()`.

When the backend is chosen at runtime, use `DynBackend = Box<dyn BackendAdapter>`;
core provides a `BackendAdapter` impl for the boxed form, so
`ZkHostRunner<DynBackend>` works with no changes. You lose inherent methods —
you get the trait surface only. Rationale in
[adr/ADR-007-backend-selection.md](adr/ADR-007-backend-selection.md).

## Async

The SP1 adapter uses `sp1-sdk`'s `blocking` feature, and **that client panics if
called from inside an existing Tokio runtime**. From async code, wrap runner
calls in `tokio::task::spawn_blocking`. Proving is CPU-bound anyway, so it does
not belong on an async executor thread.

## Related

- [guest-guide.md](guest-guide.md)
- [security-model.md](security-model.md)
- [troubleshooting.md](troubleshooting.md)
