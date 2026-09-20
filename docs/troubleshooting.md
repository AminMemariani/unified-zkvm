# Troubleshooting

Symptom first, then the fix. Most of these were found by actually compiling the
adapters, not by reading docs.

## Build: `protoc` not found (SP1)

**Symptom.** Building `unified-zkvm-sp1` fails in a build script, typically
`sp1-prover-types`, complaining that `protoc` is missing.

**Cause.** SP1's prover types are generated from protobuf definitions at build
time. The compiler is a host tool; cargo does not install it.

**Fix.**

```bash
brew install protobuf      # macOS
apt-get install -y protobuf-compiler   # Debian/Ubuntu
```

## Build: Metal / GPU kernel failure (RISC Zero, macOS)

**Symptom.** Building `unified-zkvm-risc0` fails compiling GPU kernels, asking
for the Xcode Metal Toolchain.

**Cause.** RISC Zero builds Metal kernels on macOS for GPU acceleration.

**Fix.** Install the Xcode Metal Toolchain, **or** skip kernel building:

```bash
RISC0_SKIP_BUILD_KERNELS=1 cargo build -p unified-zkvm-risc0
```

Skipping disables GPU acceleration. **CPU proving is unaffected** - it is the
right choice for CI and for development machines.

## Runtime: panic in `get_r0vm_path().unwrap()` (RISC Zero)

**Symptom.** Everything compiles, then `default_prover()` panics at runtime.

**Cause.** `risc0-zkvm`'s `prove` feature is **not** enabled by default. Without
it the prover resolves to an external `r0vm` binary path that is not there. It
is a runtime panic rather than a compile error, which is why this deserves a
pinned manifest.

**Fix.** Enable it explicitly:

```toml
risc0-zkvm = { version = "3.0.6", default-features = false, features = ["client", "prove", "std"] }
```

That is exactly what the adapter's manifest does.

## Runtime: proving went to a remote service

**Symptom.** Proving is unexpectedly fast or fails with a network/auth error,
and `BONSAI_API_URL` / `BONSAI_API_KEY` exist in your environment.

**Cause.** RISC Zero's `bonsai` feature routes proving to a remote service when
those variables are set.

**Fix.** Keep `default-features = false` on `risc0-zkvm` so `bonsai` is never
enabled implicitly. The adapter does this deliberately: remote proving should be
an explicit decision, not an environment accident. `REMOTE_PROVING` is not a
claimed capability of any adapter here.

## Runtime: panic "cannot block inside a Tokio runtime" (SP1)

**Symptom.** Calling `prove` from an async function panics.

**Cause.** The SP1 adapter uses `sp1-sdk`'s `blocking` feature. The blocking
client panics when called from inside an existing Tokio runtime.

**Fix.**

```rust
let proof = tokio::task::spawn_blocking(move || runner.prove(&program, &input)).await??;
```

Proving is CPU-bound; it does not belong on an executor thread regardless.

## Build: guest toolchain missing (`sp1up` / `rzup`)

**Symptom.** Building a guest crate fails with an unknown target or a missing
toolchain (`succinct`, `risc0`).

**Cause.** Guest ELFs need vendor toolchains that **rustup does not install**
and `rust-toolchain.toml` does not pin.

**Fix.** Install `sp1up` for SP1 or `rzup` for RISC Zero, following the vendor's
current instructions.

**Note.** You do not need either to work on this repository.
`cargo test --workspace` passes with no zkVM installed - that is deliberate.

## Build: `zk_read`/`zk_commit` not found

**Cause.** The `guest` feature is not enabled on the `unified-zkvm` facade.

**Fix.**

```toml
unified-zkvm = { version = "0.1", default-features = false, features = ["guest"] }
```

Add `macros` if you use `#[entrypoint]`. Do not enable `host` in a guest crate - 
guests pay for every linked byte in proving cycles.

## Build: `#[entrypoint]` errors

| Message | Cause |
|---|---|
| "a unified-zkvm entrypoint takes no arguments" | read input in the body with `zk_read()` |
| "a guest entrypoint cannot be `async`" | zkVM guests are single-threaded with no executor |
| linker/`main` errors on a real backend | the guest must declare `#![no_main]` itself; the macro cannot add an inner attribute |

The preamble: `#![cfg_attr(any(feature = "sp1", feature = "risc0"), no_main)]`.

## Build: two backend features enabled at once

**Symptom.** Conflicting entrypoint definitions, or duplicate/incompatible guest
runtimes.

**Cause.** Exactly one guest runtime may be selected. `sp1` and `risc0` are
mutually exclusive in a guest build.

**Fix.** Enable one. If you need both backends in one *application*, build two
guest binaries and select the host adapter at runtime with `DynBackend`.

## Runtime: `BackendNotEnabled`

**Cause.** You asked for a backend whose adapter is not compiled in.

**Fix.** Check `unified_zkvm::available_backends()` - it lists only backends
whose feature is enabled *and* whose adapter exists. The error is deliberately
distinct from a confusing import failure.

## Runtime: `UnsupportedCapability`

**Cause.** The operation is real but the backend does not claim the bit. Common
cases: `Aggregation` (no backend claims it - see [aggregation.md](aggregation.md))
and `KeccakAccel` (`keccak256` always fails - see [crypto.md](crypto.md)).

**Fix.** Check `runner.capabilities()` and
[backend-compatibility.md](backend-compatibility.md). This is the abstraction
telling the truth, not a bug.

## Runtime: `UnsupportedProofKind`

**Cause.** You requested a kind the backend cannot produce and the default
`FallbackPolicy::Deny` refused to downgrade silently.

**Fix.** Request a supported kind (both real adapters support `Native` and
`Compressed`), or opt in explicitly with `FallbackPolicy::AllowNative` - 
understanding that proof size, verification cost and on-chain compatibility
change.

## Runtime: `ProgramIdMismatch`

**Cause.** The proof was produced for a different program. Usually the guest ELF
was rebuilt - a recompile changes the verifying key / image ID, and therefore
the identity.

**Fix.** Verify against the exact artifact that produced the proof. This error
firing is the binding check working.

## Runtime: `BackendMismatch`

**Cause.** A proof from one backend reached another's verifier - often a mock
proof reaching a real verifier.

**Fix.** Route by `proof.backend()`. Never attempt to verify cross-backend;
proofs are backend-native artifacts.

## Runtime: `UnsupportedVersion`

**Cause.** A stored proof or message uses a different `ENCODING_VERSION` (1) or
`PROOF_CONTAINER_VERSION` (1).

**Fix.** Re-generate with a matching version. Formats fail closed rather than
best-effort parsing. See [versioning.md](versioning.md).

## Test failure: golden vectors

**Symptom.** `tests/vectors/golden.rs` fails.

**Cause.** The wire encoding changed - a codec swap, a struct field reorder, or
a dependency bump.

**This is not a flaky test.** It means the bytes a deployed guest ELF sees have
changed, and a deployed ELF cannot be renegotiated. Treat it as a
**semver-breaking** change: fix the encoding, or bump `ENCODING_VERSION` and
follow [versioning.md](versioning.md).

## Adapter breaks after a core change

**Cause.** A change to a `BackendAdapter` trait signature in core necessarily
breaks every adapter implementing it.

**Fix.** `cargo test --workspace` compiles the adapters, so the break surfaces
at once. Update every adapter in the same commit as the trait change. If you
selected crates with `-p` to skip the proving SDKs, run the full workspace
before pushing.
