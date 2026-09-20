# Adding a backend

A new adapter is welcome. It is also a security-relevant contribution: an
adapter is the code that decides whether a proof is accepted. This page is the
contract.

## Step 1 — reserve the `BackendId`

`BackendId` discriminants are **written to disk** inside proof containers and
must never be reused or renumbered. Currently taken: Mock=0, Sp1=1, Risc0=2,
Jolt=3, OpenVm=4, Pico=5. Add a new backend with a new number, then update:

- the enum and `BackendId::ALL`
- `feature_name()`
- `is_cryptographic()`
- `integration_status()` — start at `Planned`
- `from_u16()` — it must keep failing closed for unknown values
- `Display`

## Step 2 — create the adapter crate

`crates/unified-zkvm-<backend>/`, with its own `[workspace]` table so it is
independent, and add it to the root `Cargo.toml` `exclude` list. Adapters stay
out of the default workspace on purpose: each pulls a multi-hundred-crate SDK,
and guest builds need a vendor toolchain. That exclusion is what keeps
`cargo test --workspace` fast on a clean checkout.

Pin the SDK to an exact version and document every non-default feature you
enable, with the reason. Precedent worth copying: the RISC Zero adapter uses
`default-features = false` specifically so the `bonsai` feature cannot silently
route proving to a remote service when environment variables happen to be set.

## Step 3 — implement `BackendAdapter`

```rust
pub trait BackendAdapter: Send + Sync {
    fn backend_id(&self) -> BackendId;
    fn capabilities(&self) -> CapabilitySet;
    fn execute(&self, program: &ProgramArtifact, input: &[u8])
        -> Result<ExecutionResult, ZkVmError>;
    fn prove(&self, program: &ProgramArtifact, input: &[u8], options: &ProvingOptions)
        -> Result<ZkProof, ZkVmError>;
    fn verify(&self, proof: &ZkProof, program: &ProgramArtifact)
        -> Result<VerificationWitness, ZkVmError>;
    fn aggregate(&self, _proofs: &[ZkProof]) -> Result<ZkProof, ZkVmError> { /* default: unsupported */ }
    fn backend_version(&self) -> String { /* default */ }
}
```

Plus an inherent `build_program(&self, elf_bytes: &[u8]) -> Result<ProgramArtifact, ZkVmError>`
and `supported_proof_kinds() -> [ProofKind; N]` with the **default kind first** —
`ProvingOptions::resolve_kind` treats the first entry as the default.

### The capability honesty rule

**Set a bit only if this adapter implements it and a test exercises it.**

Not "the SDK supports it". Not "it should work". A capability bit is a promise
the host runner makes to application code before it does any work; a false bit
turns into a confusing runtime failure at best and a wrong security assumption
at worst.

Follow the existing adapters: SP1 and RISC Zero claim exactly
`MINIMUM_VIABLE | CYCLE_METRICS | COMPRESSION`, and deliberately do **not**
claim `AGGREGATION`, `RECURSION`, `ONCHAIN_PROOF` or any `*_ACCEL` bit, each for
a documented reason. Write the same kind of comment in your adapter, and add a
unit test asserting the negative claims — both existing adapters have one.

### Program identity must be the thing the verifier binds to

This is the subtlest requirement here. SP1's adapter derives its `ProgramId`
from the **verifying-key hash** (`pk.verifying_key().hash_u32()`), not from a
digest of the ELF, because the verifying key is what SP1's verifier actually
binds a proof to. Binding our `ProgramId` to anything else would let a proof of
a *different* program pass `verify_binding`.

Find the analogous value in your SDK (image ID, verifying key, program
commitment) and use `ProgramId::from_digest`, `from_u32_words` or `from_opaque`.
If the identity is not what the verifier checks, the binding check is theatre.

### `verify()` must call the real verifier

Order matters and is not negotiable:

```rust
// Once, at the top of your crate: grants this adapter the right to attest that
// verification happened. The underlying trait is sealed, so application code
// can never do this.
unified_zkvm_core::impl_verifier_identity!(MyBackend);

fn verify(&self, proof: &ZkProof, program: &ProgramArtifact)
    -> Result<VerificationWitness, ZkVmError>
{
    proof.verify_binding(program)?;   // 1. backend match, then program-ID match
    // 2. decode the native proof, then call the SDK's real verifier
    //    ...
    // 3. ONLY on success:
    Ok(VerificationWitness::new(self))
}
```

Binding first means a cryptographically valid proof of the *wrong* program still
fails, and the expensive path stays off the error route.

The returned `VerificationWitness` is what lets a caller read the proof's public
values, so minting one is a security-critical act: return it **only** after both
the binding check and the SDK verifier have succeeded. Minting it early — or on
an error path — silently converts unchecked proofs into trusted ones for every
downstream consumer. Never "verify" by recomputing something
you produced yourself — that is what the mock backend does, and it is why the
mock is quarantined by three independent guards.

### Input framing

Pass the canonical bytes straight through. SP1 uses `SP1Stdin::write_slice`
(pairing with the guest's `read_vec()`) specifically to avoid the SDK's serde
`write`, which would insert a second encoding layer on top of the canonical
postcard framing. Do not double-encode.

### Errors

Map SDK failures into `ZkVmError::backend(backend, Operation, Stage, source)`
with accurate `Operation` (`Setup`/`Execute`/`Prove`/`Verify`) and `Stage`
(`BackendSetup`/`GuestExecution`/`ProofGeneration`/`Conversion`). A verification
failure is `ZkVmError::VerificationFailed`, not a generic backend error — callers
branch on that difference.

## Step 4 — guest runtime (if needed)

If the backend needs a guest-side runtime, add a feature to
`unified-zkvm-guest` and a `GuestRuntime` impl, and extend the `#[entrypoint]`
macro with the backend's entrypoint ritual. Keep the no-backend fallback intact:
with no feature selected the guest must still compile and run as a plain binary,
because that is what makes guest logic testable without a toolchain.

## Step 5 — tests required

| Test | Where | Required |
|---|---|---|
| capabilities claim only what is implemented (incl. negative asserts) | adapter crate | yes |
| `build_program` derives the verifier-bound identity | adapter crate | yes |
| binding rejects a foreign backend and a wrong program | adapter crate | yes |
| end-to-end prove → verify | adapter crate, `#[ignore]`d | yes |
| portability differential vs the reference model | `tests/portability/` | yes |
| golden vectors if any wire format changed | `tests/vectors/` | if applicable |

End-to-end tests are `#[ignore]`d because they need the vendor toolchain and a
real guest ELF; they run in the backend CI job. Take an ELF path from an
environment variable, as the RISC Zero adapter does with `UZKVM_RISC0_TEST_ELF`.

## Step 6 — documentation required

A PR adding a backend is incomplete without:

- a row in every table in [backend-compatibility.md](backend-compatibility.md),
  including unset capability bits **with reasons**
- a per-backend section: pinned version, host prerequisites, guest toolchain,
  required features and why, proof-kind mapping, identity derivation
- symptom entries in [troubleshooting.md](troubleshooting.md) for each build
  prerequisite you discovered the hard way
- the README maturity table
- a `CHANGELOG.md` entry
- crate-level rustdoc explaining what the adapter does *not* claim

## Step 7 — promote the status honestly

`Planned` → `Supported` when the adapter compiles against a pinned SDK and unit
tests pass. `Supported` → `Stable` only when end-to-end proving runs in CI on a
schedule and the portability suite passes against it. Do not skip a step; the
status field is the first thing a user reads.

## Related

- [architecture.md](architecture.md)
- [security-model.md](security-model.md)
- [adr/ADR-002-isolated-backend-adapters.md](adr/ADR-002-isolated-backend-adapters.md)
