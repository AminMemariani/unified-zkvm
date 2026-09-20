# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as qualified in [docs/versioning.md](docs/versioning.md).

## [Unreleased]

## [0.1.0] - 2026-09-20

### Added

- `unified-zkvm-core`: backend-neutral types — `BackendId` (Mock=0, Sp1=1, Risc0=2, Jolt=3, OpenVm=4, Pico=5), `IntegrationStatus`, `ZkProof`, `ProgramId`, `ProgramArtifact`, `PublicValues`, `ProofKind`, `ProvingOptions`, `FallbackPolicy`, `ProofMetadata`, `ExecutionResult`, `ResourceUsage`, `ZkVmError`.
- `CapabilitySet` bitflags with `MINIMUM_VIABLE`, `satisfies`, `missing_from` and `iter_capabilities`, plus the `Capability` enum for single-capability errors.
- Canonical serialization: postcard payload framed as magic `0x5A 0x4B` followed by u16 LE version, u32 LE length and payload; `ENCODING_VERSION` 1, `MAX_MESSAGE_BYTES` 256 MiB.
- Proof container format: magic `UZKVMPRF`, u16 version, u16 backend, u32 body length, postcard body; `PROOF_CONTAINER_VERSION` 1, with `to_bytes`, `from_bytes`, `read_header` and std-gated `save`/`load`.
- `ZkProof::verify_binding` checking backend match then program-ID match before any cryptographic verification.
- `VerifiedPublicValues`, constructible only via `ZkProof::into_verified()`, which requires a `VerificationWitness` — a zero-sized capability token that only a backend adapter can mint, on the success path of its `verify()`. Reading a trusted guest output therefore requires verification to have happened, enforced at compile time rather than by convention.
- `VerificationWitness` and the sealed `VerifierIdentity` trait, with the `impl_verifier_identity!` macro that lets adapter crates opt in.
- `unified-zkvm-guest`: `zk_read`, `zk_read_bytes`, `zk_commit`, `zk_commit_bytes`, `sha256`, `sha256_parts`, `active_backend`, and `keccak256` which returns `UnsupportedCapability` by design.
- `GuestRuntime` trait with SP1, RISC Zero and host-test implementations; the host-test runtime makes guest logic unit-testable with plain `cargo test`.
- `unified-zkvm-host`: `ZkHostRunner` with `execute`, `prove`, `prove_with`, `verify` and `prove_and_verify`; `ZkHostRunnerBuilder`; `Verifier`; `Prover`; `ProofAggregator`.
- `RunnerConfig`, `TelemetryConfig` and `ArtifactPolicy` with safe defaults: `FallbackPolicy::Deny`, `verify_after_prove` off, and no logging of guest input or public values.
- `unified-zkvm-macros`: the `#[entrypoint]` attribute, emitting the SP1 or RISC Zero entrypoint ritual, or a plain `fn main()` when no backend feature is selected.
- `unified-zkvm-mock`: development backend with `with_guest`, `with_capabilities`, `build_program` and `verify_call_count`; produces no cryptographic proof and is isolated by three independent guards.
- `unified-zkvm` facade with `std`, `host`, `guest`, `macros`, `mock`, `sp1` and `risc0` features, plus `available_backends()`.
- `unified-zkvm-sp1` adapter against `sp1-sdk 6.8.0` (feature `blocking`), with program identity derived from the verifying-key hash and input framed via `SP1Stdin::write_slice`.
- `unified-zkvm-risc0` adapter against `risc0-zkvm 3.0.6` with `default-features = false` and features `client`, `prove`, `std` — `prove` is required or `default_prover()` panics at runtime, and disabling defaults prevents `bonsai` from silently routing proving to a remote service.
- 15 cross-backend portability tests comparing against a shared reference model.
- 9 negative-security tests covering tampered proof bytes, rewritten public values, wrong program identity, proof relabelling, mock-as-real substitution, cross-backend verification, hostile length prefixes, container truncation and header rewriting.
- 15 property-based serialization tests and 15 golden vectors pinning exact wire bytes.
- Documentation suite: README, `docs/` (architecture, backend compatibility, guest and host guides, crypto, aggregation, adding a backend, security model, troubleshooting, versioning, migration, backend comparison, dependencies, benchmarks), seven ADRs, and the community files.

### Known limitations

- End-to-end proving with SP1 and RISC Zero has not been executed in this repository; those tests are `#[ignore]`d pending the vendor toolchains.
- No backend claims `AGGREGATION`, `RECURSION`, `ONCHAIN_PROOF` or any `*_ACCEL` capability; `aggregate()` returns `UnsupportedCapability`.
- `keccak256` always returns `UnsupportedCapability`.
- No benchmark numbers are published.

[Unreleased]: https://github.com/unified-zkvm/unified-zkvm/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/unified-zkvm/unified-zkvm/releases/tag/v0.1.0
