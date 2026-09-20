# Roadmap

Phased. Only items that actually exist in this repository are marked done.

## Phase 1 — Foundation (done)

- [x] `unified-zkvm-core`: `BackendId`, `CapabilitySet`, `ZkProof`, `ProgramId`, `PublicValues`, `ZkVmError`
- [x] Canonical serialization: postcard payload in a framed message (`ENCODING_VERSION` 1)
- [x] Proof container format `UZKVMPRF` (`PROOF_CONTAINER_VERSION` 1) with save/load
- [x] `unified-zkvm-guest`: `zk_read`, `zk_commit`, `sha256`, `sha256_parts`
- [x] `unified-zkvm-host`: `ZkHostRunner`, builder, `RunnerConfig`, `Verifier`, `Prover`
- [x] `#[entrypoint]` macro with a host-testable no-backend fallback
- [x] `unified-zkvm-mock` development backend with three isolation guards
- [x] `unified-zkvm` facade with feature-gated re-exports

## Phase 2 — First real backends (done)

- [x] SP1 adapter against `sp1-sdk 6.8.0` — compiles, unit tests pass
- [x] RISC Zero adapter against `risc0-zkvm 3.0.6` — compiles, unit tests pass
- [x] Verification binding: backend match, then program ID, then real verifier
- [x] Program identity derived from the value each verifier binds to
- [x] Capability honesty rule plus negative-claim tests in both adapters

> Not yet done in Phase 2: end-to-end proving has **not** been executed in this
> repository. It requires the vendor toolchain and is exercised by `#[ignore]`d
> tests and scheduled CI.

## Phase 3 — Test and documentation suite (done)

- [x] 15 cross-backend portability tests against a shared reference model
- [x] 9 negative-security tests, each mapped to a concrete attack
- [x] 15 property-based serialization tests (proptest)
- [x] 15 golden vectors pinning exact wire bytes
- [x] `cargo test --workspace` green with no zkVM installed (~154 tests)
- [x] Documentation suite: README, `docs/`, 7 ADRs, community files

## Phase 4 — Confidence in the real backends (next)

- [ ] End-to-end prove/verify running in scheduled CI for SP1 and RISC Zero
- [ ] Example guests (fibonacci, sha256) building against both toolchains
- [ ] Portability harness running against real backends, not just mock
- [ ] Promote SP1 and RISC Zero from `Supported` to `Stable` once the above holds
- [ ] Host-side microbenchmarks for abstraction overhead (criterion)

## Phase 5 — Capability expansion (future)

- [ ] Keccak-256 via real precompiles; `keccak256` currently returns `UnsupportedCapability`
- [ ] Verified `SHA256_ACCEL` / `KECCAK_ACCEL` claims, including guest `[patch.crates-io]` sets
- [ ] `ONCHAIN_PROOF`: Groth16/Plonk path, tested rather than assumed
- [ ] Aggregation: an application-neutral aggregation guest, or documentation that it cannot exist generically
- [ ] Remote proving as an explicit, opt-in capability — never an environment accident

## Phase 6 — More backends (future)

- [ ] OpenVM adapter (`2.0.2` on crates.io; MSRV 1.91.1 is the current friction)
- [ ] Jolt adapter — blocked: git-only, `v0.3.0-alpha`, upstream states it is not production-suitable
- [ ] Pico adapter — blocked: git-only (crates.io `pico-sdk` is an unrelated oscilloscope driver)

## Phase 7 — Hardening (future)

- [ ] Fuzzing the message and container parsers
- [ ] Published benchmark methodology with reproducible numbers
- [ ] An external review of the verification path
- [ ] 1.0 with a stable wire format commitment

## Not planned

- Ranking backends by performance
- A proving system of our own
- Runtime plugin loading of adapters
- Guaranteeing that every guest runs unchanged on every backend
