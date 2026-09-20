# Backend compatibility

The rule this file exists to enforce: **a capability bit means a tested
implementation.** If a bit is unset, it is unset because we have not verified
it - not because the upstream backend lacks it.

## Status vocabulary

`BackendId::integration_status()` returns one of:

| Status | Meaning |
|---|---|
| `Stable` | adapter implemented and exercised in the default test run |
| `Supported` | adapter implemented, compiles against a pinned SDK, unit tests pass; end-to-end proving requires a vendor toolchain |
| `Planned` | a `BackendId` discriminant is reserved; no adapter exists |

These describe **this project's adapter**, not upstream's own maturity.

## Matrix

| | Mock | SP1 | RISC Zero | OpenVM | Jolt | Pico |
|---|---|---|---|---|---|---|
| `BackendId` discriminant | 0 | 1 | 2 | 4 | 3 | 5 |
| Status | stable | supported | supported | planned | planned | planned |
| Adapter crate | `unified-zkvm-mock` | `unified-zkvm-sp1` | `unified-zkvm-risc0` | - | - | - |
| Pinned SDK | - | `sp1-sdk 6.8.0` | `risc0-zkvm 3.0.6` | `2.0.2` (not integrated) | git-only `v0.3.0-alpha` | git-only |
| `is_cryptographic()` | **false** | true | true | true | true | true |
| Execute | yes | yes | yes | - | - | - |
| Prove | yes (**not a proof**) | yes | yes | - | - | - |
| Verify | yes (digest recompute) | yes | yes | - | - | - |
| `GUEST_IO` | yes | yes | yes | - | - | - |
| `PUBLIC_VALUES` | yes | yes | yes | - | - | - |
| `EXECUTE` | yes | yes | yes | - | - | - |
| `PROVE` | yes | yes | yes | - | - | - |
| `VERIFY` | yes | yes | yes | - | - | - |
| `CYCLE_METRICS` | yes | yes | yes | - | - | - |
| `COMPRESSION` | - | yes | yes | - | - | - |
| `AGGREGATION` | - | - | - | - | - | - |
| `RECURSION` | - | - | - | - | - | - |
| `ONCHAIN_PROOF` | - | - | - | - | - | - |
| `SHA256_ACCEL` | - | - | - | - | - | - |
| `KECCAK_ACCEL` | - | - | - | - | - | - |
| `ELLIPTIC_CURVE_ACCEL` | - | - | - | - | - | - |
| `REMOTE_PROVING` | - | - | - | - | - | - |

`MINIMUM_VIABLE` is the union of `GUEST_IO | PUBLIC_VALUES | EXECUTE | PROVE |
VERIFY`. Both real adapters claim exactly
`MINIMUM_VIABLE | CYCLE_METRICS | COMPRESSION`.

### Why the unset bits are unset

- **`*_ACCEL`** - acceleration is *not* a host-side property. Precompiles are
  selected in the **guest** manifest via `[patch.crates-io]`, replacing e.g.
  `sha2` with a backend-patched crate. A host adapter has no way to know which
  patches a given guest ELF was built with, and we have not verified the
  patched builds. Claiming the bit would let `CryptoSupport` tell callers their
  hashing is cheap when it is not. See [crypto.md](crypto.md).
- **`AGGREGATION` / `RECURSION`** - neither SDK exposes a host-level
  `aggregate(&[proof]) -> proof`. Both provide ingredients that require an
  application-specific aggregation guest. See [aggregation.md](aggregation.md).
- **`ONCHAIN_PROOF`** - the Groth16/Plonk path needs vendor proving artifacts
  that these adapters neither download nor test. An untested on-chain claim is
  the most expensive kind of wrong.
- **`REMOTE_PROVING`** - deliberately not wired. See the RISC Zero note below
  about `bonsai`.

## Proof-kind vocabulary

`ProofKind` refuses to adopt one vendor's words for every backend:

| `ProofKind` | SP1 | RISC Zero |
|---|---|---|
| `Native` | Core | Composite |
| `Compressed` | Compressed | Succinct |
| `Onchain` | Groth16 / Plonk | Groth16 |
| `Aggregated` |- (see aggregation.md) | - |
| `Mock` | - | - |

Both adapters expose `supported_proof_kinds() -> [ProofKind; 2]` returning
`[Native, Compressed]`, **default first** - the ordering is load-bearing,
because `ProvingOptions::resolve_kind` treats the first entry as the default
for an unset request.

## Per-backend detail

### Mock (`BackendId::Mock`, discriminant 0)

Development only. Performs **no cryptography**. Its proofs are `ProofKind::Mock`
artifacts carrying a plain digest, and `verify` recomputes that digest - which
detects accidental corruption and nothing else, since the construction is public
and keyless. Anyone can forge one.

Three independent guards make a mock artifact useless outside the mock backend:

1. `BackendId::Mock.is_cryptographic()` is `false`.
2. Its `ProgramId` is scoped to `BackendId::Mock`, so `ZkProof::verify_binding`
   rejects it against any real program.
3. Real adapters reject a foreign backend *before* invoking their verifier.

`MockBackend::with_guest(f)` registers a real guest function, which is what
makes the portability tests meaningful rather than stub-checking.

### SP1 (`BackendId::Sp1`, discriminant 1)

- **Pinned:** `sp1-sdk 6.8.0`, feature `blocking`. Upstream MSRV 1.88.
- **Host prerequisite: `protoc`.** `sp1-prover-types`' build script fails
  without it - `brew install protobuf` on macOS.
- **The `blocking` feature is required** for the sync API used here. The
  blocking client **panics if called from inside an existing Tokio runtime**, so
  do not call the adapter from an async context without `spawn_blocking`.
- **Guest toolchain:** `sp1up` (installs the `succinct` toolchain). Not
  installed by rustup.
- **Program identity is the verifying-key hash**, via
  `ProgramId::from_u32_words(BackendId::Sp1, pk.verifying_key().hash_u32())` - 
  not a digest of the ELF. This matters: SP1's verifier binds a proof to the
  verifying key, so binding our `ProgramId` to anything else would let a proof
  of a *different* program pass our binding check.
- **Input framing:** `SP1Stdin::write_slice`, which pairs with the guest's
  `sp1_zkvm::io::read_vec()`. The SDK's serde `write` is deliberately *not*
  used - it would insert a second encoding layer on top of the canonical
  postcard framing.
- **Proof bytes** are `bincode`-serialized `SP1ProofWithPublicValues`.

### RISC Zero (`BackendId::Risc0`, discriminant 2)

- **Pinned:** `risc0-zkvm 3.0.6` with `default-features = false` and features
  `client, prove, std`. 3.0.6 is the latest stable line; there is no 5.0.0
  release.
- **The `prove` feature is not default and must be enabled.** Without it,
  `default_prover()` panics at runtime inside `get_r0vm_path().unwrap()` - a
  runtime panic, not a compile error, which is exactly the failure mode worth
  pinning in a manifest.
- **`default-features = false` is deliberate** so the `bonsai` feature cannot
  silently route proving to a remote service when `BONSAI_API_URL` /
  `BONSAI_API_KEY` happen to be set in the environment. Remote proving should be
  an explicit choice, not an environment accident.
- **macOS host prerequisite:** either the Xcode Metal Toolchain, or set
  `RISC0_SKIP_BUILD_KERNELS=1`. Skipping kernels disables GPU acceleration;
  CPU proving is unaffected.
- **Guest toolchain:** `rzup` (installs the `risc0` toolchain).
- **Proof bytes** are `bincode`-serialized receipts.

### OpenVM (`BackendId::OpenVm`, discriminant 4) - planned

Published as `2.0.2` on crates.io. Its MSRV is 1.91.1, well above this
workspace's declared 1.85; the repo's `rust-toolchain.toml` pins the development
channel newer than the MSRV partly so OpenVM can be evaluated without a second
rustup install. No adapter exists.

### Jolt (`BackendId::Jolt`, discriminant 3) - planned

**Not published on crates.io at all.** Git-only; latest tag `v0.3.0-alpha`,
which pins Rust 1.95. Upstream's README states verbatim: "Jolt is in alpha and
is not suitable for production use at this time." A git dependency in a
published crate is not an option, so an adapter waits on a release.

### Pico (`BackendId::Pico`, discriminant 5) - planned

Brevis Pico is git-only. **Beware:** the crates.io name `pico-sdk` is an
**unrelated PicoScope oscilloscope driver**. Depending on it by name would be a
supply-chain mistake, not an integration.

## Prerequisites summary

| Need | SP1 | RISC Zero |
|---|---|---|
| Host build | `protoc` | Metal Toolchain *or* `RISC0_SKIP_BUILD_KERNELS=1` (macOS) |
| Guest build | `sp1up` | `rzup` |
| Required cargo feature | `blocking` | `prove` (not default) |
| Async caution | blocking client panics inside a Tokio runtime | - |
| Remote-proving caution | - | keep `bonsai` off via `default-features = false` |

Symptom-to-fix mapping: [troubleshooting.md](troubleshooting.md).

## What "supported" does not mean

It does not mean end-to-end proving has been executed in this repository. It has
not. The adapters compile against the pinned SDK and their unit tests pass;
end-to-end proving requires the vendor toolchain and a real guest ELF, and is
exercised by `#[ignore]`d tests (the RISC Zero one reads a guest ELF path from
`UZKVM_RISC0_TEST_ELF`) and by scheduled backend CI.
