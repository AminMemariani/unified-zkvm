# Backend comparison

**This page contains no performance rankings and no recommendation.** Proving
performance depends on the workload, the hardware, the proof kind and the
precompiles in use, and this project has not published measurements. What
follows is documented technical fact and integration status - the things that
are true regardless of benchmark.

For why numbers are absent, see [benchmarks.md](benchmarks.md).

## At a glance

| | SP1 | RISC Zero | OpenVM | Jolt | Pico |
|---|---|---|---|---|---|
| Vendor | Succinct | RISC Zero | OpenVM | a16z | Brevis |
| Pinned / latest known | `sp1-sdk 6.8.0` | `risc0-zkvm 3.0.6` | `2.0.2` | `v0.3.0-alpha` | - |
| On crates.io | yes | yes | yes | **no** (git only) | **no** (git only) |
| Adapter here | supported | supported | planned | planned | planned |
| `BackendId` | 1 | 2 | 4 | 3 | 5 |
| Guest toolchain | `sp1up` | `rzup` | vendor | vendor | vendor |
| Upstream MSRV | 1.88 | - | 1.91.1 | 1.95 (alpha tag) | - |

Note for anyone searching crates.io: **`pico-sdk` is an unrelated PicoScope
oscilloscope driver**, not Brevis Pico. And there is no `risc0-zkvm` 5.0.0; the
latest stable line is 3.0.x.

## Proof-kind vocabulary

Every project names the same ideas differently. `ProofKind` deliberately does
not adopt one vendor's vocabulary for all backends:

| `ProofKind` | SP1 | RISC Zero |
|---|---|---|
| `Native` | Core | Composite |
| `Compressed` | Compressed | Succinct |
| `Onchain` | Groth16 / Plonk | Groth16 |

Both adapters here expose `[Native, Compressed]`, default first. `Onchain` is
*not* claimed by either adapter - the SNARK-wrapping path needs vendor artifacts
these adapters neither download nor test.

## Program identity

| Backend | Identity is |
|---|---|
| SP1 | the verifying-key hash (`pk.verifying_key().hash_u32()`) |
| RISC Zero | the image ID |
| Mock | a digest scoped to `BackendId::Mock` |

In each case identity must be *what the verifier binds to*. Anything else makes
the binding check meaningless. See
[adding-a-backend.md](adding-a-backend.md#program-identity-must-be-the-thing-the-verifier-binds-to).

## Host integration characteristics

| | SP1 | RISC Zero |
|---|---|---|
| Sync API | `blocking` feature; panics inside a Tokio runtime | client API |
| Host build prerequisite | `protoc` | Metal Toolchain or `RISC0_SKIP_BUILD_KERNELS=1` (macOS) |
| Non-default feature required | `blocking` | `prove` - else `default_prover()` panics at runtime |
| Remote-proving risk | - | `bonsai` can route proving remotely from env vars; disabled via `default-features = false` |
| Input framing used here | `SP1Stdin::write_slice` ↔ guest `read_vec()` | receipt/env API |
| Proof serialization here | bincode | bincode |

## Aggregation ingredients

Neither SDK offers a host-level `aggregate(&[proof]) -> proof`:

| Backend | What exists |
|---|---|
| SP1 | in-guest `verify_sp1_proof`, host `SP1Stdin::write_proof`; input proofs must be compressed |
| RISC Zero | host `env::add_assumption`, in-guest `env::verify` |

Both require an application-specific aggregation guest. Details and a build
sketch: [aggregation.md](aggregation.md).

## Precompiles

Both projects ship patched crates selected through the guest manifest's
`[patch.crates-io]`. The sets differ, so the manifest is backend-specific even
when the guest source is not. No adapter here claims an `*_ACCEL` capability,
because none has been verified end to end - see [crypto.md](crypto.md).

## Maturity of the *upstream* projects

Distinct from this project's adapter status:

- **SP1** and **RISC Zero** publish stable releases on crates.io and are used in
  production by third parties.
- **OpenVM** publishes on crates.io (`2.0.2`); its MSRV of 1.91.1 is currently
  the main friction for this workspace.
- **Jolt** is git-only at `v0.3.0-alpha`, and its README states verbatim: "Jolt
  is in alpha and is not suitable for production use at this time."
- **Pico** is git-only.

## How to choose

This project does not choose for you, and would be guessing if it did. What it
can do is make the experiment cheap:

1. Write the guest once, against the portable API.
2. Compile the adapters you are considering.
3. Run *your* workload on each and measure cycles, proving time, proof size and
   peak memory on hardware you will actually deploy on.
4. Weigh the non-performance facts above: toolchain friction, on-chain needs,
   licence, upstream maturity, and how much backend-specific code you would end
   up behind the escape hatch.

Then decide with numbers you generated, not numbers someone else published.

## Related

- [backend-compatibility.md](backend-compatibility.md)
- [migrating-between-backends.md](migrating-between-backends.md)
- [benchmarks.md](benchmarks.md)
