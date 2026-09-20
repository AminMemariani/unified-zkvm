# Benchmarks

**No benchmark numbers are published for this project yet.** This page describes
the methodology that will be used and explains what such numbers can and cannot
mean. Publishing a plausible-looking table today would be the kind of claim this
project refuses to make.

## Two very different questions

### 1. What does the abstraction cost?

This is a fair question with a measurable answer, and it is the only thing
unified-zkvm actually controls. The abstraction adds:

- canonical encoding of the input (`ZkMessage::encode`) and decoding in the
  guest,
- a capability check before each operation,
- construction of the `ZkProof` envelope and, on verify, two comparisons before
  the cryptographic verifier,
- optional container framing when a proof is persisted.

All of that is serialization and a handful of comparisons. Proving is the
dominant cost by a wide margin — measuring the overhead requires isolating it
from proving, not measuring them together.

### 2. Which backend is faster?

This is a question about the backends, not about this library, and it has no
single answer. It depends on the workload's instruction mix, which precompiles
the guest was built with, the proof kind requested, the hardware (CPU core
count, RAM, GPU availability), and the SDK version. A ranking without all of
those stated is not information.

**Abstraction overhead is not proving time.** Conflating them is the most common
error in zkVM benchmark writing: the overhead is a serialization cost, the
proving time is a cryptography cost, and they differ by orders of magnitude.

## Planned methodology

When numbers are published, they will come with all of this:

| Dimension | Reported |
|---|---|
| Hardware | CPU model, core count, RAM, GPU (or none) |
| Software | exact SDK version, adapter version, rustc version, OS |
| Workload | source of the guest, input size, cycle count |
| Proof kind | `Native` or `Compressed`, named per vendor too |
| Precompiles | the exact `[patch.crates-io]` set used |
| Metrics | cycles, wall-clock proving time, peak RSS, proof bytes, verification time |
| Statistics | repeat count, median and spread — not a single lucky run |
| Reproduction | the exact command |

Rules that come with it:

1. **Same guest source, same input, same proof kind**, or the comparison is not
   a comparison.
2. **Report cycles alongside time.** Cycles are hardware-independent and expose
   whether a difference came from the circuit or the machine.
3. **Report failures too**, including out-of-memory.
4. **Never publish a single-run number.**
5. **Never extrapolate** from one workload to "backend X is faster".

`criterion` is already a dev-dependency for host-side microbenchmarks
(encode/decode, container round-trip, capability checks) — the parts that can be
measured without a proving SDK.

## What we will not do

- Publish a leaderboard.
- Compare a backend with precompiles against one without and call it a result.
- Benchmark a backend we have not run end to end.
- Report proving numbers from a machine we cannot describe.

## Measuring your own workload

This is the useful version, and the abstraction is designed to make it cheap:

1. Write the guest once against the portable API.
2. Use `runner.execute(&program, &input)` to get an `ExecutionResult` whose
   `ResourceUsage` carries cycles and execution time — **without proving**.
   Cycle count is the best early signal.
3. Compile each adapter you are considering and prove the same input.
4. Record everything in the table above.
5. Decide from your numbers on your hardware.

Note `execute`'s public values are **not proven**; it is a measurement and
debugging tool, never a source of trusted output.

## Related

- [backend-comparison.md](backend-comparison.md) — facts, no rankings
- [crypto.md](crypto.md) — why precompiles dominate hashing costs
- [host-guide.md](host-guide.md)
