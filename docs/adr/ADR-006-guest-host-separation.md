# ADR-006: Guest/host separation

## Status

Accepted.

## Context

Guest and host code have opposite constraints.

A guest runs inside the zkVM: no operating system, no threads, no async
executor, no network, no filesystem. Critically, **every instruction it executes
must be proven**, so a dependency is not merely disk space - it is proving time
and money.

A host is an ordinary program: it wants `std`, file I/O, `tracing`, possibly an
async runtime, and it does not care much about its own binary size.

They must nevertheless agree exactly on proof types, program identity, error
types and wire format. Getting that agreement while keeping the two environments
apart is the design problem.

The other half of the problem is testability. If guest logic can only run inside
a zkVM, then testing a business rule means building an ELF with a vendor
toolchain and generating a proof - turning a millisecond unit test into a
multi-minute ordeal. Teams respond by not testing.

## Decision

1. **Separate crates**: `unified-zkvm-guest` and `unified-zkvm-host`, both
   depending on `unified-zkvm-core`.
2. **The guest crate takes no host-side dependencies** - no async runtime, no
   HTTP client, no filesystem client. Stated as a rule in its manifest.
3. **Core is `no_std + alloc`** with `std` as an additive feature, so the same
   proof and message types exist on both sides.
4. **The guest runtime is a trait**, `GuestRuntime`, with implementations
   selected by feature: `Sp1Runtime` (`sp1`), `Risc0Runtime` (`risc0`), and
   `HostTestRuntime` when no backend feature is enabled.
5. **The no-backend default is the host-test runtime.** `HostTestRuntime`
   provides `set_input`, `take_output` and `reset`, so guest code runs under
   plain `cargo test`.
6. **`#[entrypoint]` emits the backend's ritual**, or a plain `fn main()` when no
   backend is selected - so a guest file is also an ordinary binary.
7. **The guide teaches the pattern**: pure business logic in functions, a
   three-line I/O shell in the entrypoint.

## Consequences

### Positive

- Guest logic is unit-testable with no zkVM, no toolchain and no proof. This is
  the single biggest developer-experience win in the project.
- The portability harness runs the *real* guest function through the mock
  backend, so a passing test means the whole encode → transport → decode →
  commit → verify → decode path is lossless - not that two stubs agreed.
- Host machinery cannot accidentally enter a guest build; it is not reachable.
- Guests stay small, and small guests prove faster.
- One shared core means a proof means the same thing on both sides.

### Negative

- **Three runtimes to keep in sync.** A change to guest I/O semantics must be
  mirrored in SP1, RISC Zero and host-test implementations, and the host-test
  one is the one that never runs in a real zkVM.
- **The host-test runtime is not a zkVM.** It proves nothing about cycle counts,
  memory limits or precompile behaviour. It validates logic and plumbing only,
  and the guide says so.
- Feature-gated runtime selection means feature combinations must be tested;
  enabling two backends at once is a compile error, which is correct but needs a
  clear message.
- Shared types must live in core even when only one side uses them, which
  occasionally makes core carry something that feels host-shaped.
- Contributors must think about which side a change belongs to.

## Alternatives considered

**One crate with `#[cfg]`.** Fewer crates, but guest builds would carry host
dependency declarations, and `no_std` correctness would rest on feature
discipline alone.

**Guest code calls SDK APIs directly.** No abstraction to maintain - and no
portability, plus guest logic that cannot be tested without a toolchain.

**Mocking the zkVM with a trait object at runtime.** Dynamic dispatch and a
vtable in the guest, where every instruction is proven. Compile-time selection
costs nothing at runtime, which matters far more here than elsewhere.
