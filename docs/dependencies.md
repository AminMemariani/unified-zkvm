# Dependency policy

A zkVM abstraction sits under security-relevant code and inside guest programs
where every linked byte becomes proving cycles. Both facts push the same way:
take as few dependencies as possible, and justify each one.

## The policy

1. **Core stays minimal.** A new direct dependency in `unified-zkvm-core`
   requires a written justification in the PR.
2. **`no_std + alloc` by default.** Guests have no operating system. `std` is an
   opt-in feature that adds `std::error::Error` impls and filesystem proof
   save/load.
3. **`default-features = false` everywhere**, with features re-enabled
   deliberately. This is not tidiness - it is how the RISC Zero adapter prevents
   `bonsai` from silently routing proving to a remote service.
4. **The guest crate takes no host-side dependencies.** No async runtime, no
   HTTP client, no filesystem client. The manifest says so in a comment.
5. **Backend SDKs are isolated** in separate crates excluded from the default
   workspace, so an application that does not use a backend never compiles its
   dependency tree.
6. **SDK versions are pinned exactly**, so an upstream release cannot change
   proving behaviour without a visible manifest change.
7. **No git dependencies in published crates.** This is why Jolt and Pico have
   no adapter - neither is on crates.io.

## Core's direct dependencies

| Crate | Why it is here | Why not hand-rolled |
|---|---|---|
| `serde` | the Rust serialization interface; users already derive it | writing a competing derive would make every user type incompatible with the ecosystem |
| `postcard` | the canonical wire codec: compact, deterministic, `no_std`, stable format | a bespoke codec means writing *and maintaining* a spec, a fuzzer and a security story for zero gain |
| `bitflags` | `CapabilitySet` | hand-rolled bit constants lose type safety, `Debug`, iteration and set algebra - see ADR-005 |
| `sha2` | program/proof digests, guest `sha256` | implementing a hash yourself in a security-relevant crate is the classic own-goal; `sha2` is also the crate backends *patch* for precompiles, which is exactly why it must be `sha2` and not a private copy |

That last column matters for `sha2`: using it by name is what lets a guest's
`[patch.crates-io]` substitute a backend precompile underneath the whole
workspace without a single `#[cfg]` in the guest API.

## The other workspace crates

| Crate | Extra dependencies | Why |
|---|---|---|
| `unified-zkvm-guest` | `serde`, `postcard` | must match the host's canonical framing exactly |
| `unified-zkvm-host` | `tracing` | facade-only when no subscriber is installed; the alternative is either no observability or a bespoke logging trait |
| `unified-zkvm-macros` | `syn`, `quote`, `proc-macro2` | unavoidable for a proc macro, and compile-time only |
| `unified-zkvm-mock` | none beyond core | it is a development backend, not a proving system |

Dev-only: `proptest` (property tests), `hex` (golden vectors), `criterion`
(benchmark harness), `anyhow` (tooling).

## Why `thiserror` is not in core

The workspace declares `thiserror 2.0` and it is available - but
`unified-zkvm-core`'s error type does **not** use it. `ZkVmError` implements
`Display` by hand and gates `std::error::Error` behind the `std` feature.

The reasons:

- **Core must be `no_std`.** Hand-writing `Display` keeps the `no_std` path
  obvious rather than feature-conditional on a derive macro.
- **Error messages are a user interface.** These messages are the first thing a
  developer sees when verification fails; they deserve to be written, not
  generated from an attribute.
- **One less proc macro in the guest's build graph.** Guests are
  compile-time-sensitive, and a proc macro is a compiled build dependency.

It is more code. It is core's error type, it changes rarely, and it is worth it.

## Adding a dependency

A PR adding one to core must state: what it does, why the standard library or
an existing dependency cannot, its `no_std` status, its own dependency count,
its licence (MIT/Apache-2.0-compatible), and its maintenance status. Dev
dependencies and adapter-crate dependencies get a lighter version of the same
question.

## Supply chain

`deny.toml` plus the security workflow cover advisories, licences, duplicate
versions and source restrictions. `Cargo.lock` is committed. Dependabot is
configured.

Two name-confusion hazards worth repeating: **`pico-sdk` on crates.io is an
unrelated PicoScope oscilloscope driver**, not Brevis Pico; and there is no
`risc0-zkvm` 5.0.0 - the stable line is 3.0.x.

## Related

- [architecture.md](architecture.md)
- [security-model.md](security-model.md#supply-chain)
- [adr/ADR-003-canonical-serialization.md](adr/ADR-003-canonical-serialization.md)
