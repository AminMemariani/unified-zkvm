# ADR-001: Workspace architecture

## Status

Accepted.

## Context

A zkVM abstraction must serve two environments that share types but share almost
nothing else:

- **The guest** runs inside the zkVM. No operating system, no std, and every
  linked byte becomes proving cycles.
- **The host** orchestrates: builds programs, proves, verifies, persists
  artifacts, emits telemetry. It wants `std`, filesystem access and `tracing`.

Both must agree exactly on proof types, program identity and wire encoding. A
single crate would force guests to link host machinery; entirely separate
codebases would let the two sides' understanding of a proof drift apart.

Additionally, each proving SDK is enormous — a multi-hundred-crate dependency
tree, plus a vendor toolchain for guest builds that rustup does not install. If
those trees sit in the default workspace, `cargo test` on a clean checkout
becomes a multi-minute, prerequisite-laden ordeal, and the project stops being
approachable.

## Decision

Split into six workspace crates plus adapter crates excluded from the workspace:

| Crate | Environment | Contents |
|---|---|---|
| `unified-zkvm-core` | `no_std + alloc`, `std` optional | shared types and formats |
| `unified-zkvm-guest` | guest | `zk_read`, `zk_commit`, `sha256` |
| `unified-zkvm-host` | `std` | `ZkHostRunner`, `Verifier`, config |
| `unified-zkvm-macros` | proc-macro | `#[entrypoint]` |
| `unified-zkvm-mock` | `std` | development backend |
| `unified-zkvm` | facade | feature-gated re-exports |
| `unified-zkvm-sp1`, `unified-zkvm-risc0` | **excluded** | real adapters |

Rules:

1. Dependencies point at core; core depends on no other workspace crate.
2. Core is `no_std + alloc`; `std` is additive only.
3. The guest crate takes no host-side dependencies.
4. Adapter crates are in the root `exclude` list with the reason stated in the
   manifest.
5. `tests/` is a workspace member with a `[lib]` named `uzkvm_test_support`, so
   the portability harness and example guests share one reference implementation.

## Consequences

### Positive

- `git clone && cargo test --workspace` works in seconds with no zkVM installed.
- Guests link only what they need; host code cannot leak into a guest by
  accident, because it is not reachable.
- Core is auditable without reading a proving SDK.
- Users pay only for the backends they enable.
- Differential portability tests compare against the *same* reference function,
  not a copy of it.

### Negative

- **Excluded crates are not covered by the default `cargo check`.** A core API
  change can break an adapter while the main test run stays green. Mitigated by
  the backend CI job — not by hope. This is the sharpest cost of the design.
- Six crates plus adapters means more manifests, more version coordination, and
  a release process with an order to it.
- Contributors must learn which crate a change belongs in.
- A change touching the host/guest contract spans several crates in one PR.
- The facade's feature matrix needs its own tests to stay honest.

## Alternatives considered

**One crate with features.** Simplest to publish, but guests would carry host
dependencies in their build graph and `no_std` correctness would rest entirely on
feature discipline.

**Adapters inside the workspace.** Better compile-time coverage, at the price of
making the default test run require `protoc`, a Metal toolchain, and several
hundred crates. That trade was rejected: an approachable test run is worth more
than automatic coverage of two crates that CI can cover explicitly.

**Guest and host in one crate, core separate.** Retains the leakage problem the
split exists to solve.
