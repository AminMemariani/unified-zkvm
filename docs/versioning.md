# Versioning policy

Semantic versioning, with one extra rule that matters more than the Rust API:
**a deployed guest ELF cannot be renegotiated.** Bytes on the wire and bytes on
disk are part of the public interface.

## Pre-1.0

While `0.x`, breaking changes may land in a minor release (`0.1 -> 0.2`), as
cargo's `0.x` semantics already imply. Every breaking change is still listed in
[../CHANGELOG.md](../CHANGELOG.md) with a migration note.

## What counts as breaking

### 1. Canonical encoding

`ENCODING_VERSION` (currently `1`), the frame layout
(`magic || u16 version || u32 length || payload`), the magic bytes
`0x5A 0x4B`, little-endian ordering, and the postcard payload encoding.

Any change to the bytes a guest reads or commits is breaking, **even if every
round-trip test still passes.** That is exactly why the golden vectors exist:
round-trip tests prove the codec is self-consistent, not that it is unchanged. A
golden-vector failure is a semver signal, not a flaky test.

### 2. Proof container format

`PROOF_CONTAINER_VERSION` (currently `1`), the magic `UZKVMPRF`, and the header
layout (`magic || u16 version || u16 backend || u32 body len || body`). Stored
proofs must keep loading, or the version must be bumped and old versions
explicitly handled.

### 3. Verification semantics

Any change to what verification accepts or rejects - the check order, the
binding rules, the meaning of `VerifiedPublicValues`. **Loosening is breaking.**
Tightening may also be breaking for callers who relied on the looser behaviour,
and is documented loudly either way; correctness wins, but silently is never an
option.

### 4. Program-ID representation

How a `ProgramId` is derived per backend (for SP1, the verifying-key hash).
Changing the derivation invalidates every stored identity and every proof bound
to one.

### 5. Backend discriminants

`BackendId` numeric values are written into proof containers: Mock=0, Sp1=1,
Risc0=2, Jolt=3, OpenVm=4, Pico=5. **Never reused, never renumbered.** Adding a
new backend with a new number is additive; changing an existing one is breaking
in the worst way, because old containers would decode to the wrong backend
rather than failing.

### 6. Rust API

Ordinary semver: removing or renaming public items, changing signatures,
narrowing trait bounds, adding required trait methods.

## What is not breaking

- Adding a `BackendId` with a fresh discriminant (the enum is `#[non_exhaustive]`).
- Adding a `CapabilitySet` bit.
- Adding a variant to a `#[non_exhaustive]` enum (`ZkVmError`, `ProofKind`,
  `BackendId`) or a field to a `#[non_exhaustive]` struct (`RunnerConfig`).
- Adding a defaulted trait method to `BackendAdapter`.
- Adding a builder method.
- **A backend claiming a capability it newly implements and tests** - that is
  additive, and it is the intended way for `*_ACCEL`, `AGGREGATION` or
  `ONCHAIN_PROOF` to appear.
- Changing proof *size* or *proving time*. Performance is explicitly not part of
  the contract.
- Changing adapter status from `Planned` -> `Supported` -> `Stable`.

## SDK version bumps

Adapters pin exact SDK versions. A bump is a visible change, released as:

- **patch** - the SDK patch release changes nothing observable here;
- **minor** - new capability or behaviour, additive;
- **breaking** - the SDK changes proof format, identity derivation or
  verification semantics. This is common in a fast-moving field and is not
  treated as an inconvenience to paper over.

The pinned versions today are `sp1-sdk 6.8.0` and `risc0-zkvm 3.0.6`.

## MSRV

Declared MSRV is **1.85** for the workspace core (core, guest, host, macros,
mock, facade). Raising it is a minor-version change and is called out in the
changelog.

The `rust-toolchain.toml` pin is the *development* toolchain and is deliberately
newer than the MSRV - partly so OpenVM (MSRV 1.91.1) can be evaluated without a
second rustup install. Do not read it as the MSRV.

Backend SDKs carry their own, higher MSRVs (SP1 1.88; Jolt's alpha pins 1.95).
Those apply only when you build that adapter.

## Deprecation

Deprecated items get a `#[deprecated]` attribute naming the replacement, survive
at least one minor release, and are listed in the changelog. Anything
security-relevant may be removed faster, with the reason stated.

## Related

- [../CHANGELOG.md](../CHANGELOG.md)
- [backend-compatibility.md](backend-compatibility.md)
- [adr/ADR-003-canonical-serialization.md](adr/ADR-003-canonical-serialization.md)
