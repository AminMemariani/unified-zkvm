# ADR-004: Proof representation

## Status

Accepted.

## Context

Proofs from different backends have nothing structurally in common: an SP1
`SP1ProofWithPublicValues` and a RISC Zero receipt are different types with
different internals. But an application needs to do the same things with any of
them — store, load, route to a verifier, inspect metadata, and act on the public
values *only after verification*.

Two mistakes are easy here, and both are expensive:

1. Treating a proof as "just bytes", so a proof of the wrong program or from the
   wrong backend can be handed to a verifier that has no way to notice.
2. Making public values readable as ordinary data, so application code reads
   them before anything checked them.

## Decision

Two layers: an in-memory **envelope** and an on-disk **container**.

### Envelope: `ZkProof`

```rust
ZkProof::new(backend, program_id, kind, public_values, proof_bytes, metadata)
    -> Result<ZkProof, ZkVmError>
```

Accessors: `backend()`, `program_id()`, `kind()`, `proof_bytes()`, `metadata()`,
`size_bytes()`, `digest()`, `public_values_unverified()`.

Key methods:

- `verify_binding(&program)` — checks backend match, then program-ID match.
- `into_verified() -> VerifiedPublicValues` — the only constructor for the
  verified type; the runner calls it *after* the backend's verifier succeeds.

`Debug` is implemented by hand so a proof does not dump its bytes into logs.

### Public values are type-gated

`VerifiedPublicValues` can only come from `into_verified()`. So the normal way
to read a guest's output requires having verified it. Unverified access exists —
`PublicValues::decode_unverified` — and its name is deliberately long so it
stands out in review.

### Container: on-disk format

```text
UZKVMPRF ‖ u16 version ‖ u16 backend ‖ u32 body len ‖ postcard body
```

`PROOF_CONTAINER_VERSION = 1`, `CONTAINER_HEADER_LEN = 16`,
`MAX_CONTAINER_BODY_BYTES = 512 MiB`. API: `to_bytes`, `from_bytes`,
`read_header`, and (with `std`) `save` / `load`.

The backend is in the **header**, so a proof can be routed to the right verifier
without decoding the body — and a rewritten header is caught because the decoded
backend must match the proof's own.

`BackendId::from_u16` fails closed on unknown discriminants: a corrupted or
forward-version container is never silently attributed to the wrong backend.

## Consequences

### Positive

- One type carries every backend's proof; storage and routing code is written
  once.
- Binding checks are structural and cheap, and run before cryptography, so a
  cross-backend or wrong-program proof is refused without touching an SDK
  decoder.
- The type system pushes callers through verification.
- `read_header` inspects a proof cheaply, and bounds are checked before
  allocation, so a hostile length prefix cannot exhaust memory.
- Proof metadata (cycles, proving time, backend version) travels with the proof
  for diagnostics without affecting verification.

### Negative

- **An extra layer.** Backend-native proof bytes are wrapped, so tools expecting
  a raw SDK artifact need `proof_bytes()` and knowledge of the encoding.
- The container format is now a compatibility surface: changing it is
  semver-breaking, and stored proofs must keep loading.
- `metadata` is unauthenticated — it is not covered by the proof and must never
  be trusted for a security decision. It exists for diagnostics only.
- `into_verified()` consumes the proof (the runner clones), a small ergonomic
  cost accepted in exchange for the type-level guarantee.
- Adapters must serialize native proofs themselves (both currently use bincode),
  which couples proof bytes to a serializer version.

## Alternatives considered

**Raw bytes plus out-of-band metadata.** Smallest representation, but nothing
binds the proof to a program or backend, so every consumer has to reimplement
the binding check — and one of them will forget.

**A trait object per backend proof type.** Preserves native types, prevents a
single stable on-disk format and forces dynamic dispatch on every access.

**Public values readable directly from `ZkProof`.** More convenient and exactly
the footgun this ADR is designed to remove.
