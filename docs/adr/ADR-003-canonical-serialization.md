# ADR-003: Canonical serialization

## Status

Accepted.

## Context

Host and guest must agree on bytes. Every zkVM SDK has its own convention for
writing input and reading committed output, and those conventions differ. If the
abstraction adopted whichever one the current backend uses, the same guest source
would see different bytes on different backends - which would make the central
portability claim false.

The format must be: deterministic (identical value, identical bytes, always),
compact (bytes in a guest are cycles), `no_std`-capable, and stable across
versions, because **a deployed guest ELF cannot be renegotiated**.

## Decision

Use **postcard** for the payload, inside our own frame:

```text
magic 0x5A 0x4B ("ZK") ‖ u16 LE version ‖ u32 LE length ‖ payload
```

- `ENCODING_VERSION = 1`
- `HEADER_LEN = 8`
- `MAX_MESSAGE_BYTES = 256 MiB`
- little-endian throughout

The API is `ZkMessage::encode`, `frame`, `parse`, `decode`. Adapters pass framed
bytes straight through without re-encoding - SP1 uses `SP1Stdin::write_slice`,
pairing with the guest's `read_vec()`, precisely so the SDK's serde `write` does
not add a second encoding layer.

### Why postcard

- Deterministic and canonical by construction.
- Compact: varint integers, no field names, no tags.
- `no_std + alloc`, which core requires.
- A documented, stable wire format rather than an implementation detail.
- Already used across embedded Rust, so it is a maintained, reviewed codec.

Bincode was rejected: it is less compact and its stability story across versions
is weaker. JSON/CBOR were rejected: self-describing formats spend guest cycles
on field names. A bespoke codec was rejected: writing one means also writing a
spec, a fuzzer and a security story, for no gain over postcard.

### Why our own framing

Postcard alone gives no way to detect a truncated message, a version change, or
a stream that is not ours. The frame adds four things a raw payload cannot:

1. **Magic** - arbitrary bytes are rejected instead of misparsed.
2. **Version** - a format change is an explicit `UnsupportedVersion` error, not
   a best-effort parse of incompatible bytes.
3. **Length** - truncation is detected, and the declared length is checked
   against `MAX_MESSAGE_BYTES` **before allocating**, so a hostile prefix cannot
   exhaust memory.
4. **Self-containment** - a message can be stored or transported without
   out-of-band metadata.

Eight bytes. In a guest, that is negligible against what it buys.

## Consequences

### Positive

- The same guest source sees identical bytes on every backend.
- Malformed, truncated, hostile and wrong-version inputs fail loudly and early;
  covered by negative-security tests.
- Golden vectors can pin exact bytes, so an accidental format change is caught
  by a failing test rather than by a production incident.
- `no_std` works, so core is one crate for both sides.

### Negative

- **Postcard is not self-describing.** `None::<u32>`, `0u32` and `""` encode to
  identical bytes. Decoding as the wrong type can *succeed and return a wrong
  value* rather than erroring. This is the sharpest cost of the choice: host and
  guest **must** agree on the exact type, ideally by sharing one crate. It is
  documented in the guest guide and the security model, not buried.
- The 8-byte header costs cycles, however few.
- Changing the format later is semver-breaking and needs a version bump plus a
  migration path for stored data.
- Double encoding is a live hazard when writing an adapter: using an SDK's serde
  input API on top of the framed bytes silently adds a layer. Adapters must pass
  bytes through, and the guide says so.
- Non-Rust consumers need a postcard implementation to read public values.

## Alternatives considered

**Each backend's native encoding.** Zero overhead, but destroys portability and
makes cross-backend golden vectors impossible.

**Self-describing (CBOR/MessagePack).** Type-mismatch safety at the price of
guest cycles spent on names and tags, on every field, in every run.

**Protobuf.** Schema evolution and cross-language support, at the price of a
code-generation step - and `protoc`, which is already a friction point for the
SP1 adapter.
