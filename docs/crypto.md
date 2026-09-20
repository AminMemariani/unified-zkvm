# Crypto in guests

Hashing inside a zkVM is not like hashing on a CPU. Every bit of the computation
must be proven, so a hash that costs microseconds natively can dominate a
proof's cost. This is why the crypto API here is small and honest rather than
broad.

## Accelerated vs portable

| Implementation | What it is | Cost |
|---|---|---|
| **Portable** | ordinary Rust (`sha2`) compiled to RISC-V and proven instruction by instruction | high, proportional to the circuit work |
| **Accelerated** | a backend precompile: the zkVM has a dedicated circuit for the primitive, invoked by syscall | dramatically lower — but backend-specific |

`CryptoSupport` reports which one you get:

```rust
use unified_zkvm_core::{CryptoPrimitive, CryptoSupport};

let support = CryptoSupport::from_capabilities(backend.capabilities());
let impl_kind = support.implementation(CryptoPrimitive::Sha256);
let fast = support.is_accelerated(CryptoPrimitive::Sha256);
```

`CryptoSupport::portable_only()` is the conservative constructor. Derivation
from capabilities is the important part: the report follows the `*_ACCEL` bits,
and those bits follow tested reality.

## How precompiles actually work

Acceleration is **not a host setting and not a runtime switch**. It is a *build*
decision made in the guest crate's manifest:

```toml
# In the GUEST crate's Cargo.toml — illustrative, consult your backend's docs
[patch.crates-io]
sha2 = { git = "...", tag = "..." }   # backend-patched sha2
```

The patched crate keeps the same API but calls the zkVM's syscall instead of
executing the compression function in software. Your guest code does not change;
its dependency graph does.

Two consequences follow, and they explain most of this file:

1. **The host cannot know.** A `ProgramArtifact` is ELF bytes. Nothing in the
   host adapter can tell whether that ELF was built with a patched `sha2`.
   Advertising `SHA256_ACCEL` from the host would be a guess.
2. **Portability has a seam here.** The patch set differs per backend, so the
   *manifest* is backend-specific even when the *code* is not. This is one of
   the places where "write once" means the source, not the build.

## `sha256`

```rust
pub fn sha256(input: &[u8]) -> [u8; 32]
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32]
```

`unified_zkvm_guest::sha256` delegates to `unified_zkvm_core::crypto::sha256`,
so the workspace holds exactly one SHA-256 implementation — and a precompile
substitutes itself underneath it through `[patch.crates-io]`. There is no
`#[cfg]` ladder in the guest API, because there does not need to be.

`sha256_parts` hashes several slices as if concatenated without materialising
the concatenation — in a guest, that means avoiding an allocation and the cycles
to copy it.

> **Security note.** `sha256_parts` is plain concatenation with **no domain
> separation and no length prefixing**. `(b"ab", b"c")` and `(b"a", b"bc")`
> produce the same digest. If the pieces are attacker-influenced, add your own
> framing first.

## Why `keccak256` returns `UnsupportedCapability`

```rust
pub fn keccak256(_input: &[u8]) -> Result<[u8; 32], ZkVmError>
```

It always returns `UnsupportedCapability { backend, capability: KeccakAccel }`.
That is a deliberate choice, not an unfinished function.

Keccak-256 is only worth using inside a guest when a backend precompile proves
it. A portable software Keccak is so expensive to prove that shipping one would
be a trap rather than a feature: it would work in tests, pass review, and then
cost a fortune in cycles in production. Wiring the real precompiles
(`risc0-circuit-keccak`, SP1's keccak syscall) requires guest-side toolchain
support this crate does not yet verify — and shipping an unaccelerated fallback
under an accelerated-looking name would violate the project rule that a
capability bit means a tested implementation.

So the function fails loudly, and `CryptoSupport` reports Keccak-256 honestly.
Tracked in [../ROADMAP.md](../ROADMAP.md).

**If you need Keccak today:** compute it on the host outside the proof, or use
the backend SDK directly through the escape hatch in a clearly isolated,
non-portable module, and measure the cycle cost before committing to it.

## Elliptic curves

No curve operations are exposed. `ELLIPTIC_CURVE_ACCEL` exists as a capability
bit for a future adapter to claim, and no adapter claims it. Curve work inside a
guest today means using backend-specific patched crates directly.

## Choosing what to prove

The cheapest cryptography in a guest is the cryptography you do not do there.
Before hashing inside the proof, ask whether the hash could be computed on the
host and *committed* as a public value instead — the guest only needs to prove
the parts whose correctness is actually in question.

## Related

- [backend-compatibility.md](backend-compatibility.md) — which bits are set
- [guest-guide.md](guest-guide.md)
- [benchmarks.md](benchmarks.md) — why no numbers are published yet
