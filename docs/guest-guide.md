# Guest guide

A guest is the program whose execution gets proven. Everything it links becomes
proving cycles, so the guest API is deliberately tiny.

## The whole API

```rust
use unified_zkvm_guest::{zk_read, zk_read_bytes, zk_commit, zk_commit_bytes, sha256};
```

| Function | Signature |
|---|---|
| `zk_read` | `fn zk_read<T: DeserializeOwned>() -> Result<T, ZkVmError>` |
| `zk_read_bytes` | `fn zk_read_bytes() -> Result<Vec<u8>, ZkVmError>` |
| `zk_commit` | `fn zk_commit<T: Serialize + ?Sized>(value: &T) -> Result<(), ZkVmError>` |
| `zk_commit_bytes` | `fn zk_commit_bytes(bytes: &[u8]) -> Result<(), ZkVmError>` |
| `sha256` | `fn sha256(input: &[u8]) -> [u8; 32]` |
| `sha256_parts` | `fn sha256_parts(parts: &[&[u8]]) -> [u8; 32]` |
| `keccak256` | `fn keccak256(input: &[u8]) -> Result<[u8; 32], ZkVmError>` - always `UnsupportedCapability` today |
| `active_backend` | `const fn active_backend() -> BackendId` |

`zk_read` is the **private witness**. `zk_commit` writes **public values** - the
part the verifier sees. Committing a secret makes it public; that is the one
mistake in this API that cryptography cannot undo for you.

## A complete guest

```rust
#![cfg_attr(any(feature = "sp1", feature = "risc0"), no_main)]

use unified_zkvm::guest::{zk_commit, zk_read};

#[unified_zkvm::entrypoint]
fn main() {
    let preimage: Vec<u8> = zk_read().expect("input");
    let digest = unified_zkvm::guest::sha256(&preimage);
    zk_commit(&digest).expect("commit");
}
```

The `#![no_main]` line is *not* emitted by the macro - an attribute macro cannot
add an inner attribute - so the guest declares it itself, gated so the same file
still runs as an ordinary binary on the host.

## What `#[entrypoint]` expands to

No magic. The macro renames your function to `__unified_zkvm_guest_main`, leaves
the body untouched, and emits the backend's entrypoint invocation:

| Feature | Emitted |
|---|---|
| `sp1` | `::sp1_zkvm::entrypoint!(__unified_zkvm_guest_main);` |
| `risc0` | `::risc0_zkvm::guest::entry!(__unified_zkvm_guest_main);` |
| neither | a plain `fn main()` calling through |

That last row is the load-bearing one: with no backend feature, the guest is a
normal binary, so `cargo run` and `cargo test` work with no zkVM installed.

The macro rejects, with a clear compile error, an entrypoint that takes
arguments ("read input inside the body with `zk_read()`") or one marked `async`
("zkVM guests are single-threaded and have no executor").

## The pattern that matters: keep business logic out of I/O

This is the single most valuable habit for a zkVM guest.

```rust
// Pure. No zkVM types. Unit-testable anywhere.
pub fn settle(order: &Order) -> Settlement {
    // ...
}

// I/O shell. Three lines, nothing worth testing.
#[unified_zkvm::entrypoint]
fn main() {
    let order: Order = unified_zkvm::guest::zk_read().expect("input");
    let settlement = settle(&order);
    unified_zkvm::guest::zk_commit(&settlement).expect("commit");
}
```

Why it pays:

- **Tests run in milliseconds instead of minutes.** Proving a guest to test its
  arithmetic is the slowest possible unit test.
- **The reference model is the same function.** The portability harness in
  `tests/` runs the real function through the mock backend, so a passing test
  means the plumbing (encode -> transport -> decode -> commit -> verify -> decode) is
  lossless - not that a stub matched a stub.
- **Portability failures get isolated.** If the pure function passes and the
  guest fails, the problem is in I/O or the backend, not your logic.

```rust
#[test]
fn settlement_nets_to_zero() {
    let s = settle(&Order::sample());
    assert_eq!(s.net(), 0);
}
```

No toolchain, no proof, no backend.

## Serialization contract

Host and guest speak canonical postcard inside a framed message:

```text
magic 0x5A 0x4B ("ZK") || u16 LE version || u32 LE length || payload
```

`ENCODING_VERSION = 1`, `MAX_MESSAGE_BYTES = 256 MiB`, little-endian throughout.

**Postcard is not self-describing.** `None::<u32>`, `0u32` and `""` all encode
to identical bytes. The consequence is a rule, not a caveat: **the host and the
guest must agree on the exact type.** Decoding the same bytes as a different
type can succeed and give you a wrong answer rather than an error. Pin your
input and output types in a crate both sides depend on.

Guest input arrives as one framed message; `zk_read::<T>()` parses the frame and
decodes `T`. `zk_read_bytes()` hands you the payload if you want to decode it
yourself.

## Crypto in a guest

`sha256` delegates to core, so the workspace has exactly one implementation - 
and a backend precompile substitutes itself underneath `sha2` through the guest
manifest's `[patch.crates-io]`.

`sha256_parts(&[a, b])` hashes several slices as if concatenated, avoiding an
allocation and the cycles to copy it. It is **plain concatenation with no domain
separation or length prefixing**: `(b"ab", b"c")` and `(b"a", b"bc")` produce
the same digest. Add framing yourself if the pieces are attacker-influenced.

`keccak256` currently returns `UnsupportedCapability`, deliberately - see
[crypto.md](crypto.md).

## Building the guest ELF

That step belongs to the vendor toolchain: `sp1up` for SP1, `rzup` for RISC
Zero. The host then turns ELF bytes into a `ProgramArtifact` with the adapter's
`build_program`, which derives the backend's *real* program identity (for SP1,
the verifying-key hash). See [host-guide.md](host-guide.md).

## Guest dependency hygiene

`unified-zkvm-guest`'s manifest carries an explicit rule: no host-side
dependencies - no async runtime, no HTTP client, no filesystem client. Apply the
same rule to your own guest crate. Every dependency is cycles, and cycles are
proving time.

## Related

- [host-guide.md](host-guide.md)
- [crypto.md](crypto.md)
- [adr/ADR-006-guest-host-separation.md](adr/ADR-006-guest-host-separation.md)
