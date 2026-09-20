# Migrating between backends

The point of the abstraction is that this is a small change. It is not a
zero change, and pretending otherwise would be the exact overclaim this project
exists to avoid.

## What does not change

- **Guest business logic.** If you followed the pattern in
  [guest-guide.md](guest-guide.md) and kept pure logic out of I/O, that code is
  untouched.
- **Guest I/O calls.** `zk_read` and `zk_commit` are identical.
- **The entrypoint.** `#[entrypoint]` emits the right ritual per backend.
- **Host API.** `ZkHostRunner`, `prove`, `verify`, `prove_and_verify`,
  `RunnerConfig`, `ProvingOptions` — same calls.
- **Serialization.** The canonical postcard framing is backend-neutral, so your
  input and output types carry over byte for byte.
- **Proof container.** `container::save` / `load` work for both; the backend is
  recorded in the header.
- **Error handling.** `ZkVmError` variants are shared.

## What changes

| Thing | SP1 | RISC Zero |
|---|---|---|
| Adapter crate | `unified-zkvm-sp1` | `unified-zkvm-risc0` |
| Host type | `Sp1Backend::new()` | `Risc0Backend::new()` |
| Guest feature | `sp1` | `risc0` |
| Guest toolchain | `sp1up` (`succinct`) | `rzup` (`risc0`) |
| Host prerequisite | `protoc` | Metal Toolchain or `RISC0_SKIP_BUILD_KERNELS=1` on macOS |
| Required SDK feature | `blocking` | `prove` (not default) |
| Program identity | verifying-key hash | image ID |
| `Native` kind is called | Core | Composite |
| `Compressed` kind is called | Compressed | Succinct |
| Proof bytes | bincode `SP1ProofWithPublicValues` | bincode receipt |
| Precompile patches | SP1's patched crates | RISC Zero's patched crates |

## The diff in practice

Host:

```diff
-use unified_zkvm_sp1::Sp1Backend;
+use unified_zkvm_risc0::Risc0Backend;

-let backend = Sp1Backend::new();
+let backend = Risc0Backend::new();
 let program = backend.build_program(&elf_bytes)?;
 let runner = ZkHostRunner::new(backend);
 let (proof, verified) = runner.prove_and_verify(&program, &input)?;
```

Guest `Cargo.toml`:

```diff
-unified-zkvm = { version = "0.1", default-features = false, features = ["guest", "macros", "sp1"] }
+unified-zkvm = { version = "0.1", default-features = false, features = ["guest", "macros", "risc0"] }
```

Guest source: unchanged.

## Things that genuinely require thought

### Existing proofs do not carry over

A proof is a backend-native artifact. SP1 proofs cannot be verified by RISC
Zero, and the header check refuses the attempt before any cryptography runs. If
you have proofs in storage, plan for a dual-verification period: route by
`proof.backend()` and keep both adapters compiled in while old proofs are still
in flight.

### Program identity changes

The new backend derives identity differently, so every `ProgramId` changes. Any
system that pins an identity — a config file, an on-chain constant, an allowlist
— needs updating. Verifying an old proof against a new program yields
`ProgramIdMismatch`, which is the binding check doing its job.

### Precompiles must be re-selected

`[patch.crates-io]` entries in the guest manifest are backend-specific. Moving
backends means replacing them. Since no adapter here claims an `*_ACCEL`
capability, `CryptoSupport` will not tell you which patches are active — verify
by measuring cycles. See [crypto.md](crypto.md).

### Performance will differ

Cycle counts, proving time, proof size and memory use all change, potentially by
a lot, and in workload-dependent directions. Nothing here normalizes that.
Measure on your own workload before and after; see
[benchmarks.md](benchmarks.md).

### Backend-specific code does not move

Anything reached through `runner.backend()` is, by construction, tied to one
SDK. That is why the escape hatch belongs in one clearly named module — the
migration cost is then the size of that module, and you can see it.

## Migrating to or from the mock backend

Mock → real is the easy direction and the normal development flow: same API,
plus a real toolchain and real proving time.

Real → mock is for tests only. **Mock proofs are not proofs.** Never let a mock
artifact into a path that makes a trust decision; three guards prevent it
reaching a real verifier, but application code that inspects proofs directly
should check `BackendId::is_cryptographic()` itself.

## Running both at once

Use `DynBackend` (`Box<dyn BackendAdapter>`) to choose at runtime:

```rust
use unified_zkvm_core::backend::DynBackend;
use unified_zkvm_host::ZkHostRunner;

let backend: DynBackend = match choice {
    Choice::Sp1 => Box::new(Sp1Backend::new()),
    Choice::Risc0 => Box::new(Risc0Backend::new()),
};
let runner = ZkHostRunner::new(backend);
```

You give up inherent methods (like `build_program`) and get the trait surface
only, so build each program artifact with its concrete adapter first. Also note
each adapter compiled in pulls its full SDK tree into your build.

## Related

- [backend-compatibility.md](backend-compatibility.md)
- [backend-comparison.md](backend-comparison.md)
- [troubleshooting.md](troubleshooting.md)
