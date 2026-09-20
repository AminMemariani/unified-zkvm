# Contributing

Thanks for considering a contribution. This project's credibility rests on being
honest about backend differences, so **accuracy outranks polish** everywhere —
in code, in capability bits, and in documentation.

## Setup

```bash
git clone https://github.com/unified-zkvm/unified-zkvm
cd unified-zkvm
cargo test --workspace
```

That is the whole setup. **No zkVM, no vendor toolchain, no `protoc` required** —
backend adapters are excluded from the default workspace precisely so this
works on a clean machine in seconds.

MSRV is **1.85** for the workspace core. `rust-toolchain.toml` pins a newer
*development* channel (partly so OpenVM's 1.91.1 MSRV can be evaluated without a
second rustup install); do not mistake it for the MSRV.

## Workspace layout

| Path | What lives there |
|---|---|
| `crates/unified-zkvm-core` | backend-neutral types, encoding, container |
| `crates/unified-zkvm-guest` | guest I/O and crypto |
| `crates/unified-zkvm-host` | runner, verifier, config |
| `crates/unified-zkvm-macros` | `#[entrypoint]` |
| `crates/unified-zkvm-mock` | development backend |
| `crates/unified-zkvm` | facade |
| `crates/unified-zkvm-sp1`, `-risc0` | adapters, **excluded** from the workspace |
| `tests/` | portability, negative-security, serialization, golden vectors |
| `docs/` | the documentation suite |

Dependencies point at core; core depends on nothing in the workspace. See
[docs/architecture.md](docs/architecture.md).

## Running tests

```bash
cargo test --workspace                 # everything that needs no zkVM
cargo test -p unified-zkvm-core        # one crate
cargo test --test portability          # one suite
cargo test --test negative_security
cargo test --test golden_vectors
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

A **golden-vector failure is never flaky.** It means the wire encoding changed,
which is semver-breaking — see [docs/versioning.md](docs/versioning.md).

## Running one backend

Adapters are outside the workspace, so build them explicitly:

```bash
brew install protobuf                                   # SP1 needs protoc
cargo test --manifest-path crates/unified-zkvm-sp1/Cargo.toml

RISC0_SKIP_BUILD_KERNELS=1 \
  cargo test --manifest-path crates/unified-zkvm-risc0/Cargo.toml
```

End-to-end proving tests are `#[ignore]`d because they need the vendor toolchain
(`sp1up`, `rzup`) and a real guest ELF; run them with `-- --ignored` once those
are installed. The RISC Zero one reads its ELF path from `UZKVM_RISC0_TEST_ELF`.

**If you change a core API, build both adapters before pushing.** They are not
covered by `cargo check --workspace` — the known cost of the exclusion.

Symptom-to-fix table: [docs/troubleshooting.md](docs/troubleshooting.md).

## Adding a backend

Follow [docs/adding-a-backend.md](docs/adding-a-backend.md) — it is a contract,
not a suggestion. The rules that get PRs sent back:

- **Capability honesty.** A bit is set only if this adapter implements it *and* a
  test exercises it. "The SDK supports it" is not sufficient.
- **`verify()` must call the SDK's real verifier**, after `verify_binding`.
- **Program identity must be what the verifier binds to** (for SP1, the
  verifying-key hash — not an ELF digest).
- **`BackendId` discriminants are never reused or renumbered.** They are written
  to disk.

## Documentation standards

Docs are part of the change, not a follow-up.

- **Explain why, not just what.** Every design choice here has a reason; surface
  it.
- **No claim you cannot demonstrate.** Banned: "fastest", "the only",
  "production-ready", "works identically on every zkVM".
- **No performance numbers** without the full methodology in
  [docs/benchmarks.md](docs/benchmarks.md).
- **Every Rust example must match a real signature.** A wrong example is worse
  than no example.
- Public items need rustdoc; add `# Errors` for fallible functions and
  `# Security` where a caller could get it dangerously wrong.
- Use relative links between docs so they work on GitHub.
- Keep mermaid diagrams simple and theme-neutral; quote labels containing
  punctuation.

## Commit conventions

Conventional Commits:

```
feat(host): add prove_and_verify
fix(core): reject container with oversized length prefix
docs(backend): document RISC Zero prove feature requirement
test(portability): cover empty public values
chore(deps): bump proptest to 1.7
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`.
Scopes: `core`, `guest`, `host`, `macros`, `mock`, `sp1`, `risc0`, `tests`,
`docs`, `deps`.

A breaking change gets `!` after the scope and a `BREAKING CHANGE:` footer
explaining the migration.

## Pull requests

1. Branch from `main`.
2. Tests and docs in the same PR as the code.
3. `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace` all green.
4. A `CHANGELOG.md` entry for anything user-visible — specific items, never
   "various improvements".
5. Fill in the PR template; say what you did **not** verify.

Security-relevant changes (verification order, binding, capability claims,
parsing bounds) get extra review and must come with negative tests.

## Release process

1. Update `CHANGELOG.md`; move `Unreleased` into a version heading.
2. Bump `workspace.package.version`.
3. Confirm MSRV and pinned SDK versions are accurate in the docs.
4. `cargo test --workspace`, then build both adapters.
5. Tag `vX.Y.Z`.
6. Publish in dependency order: `core`, `guest`, `macros`, `mock`, `host`,
   `unified-zkvm`, then the adapters.

## Reporting security issues

**Not** in a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to every project space.
