# Releasing

How to publish `unified-zkvm` to crates.io.

## Before you start

Publishing is **irreversible**. A version number can never be reused or
re-uploaded, and a crate cannot be deleted, only yanked. Yanking hides a version
from new dependents; it does not remove it. Get the dry run green first.

## One-time setup

Create a token at <https://crates.io/settings/tokens> with the **publish-new**
and **publish-update** scopes, then:

```bash
cargo login
```

The token lands in `~/.cargo/credentials.toml`. Never commit it, and never pass
it on a command line where it would reach your shell history.

## Publication order

The crates form a dependency chain, and each one must exist on crates.io before
anything that depends on it can be published. The order is not optional:

```text
unified-zkvm-core          (no internal deps)
  |-- unified-zkvm-macros  (no internal deps, independent)
  |-- unified-zkvm-guest   -> core
  |-- unified-zkvm-host    -> core
  |-- unified-zkvm-mock    -> core
  |-- unified-zkvm-sp1     -> core
  |-- unified-zkvm-risc0   -> core
        `-- unified-zkvm   -> all of the above
```

Run them one at a time, waiting for each to appear in the index before the next:

```bash
cargo publish -p unified-zkvm-core
cargo publish -p unified-zkvm-macros
cargo publish -p unified-zkvm-guest
cargo publish -p unified-zkvm-host
cargo publish -p unified-zkvm-mock
cargo publish -p unified-zkvm-sp1
cargo publish -p unified-zkvm-risc0
cargo publish -p unified-zkvm
```

Index propagation is usually seconds but is not instant. If a publish fails with
`no matching package named ...`, the previous crate has not landed yet: wait and
retry. That error is expected in a dry run, where nothing is ever uploaded.

## Pre-flight checklist

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Then confirm every crate packages. This catches the mistakes that only appear at
publish time, such as a `readme` path outside the package directory or a
dependency carrying a `path` but no `version`:

```bash
for c in unified-zkvm-core unified-zkvm-macros unified-zkvm-guest \
         unified-zkvm-host unified-zkvm-mock unified-zkvm \
         unified-zkvm-sp1 unified-zkvm-risc0; do
  cargo package --list -p "$c" > /dev/null && echo "ok  $c"
done
```

CI runs this same loop on every pull request, so a packaging regression fails
long before release day.

Finally, verify the release is described:

- `CHANGELOG.md` has an entry for the version, with specific items.
- The version in `[workspace.package]` is what you intend to publish.
- `git tag v<version>` exists and is pushed.

## Version numbers

All crates share one version from `[workspace.package]`, so they move together.
That is deliberate: a user reading `unified-zkvm-sp1 = "0.1"` should not have to
work out which core version it pairs with.

What counts as a breaking change is defined in [versioning.md](versioning.md).
The short version: the guest encoding, the proof container format, verification
semantics, program-identity representation, and the backend discriminants are
all part of the public contract, not implementation details.

## After publishing

- Confirm docs.rs built each crate. The SP1 adapter is expected to fail there,
  because docs.rs has no `protoc`; that is recorded in its `[package.metadata.docs.rs]`.
- Create the GitHub release from the tag, with the changelog entry as the body.
- Check the rendered README on the `unified-zkvm` crate page. It is a generated
  copy with absolute links, since relative links do not resolve on crates.io.

## If something is wrong after publishing

```bash
cargo yank --version 0.1.0 unified-zkvm
```

Yanking prevents *new* dependents from selecting the version. Existing
`Cargo.lock` files keep working. Yank in reverse dependency order (facade first,
core last) so nothing is left pointing at a yanked dependency, then publish a
fixed patch version.
