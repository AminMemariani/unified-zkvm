## What changed

<!-- A short description of the change. -->

## Why

<!-- Motivation, linked issue, or the problem this solves. -->

## Which backend(s) are affected

<!-- mock / SP1 / RISC Zero / none (core, host, guest, macros, docs). -->

## Were portability tests added?

<!-- unified-zkvm exists so an app can switch proving backends. If this changes
     shared behaviour, say how it was verified across backends (or why not). -->

## Were docs updated?

<!-- Rustdoc, capability matrix, guides. -->

## Security implications considered?

<!-- Proof soundness, input validation, unsafe code, new dependencies. -->

## Checklist

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace` passes (no zkVM toolchain required)
- [ ] Docs build: `cargo doc --workspace --no-deps`
- [ ] CHANGELOG entry added
