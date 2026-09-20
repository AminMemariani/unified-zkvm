# proof-verification example

Two binaries, two processes, one proof container. The prover computes and
proves; the verifier checks the proof **without re-running the computation**.

```bash
# 1. Prove - writes a .uzkvm container (defaults to $TMPDIR/fibonacci.uzkvm)
cargo run -p proof-verification-example --bin prover

# 2. Verify - separate process, loads the container and checks it
cargo run -p proof-verification-example --bin verifier
```

Both accept an explicit path:

```bash
cargo run -p proof-verification-example --bin prover   -- /tmp/fib.uzkvm
cargo run -p proof-verification-example --bin verifier -- /tmp/fib.uzkvm
```

The verifier registers **no guest function** at all (`verifier_backend()` in
`src/guest.rs`), so it structurally cannot recompute the result. It rebuilds the
program artifact only to bind the proof to a program identity it trusts.

> The mock backend produces no cryptographic proof. This example demonstrates
> the *shape* of the trust boundary; with SP1 or RISC Zero the same code carries
> a real soundness guarantee.
