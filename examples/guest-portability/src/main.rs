//! **One guest function, many backends.**
//!
//! This is the centrepiece example. The application logic lives in exactly one
//! place - [`compute`] - and every backend path below calls *that same
//! function*. Nothing in `compute` knows or cares which proving system is
//! underneath; switching backends changes the adapter you construct, not a
//! single line of business logic.
//!
//! ```text
//!                       fn compute(FibonacciInput) -> FibonacciOutput
//!                                      │
//!             ┌──────────────┬─────────┴────────┬──────────────┐
//!             ▼              ▼                  ▼              ▼
//!        native call    mock backend        SP1 adapter   RISC Zero adapter
//!         (reference)   (always built)      (feature sp1) (feature risc0)
//! ```
//!
//! # Honesty rule
//!
//! Only a backend that **actually ran and matched** gets a `yes`. Backends whose
//! adapter is not compiled into this build print `-` and the reason. A report
//! that green-checks a backend that never executed is worse than no report.
//!
//! Run it:
//!
//! ```text
//! cargo run -p guest-portability-example
//! ```

use anyhow::{bail, Result};
use unified_zkvm_core::{ZkMessage, ZkVmError};
use unified_zkvm_host::ZkHostRunner;
use unified_zkvm_mock::MockBackend;
use uzkvm_test_support::{fibonacci, FibonacciInput, FibonacciOutput};

/// **The shared guest logic.** Every backend path runs this exact function.
fn compute(input: FibonacciInput) -> FibonacciOutput {
    fibonacci(input)
}

/// The thin guest wrapper: decode -> [`compute`] -> commit. Identical in shape
/// for every backend, which is why the wrapper can be shared too.
fn guest(input: &[u8]) -> Result<Vec<u8>, ZkVmError> {
    let parsed: FibonacciInput = ZkMessage::decode(input)?;
    postcard::to_allocvec(&compute(parsed)).map_err(|e| ZkVmError::Serialization {
        context: "portability guest output",
        detail: e.to_string(),
    })
}

/// One row of the comparison table.
struct Row {
    backend: &'static str,
    /// `Some(output)` when the backend actually ran; `None` when it is absent.
    outcome: Option<FibonacciOutput>,
    note: String,
}

fn main() -> Result<()> {
    let input = FibonacciInput { n: 20 };
    let mut rows = Vec::new();

    // (a) Native reference: plain Rust, no zkVM anywhere.
    rows.push(Row {
        backend: "reference",
        outcome: Some(compute(input)),
        note: "plain native call".to_string(),
    });

    // (b) Mock backend through the full host runner pipeline.
    let backend = MockBackend::new().with_guest(guest);
    let program = backend.build_program(b"portability-guest")?;
    let runner = ZkHostRunner::new(backend);
    let (proof, verified) = runner.prove_and_verify(&program, &input)?;
    let mock_output: FibonacciOutput = verified.decode()?;
    rows.push(Row {
        backend: "mock",
        outcome: Some(mock_output),
        note: format!("{} proof, {} bytes", proof.kind(), proof.size_bytes()),
    });

    // (c) SP1 - compiled in only with `--features sp1`, which additionally
    // requires the excluded `unified-zkvm-sp1` adapter crate and `protoc`.
    #[cfg(feature = "sp1")]
    {
        // The application code below is byte-for-byte the mock path except for
        // the adapter constructor - that is the entire portability claim.
        //
        //   let backend = unified_zkvm_sp1::Sp1Backend::new();
        //   let program = backend.build_program(SP1_GUEST_ELF)?;
        //   let runner  = ZkHostRunner::new(backend);
        //   let (_proof, verified) = runner.prove_and_verify(&program, &input)?;
        //   let out: FibonacciOutput = verified.decode()?;
        compile_error!(
            "the `sp1` feature needs the excluded `unified-zkvm-sp1` adapter; \
             see `cargo run -p xtask -- backend-check`"
        );
    }
    #[cfg(not(feature = "sp1"))]
    rows.push(Row {
        backend: "sp1",
        outcome: None,
        note: "adapter not compiled in (feature `sp1`)".to_string(),
    });

    // (d) RISC Zero - same story; needs `RISC0_SKIP_BUILD_KERNELS=1` on macOS.
    #[cfg(feature = "risc0")]
    {
        //   let backend = unified_zkvm_risc0::Risc0Backend::new();
        //   let program = backend.build_program(RISC0_GUEST_ELF)?;
        //   let runner  = ZkHostRunner::new(backend);
        //   let (_proof, verified) = runner.prove_and_verify(&program, &input)?;
        //   let out: FibonacciOutput = verified.decode()?;
        compile_error!(
            "the `risc0` feature needs the excluded `unified-zkvm-risc0` adapter; \
             see `cargo run -p xtask -- backend-check`"
        );
    }
    #[cfg(not(feature = "risc0"))]
    rows.push(Row {
        backend: "risc0",
        outcome: None,
        note: "adapter not compiled in (feature `risc0`)".to_string(),
    });

    let expected = compute(input);

    println!("unified-zkvm guest portability");
    println!();
    println!("  shared guest logic: fn compute(FibonacciInput) -> FibonacciOutput");
    println!("  input             : n = {}", input.n);
    println!();
    println!("  {:<12} {:<4} {:<16} note", "backend", "", "fib(n)");

    let mut ran = Vec::new();
    let mut mismatch = false;
    for row in &rows {
        match row.outcome {
            Some(out) => {
                let agrees = out == expected;
                mismatch |= !agrees;
                ran.push(row.backend);
                println!(
                    "  {:<12} {:<4} {:<16} {}",
                    row.backend,
                    if agrees { "yes" } else { "no" },
                    out.value,
                    row.note
                );
            }
            None => println!("  {:<12} {:<4} {:<16} {}", row.backend, "-", "-", row.note),
        }
    }

    println!();
    println!("  backends that actually participated: {}", ran.join(", "));
    if mismatch {
        bail!("backend outputs disagreed - portability is broken");
    }
    println!("  all participating backends agree. Absent backends are marked `-`,");
    println!("  never checked: a report must not claim a run that never happened.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backend_agrees_with_the_native_call() {
        let input = FibonacciInput { n: 30 };
        let backend = MockBackend::new().with_guest(guest);
        let program = backend.build_program(b"portability-guest").unwrap();
        let runner = ZkHostRunner::new(backend);
        let (_proof, verified) = runner.prove_and_verify(&program, &input).unwrap();
        let out: FibonacciOutput = verified.decode().unwrap();
        assert_eq!(out, compute(input));
    }
}
