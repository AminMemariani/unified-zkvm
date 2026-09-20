//! Prove and verify a Fibonacci computation end to end.
//!
//! This is the shortest complete path through the abstraction:
//!
//! 1. Write the guest logic as a **plain Rust function** ([`uzkvm_test_support::fibonacci`]).
//! 2. Register it with a backend and build a program artifact.
//! 3. `prove` on the host, then `verify` - only after verification are the
//!    public values trustworthy.
//!
//! The point of step 1 is that the business logic is an ordinary function, so
//! it can be unit-tested with `cargo test` without a zkVM in sight. See the
//! `#[test]` at the bottom of this file.
//!
//! Run it:
//!
//! ```text
//! cargo run -p fibonacci-example
//! ```

use anyhow::Result;
use unified_zkvm_core::{ZkMessage, ZkVmError};
use unified_zkvm_host::ZkHostRunner;
use unified_zkvm_mock::MockBackend;
use uzkvm_test_support::{fibonacci, FibonacciInput, FibonacciOutput};

/// The guest wrapper: decode the canonical input, call the plain function,
/// commit the output. Real SP1/RISC Zero guests have exactly this shape.
fn guest(input: &[u8]) -> Result<Vec<u8>, ZkVmError> {
    let parsed: FibonacciInput = ZkMessage::decode(input)?;
    let output = fibonacci(parsed);
    postcard::to_allocvec(&output).map_err(|e| ZkVmError::Serialization {
        context: "fibonacci guest output",
        detail: e.to_string(),
    })
}

fn main() -> Result<()> {
    let backend = MockBackend::new().with_guest(guest);
    let program = backend.build_program(b"fibonacci-guest")?;
    let runner = ZkHostRunner::new(backend);

    let input = FibonacciInput { n: 20 };

    // Execute first: no proof, but a cycle count and a fast answer.
    let executed = runner.execute(&program, &input)?;

    let (proof, verified) = runner.prove_and_verify(&program, &input)?;
    let output: FibonacciOutput = verified.decode()?;

    println!("unified-zkvm fibonacci example");
    println!();
    println!("  backend      : {}", proof.backend());
    println!("  program id   : {}", program.id().short_hex());
    println!("  n            : {}", output.n);
    println!("  fib(n)       : {}", output.value);
    println!("  proof kind   : {}", proof.kind());
    println!("  proof size   : {} bytes", proof.size_bytes());
    println!(
        "  cycles       : {}",
        executed
            .usage
            .cycles
            .map_or_else(|| "not reported".to_string(), |c| c.to_string())
    );
    println!();
    println!("  verified: the value above is safe to act on only because");
    println!("  `verify` succeeded before it was decoded.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the business logic *outside* the zkVM - the whole reason the guest
    /// body is a plain function.
    #[test]
    fn guest_logic_matches_known_values() {
        assert_eq!(fibonacci(FibonacciInput { n: 10 }).value, 55);
        assert_eq!(fibonacci(FibonacciInput { n: 20 }).value, 6765);
    }

    #[test]
    fn proving_reproduces_the_plain_function() {
        let backend = MockBackend::new().with_guest(guest);
        let program = backend.build_program(b"fibonacci-guest").unwrap();
        let runner = ZkHostRunner::new(backend);

        let input = FibonacciInput { n: 20 };
        let (_proof, verified) = runner.prove_and_verify(&program, &input).unwrap();
        let output: FibonacciOutput = verified.decode().unwrap();

        assert_eq!(output, fibonacci(input));
    }
}
