//! The **prover** side of the trust boundary.
//!
//! Runs the guest, proves it, and writes a self-contained `.uzkvm` proof
//! container to disk. After this process exits, the proof is the only thing
//! that crosses to the verifier — no shared memory, no shared state, no
//! re-running the computation.
//!
//! Run it:
//!
//! ```text
//! cargo run -p proof-verification-example --bin prover
//! ```

use std::env;

use anyhow::Result;
use unified_zkvm_core::container;
use unified_zkvm_host::ZkHostRunner;
use uzkvm_test_support::{FibonacciInput, FibonacciOutput};

use proof_verification_example::guest::{program, prover_backend};

fn main() -> Result<()> {
    let out_path = env::args().nth(1).unwrap_or_else(|| {
        env::temp_dir()
            .join("fibonacci.uzkvm")
            .display()
            .to_string()
    });

    let backend = prover_backend();
    let artifact = program(&backend)?;
    let runner = ZkHostRunner::new(backend);

    let input = FibonacciInput { n: 20 };
    let proof = runner.prove(&artifact, &input)?;

    // Sanity check locally — the prover may decode its own claim, because it
    // already knows the answer. The verifier must not.
    let claimed: FibonacciOutput = proof.public_values_unverified().decode_unverified()?;

    container::save(&proof, &out_path)?;

    println!("unified-zkvm prover");
    println!();
    println!("  program id  : {}", artifact.id().short_hex());
    println!("  input n     : {}", input.n);
    println!("  claimed     : fib({}) = {}", claimed.n, claimed.value);
    println!("  proof kind  : {}", proof.kind());
    println!("  proof size  : {} bytes", proof.size_bytes());
    println!("  written to  : {out_path}");
    println!();
    println!("  next: cargo run -p proof-verification-example --bin verifier -- {out_path}");

    Ok(())
}
