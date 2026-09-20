//! The **verifier** side of the trust boundary.
//!
//! This process loads a `.uzkvm` container produced by `prover` and verifies
//! it. It deliberately does **not** re-run the computation - it never even
//! registers the guest function. That is the entire point of a proof: the
//! verifier learns the result is correct without doing the work.
//!
//! Run it:
//!
//! ```text
//! cargo run -p proof-verification-example --bin verifier -- /path/to/fibonacci.uzkvm
//! ```

use std::env;

use anyhow::Result;
use unified_zkvm_core::container;
use unified_zkvm_host::ZkHostRunner;
use uzkvm_test_support::FibonacciOutput;

use proof_verification_example::guest::{program, verifier_backend};

fn main() -> Result<()> {
    let path = env::args().nth(1).unwrap_or_else(|| {
        env::temp_dir()
            .join("fibonacci.uzkvm")
            .display()
            .to_string()
    });

    let proof = container::load(&path)?;

    // The verifier reconstructs the program identity from the guest bytes it
    // trusts. Verifying against "whatever program the proof names" would be no
    // check at all, which is why `verify` requires the artifact.
    let backend = verifier_backend();
    let artifact = program(&backend)?;
    let runner = ZkHostRunner::new(backend);

    println!("unified-zkvm verifier");
    println!();
    println!("  loaded      : {path}");
    println!("  backend     : {}", proof.backend());
    println!("  program id  : {}", proof.program_id().short_hex());
    println!("  proof kind  : {}", proof.kind());
    println!("  proof size  : {} bytes", proof.size_bytes());
    println!();

    let verified = runner.verify(&proof, &artifact)?;
    let output: FibonacciOutput = verified.decode()?;

    println!("  verified yes");
    println!("  fib({}) = {}", output.n, output.value);
    println!();
    println!("  this process never computed a Fibonacci number; it only");
    println!("  checked the proof. NOTE: the mock backend is NOT cryptographic");
    println!(" - with a real backend this check carries a soundness guarantee.");

    Ok(())
}
