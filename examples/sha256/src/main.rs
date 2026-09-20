//! Hash bytes inside the guest and commit the digest.
//!
//! Demonstrates:
//!
//! * A guest that consumes a variable-length `Vec<u8>` and commits a
//!   `[u8; 32]` digest plus the preimage length (so the digest cannot be
//!   reinterpreted against a different-length preimage).
//! * Cross-checking the committed digest against the host-side
//!   [`unified_zkvm_core::crypto::sha256`].
//! * The trust boundary: the digest is a claim until `verify` returns.
//!
//! Run it:
//!
//! ```text
//! cargo run -p sha256-example
//! ```

use anyhow::{bail, Result};
use unified_zkvm_core::crypto::sha256;
use unified_zkvm_core::{ZkMessage, ZkVmError};
use unified_zkvm_host::ZkHostRunner;
use unified_zkvm_mock::MockBackend;
use uzkvm_test_support::{sha256_of, Sha256Input, Sha256Output};

fn guest(input: &[u8]) -> Result<Vec<u8>, ZkVmError> {
    let parsed: Sha256Input = ZkMessage::decode(input)?;
    let output = sha256_of(&parsed);
    postcard::to_allocvec(&output).map_err(|e| ZkVmError::Serialization {
        context: "sha256 guest output",
        detail: e.to_string(),
    })
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn main() -> Result<()> {
    let backend = MockBackend::new().with_guest(guest);
    let program = backend.build_program(b"sha256-guest")?;
    let runner = ZkHostRunner::new(backend);

    let message = b"the quick brown fox jumps over the lazy dog".to_vec();
    let input = Sha256Input {
        data: message.clone(),
    };

    let proof = runner.prove(&program, &input)?;

    println!("unified-zkvm sha256 example");
    println!();
    println!("  preimage     : {} bytes", message.len());
    println!("  proof kind   : {}", proof.kind());
    println!("  proof size   : {} bytes", proof.size_bytes());
    println!();
    println!("  NOTE: the proof carries a *claimed* digest. It is only");
    println!("  trustworthy AFTER `verify` succeeds — never decode");
    println!("  `public_values_unverified()` and act on it.");
    println!();

    let verified = runner.verify(&proof, &program)?;
    let output: Sha256Output = verified.decode()?;

    // Independent host-side cross-check: the guest and the host must agree.
    let host_digest = sha256(&message);
    if output.digest != host_digest || output.len != message.len() as u64 {
        bail!("guest digest disagreed with the host-side sha256 — this is a bug");
    }

    println!("  verified ✓");
    println!("  committed digest : {}", hex32(&output.digest));
    println!("  host sha256      : {}", hex32(&host_digest));
    println!("  committed length : {}", output.len);
    println!("  guest and host agree.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_digest_matches_host_sha256() {
        let input = Sha256Input {
            data: b"abc".to_vec(),
        };
        assert_eq!(sha256_of(&input).digest, sha256(b"abc"));
    }
}
