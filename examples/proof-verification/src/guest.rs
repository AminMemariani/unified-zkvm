//! Shared guest wiring for both binaries.
//!
//! The verifier needs the program artifact (to bind the proof to a program
//! identity) but deliberately never calls the guest logic.

use unified_zkvm_core::{ProgramArtifact, ZkMessage, ZkVmError};
use unified_zkvm_mock::MockBackend;
use uzkvm_test_support::{fibonacci, FibonacciInput};

/// Name of the guest; its digest is the program identity.
pub const GUEST_NAME: &[u8] = b"proof-verification-guest";

/// The guest body: decode -> compute -> commit.
pub fn guest(input: &[u8]) -> Result<Vec<u8>, ZkVmError> {
    let parsed: FibonacciInput = ZkMessage::decode(input)?;
    postcard::to_allocvec(&fibonacci(parsed)).map_err(|e| ZkVmError::Serialization {
        context: "guest output",
        detail: e.to_string(),
    })
}

/// A backend with the guest registered. The prover needs this to prove.
pub fn prover_backend() -> MockBackend {
    MockBackend::new().with_guest(guest)
}

/// A backend with **no guest registered** - the verifier cannot run the
/// computation even by accident.
pub fn verifier_backend() -> MockBackend {
    MockBackend::new()
}

/// The program artifact, reproducible from the guest bytes alone.
pub fn program(backend: &MockBackend) -> Result<ProgramArtifact, ZkVmError> {
    backend.build_program(GUEST_NAME)
}
