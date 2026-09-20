//! The proving seam, and the extension point for remote proving.
//!
//! # Why this trait exists separately from [`crate::ZkHostRunner`]
//!
//! Local proving is synchronous and CPU-bound. Network proving is neither. A
//! library that made everything `async` to accommodate the second case would
//! tax every user of the first, and one that hard-coded the synchronous shape
//! would make the second impossible to add without a breaking change.
//!
//! [`Prover`] threads that needle: it describes *a thing that turns a request
//! into a proof*, without saying where the work happens. A local adapter
//! implements it directly. A future network prover can implement it by blocking
//! on its own runtime, and a future async variant can be added alongside
//! without disturbing this one.
//!
//! No network prover ships today — see `ROADMAP.md`. This is the seam, not a
//! claim that the feature exists.

use unified_zkvm_core::{BackendAdapter, ProgramArtifact, ProvingOptions, ZkProof, ZkVmError};

/// Everything needed to produce one proof.
///
/// Bundled into a struct rather than passed as loose arguments so that a
/// request can be queued, logged or sent over a wire — the shapes a remote
/// prover needs.
#[derive(Debug, Clone)]
pub struct ProofRequest<'a> {
    /// The program to prove.
    pub program: &'a ProgramArtifact,
    /// Canonically encoded guest input.
    ///
    /// # Security
    ///
    /// This is the **private witness**. Do not log it, and do not transmit it
    /// to a remote prover you would not trust with the underlying secret —
    /// delegated proving necessarily reveals the witness to the prover.
    pub input: &'a [u8],
    /// Options controlling the proof produced.
    pub options: &'a ProvingOptions,
}

/// A source of proofs.
///
/// Implemented by every backend adapter through the blanket impl below, and
/// available for a future remote prover to implement directly.
pub trait Prover {
    /// Produces a proof for `request`.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedProofKind`] if the requested kind is
    /// unavailable, or [`ZkVmError::Backend`] if proving fails.
    fn prove_request(&self, request: ProofRequest<'_>) -> Result<ZkProof, ZkVmError>;

    /// Whether proving happens off this machine.
    ///
    /// Callers use this to decide whether the private witness is about to leave
    /// the host — a fact worth surfacing to a user before it happens.
    fn is_remote(&self) -> bool {
        false
    }
}

impl<T: BackendAdapter> Prover for T {
    fn prove_request(&self, request: ProofRequest<'_>) -> Result<ZkProof, ZkVmError> {
        self.prove(request.program, request.input, request.options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unified_zkvm_mock::MockBackend;

    #[test]
    fn local_backends_report_themselves_as_local() {
        let backend = MockBackend::new();
        assert!(
            !backend.is_remote(),
            "a local adapter must not claim the witness leaves the machine"
        );
    }

    #[test]
    fn a_backend_adapter_satisfies_the_prover_seam() {
        let backend = MockBackend::new();
        let program = backend.build_program(b"guest").unwrap();
        let options = ProvingOptions::default();
        let input = unified_zkvm_core::ZkMessage::encode(&7u32).unwrap();

        let proof = backend
            .prove_request(ProofRequest {
                program: &program,
                input: &input,
                options: &options,
            })
            .unwrap();

        assert_eq!(proof.program_id(), program.id());
    }
}
