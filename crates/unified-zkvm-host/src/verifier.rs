//! Standalone verification.
//!
//! Verification is intentionally cheap to integrate: a verifying service needs
//! the proof, the program, and nothing else. It does not need the prover, the
//! input, or the ability to re-run the computation. That separation is the
//! whole point of a proof, and this module keeps it true in the API shape.
//!
//! ```no_run
//! use unified_zkvm_core::container;
//! use unified_zkvm_host::Verifier;
//! # use unified_zkvm_mock::MockBackend;
//! # fn demo(program: unified_zkvm_core::ProgramArtifact) -> Result<(), unified_zkvm_core::ZkVmError> {
//! let proof = container::load("proof.uzkvm")?;
//!
//! let verified = Verifier::new(MockBackend::new()).verify(&proof, &program)?;
//! let output: u64 = verified.decode()?;
//! # Ok(())
//! # }
//! ```

use tracing::instrument;
use unified_zkvm_core::{
    BackendAdapter, BackendId, Capability, ProgramArtifact, VerifiedPublicValues, ZkProof,
    ZkVmError,
};

/// Verifies proofs against programs.
///
/// A thin, deliberately minimal counterpart to [`crate::ZkHostRunner`] for
/// processes that only check proofs and never produce them.
#[derive(Debug, Clone)]
pub struct Verifier<B> {
    backend: B,
    backend_id: BackendId,
}

impl<B: BackendAdapter> Verifier<B> {
    /// Creates a verifier for `backend`.
    #[must_use]
    pub fn new(backend: B) -> Self {
        let backend_id = backend.backend_id();
        Self {
            backend,
            backend_id,
        }
    }

    /// Verifies `proof` against `program`.
    ///
    /// # Security
    ///
    /// The order of checks matters and is enforced by the adapter contract:
    ///
    /// 1. backend match — an SP1 proof is never handed to a RISC Zero verifier;
    /// 2. program identity match — a valid proof of the *wrong* program is
    ///    rejected;
    /// 3. cryptographic verification.
    ///
    /// Only after all three does a [`VerifiedPublicValues`] exist. There is no
    /// API that returns public values without this sequence.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedCapability`] if the backend cannot
    /// verify, [`ZkVmError::BackendMismatch`], [`ZkVmError::ProgramIdMismatch`]
    /// or [`ZkVmError::VerificationFailed`].
    #[instrument(level = "info", skip_all, fields(backend = %self.backend_id, program = %program.id()))]
    pub fn verify(
        &self,
        proof: &ZkProof,
        program: &ProgramArtifact,
    ) -> Result<VerifiedPublicValues, ZkVmError> {
        unified_zkvm_core::backend::require_capability(
            self.backend_id,
            self.backend.capabilities(),
            Capability::Verify,
        )?;
        self.backend.verify(proof, program)?;
        Ok(proof.clone().into_verified())
    }

    /// The backend performing verification.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }
}
