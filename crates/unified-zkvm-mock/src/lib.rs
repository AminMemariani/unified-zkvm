//! # ⚠️ DEVELOPMENT ONLY - THIS BACKEND PRODUCES NO PROOFS ⚠️
//!
//! [`MockBackend`] exists so that API wiring, serialization, capability gating
//! and error handling can be tested in milliseconds, without a proving SDK or a
//! vendor toolchain. It is what makes `git clone && cargo test` useful.
//!
//! # What it does not do
//!
//! It performs **no cryptography whatsoever**. Its "proofs" are
//! [`ProofKind::Mock`] artifacts carrying a plain digest, and its `verify`
//! recomputes that digest. That detects accidental corruption and nothing else:
//! anyone can forge one trivially, because the construction is public and
//! keyless.
//!
//! # Why that is safe here
//!
//! Three independent guards make a mock artifact useless outside this backend:
//!
//! 1. Its [`BackendId::Mock`] has [`BackendId::is_cryptographic`] `== false`.
//! 2. Its [`ProgramId`] is scoped to `BackendId::Mock`, so
//!    [`ZkProof::verify_binding`] rejects it against any real program.
//! 3. Real adapters reject a foreign backend before invoking their verifier.
//!
//! A mock proof therefore cannot be smuggled past an SP1 or RISC Zero verifier.
//! Not because it would fail their cryptography, but because it never reaches
//! it.
//!
//! ```
//! use unified_zkvm_mock::MockBackend;
//! use unified_zkvm_core::BackendAdapter;
//!
//! let backend = MockBackend::new();
//!
//! // The type itself tells you this is not a real proving system.
//! assert!(!backend.backend_id().is_cryptographic());
//! ```
//!
//! [`ProofKind::Mock`]: unified_zkvm_core::ProofKind::Mock
//! [`ProgramId`]: unified_zkvm_core::ProgramId
//! [`ZkProof::verify_binding`]: unified_zkvm_core::ZkProof::verify_binding

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::Instant;

use unified_zkvm_core::crypto::sha256;
use unified_zkvm_core::{
    BackendAdapter, BackendId, CapabilitySet, ExecutionResult, ProgramArtifact, ProgramId,
    ProofKind, ProofMetadata, ProvingOptions, PublicValues, ResourceUsage, VerificationWitness,
    ZkProof, ZkVmError,
};

/// The guest computation a [`MockBackend`] runs.
///
/// Takes the canonically encoded input blob and returns the bytes the guest
/// would have committed. Registering the *real* guest function here is what
/// lets the mock exercise actual business logic rather than a stub, which in
/// turn makes the portability tests meaningful.
pub type MockGuestFn = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, ZkVmError> + Send + Sync>;

/// A development backend that simulates execution without proving.
///
/// # Security
///
/// See the module documentation. This produces no cryptographic guarantee.
#[derive(Clone)]
pub struct MockBackend {
    guest: Option<MockGuestFn>,
    capabilities: CapabilitySet,
    /// Records every verification attempt, so negative tests can assert the
    /// verifier was actually reached rather than short-circuited earlier.
    verify_calls: Arc<Mutex<usize>>,
}

// Grants this adapter the right to mint a `VerificationWitness`. The trait is
// sealed upstream, so only adapters can do this - application code cannot
// manufacture "this was verified".
unified_zkvm_core::impl_verifier_identity!(MockBackend);

impl std::fmt::Debug for MockBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockBackend")
            .field("has_guest", &self.guest.is_some())
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    /// Creates a mock backend with an echo guest.
    ///
    /// The default guest commits its input unchanged, which is enough to
    /// exercise the I/O and proof plumbing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            guest: None,
            // Deliberately excludes AGGREGATION, RECURSION and every
            // acceleration bit: the mock implements none of them, and claiming
            // otherwise would make the capability system meaningless in exactly
            // the tests meant to police it.
            capabilities: CapabilitySet::MINIMUM_VIABLE | CapabilitySet::CYCLE_METRICS,
            verify_calls: Arc::new(Mutex::new(0)),
        }
    }

    /// Registers the guest computation to simulate.
    ///
    /// Supply the same function the real guest runs, so that cross-backend
    /// differential tests compare against genuine reference behaviour.
    ///
    /// ```
    /// use unified_zkvm_core::{BackendAdapter, ZkMessage};
    /// use unified_zkvm_mock::MockBackend;
    ///
    /// let backend = MockBackend::new().with_guest(|input| {
    ///     let n: u32 = ZkMessage::decode(input)?;
    ///     Ok(postcard::to_allocvec(&(n as u64 * 2)).unwrap())
    /// });
    /// # let _ = backend;
    /// ```
    #[must_use]
    pub fn with_guest<F>(mut self, f: F) -> Self
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, ZkVmError> + Send + Sync + 'static,
    {
        self.guest = Some(Arc::new(f));
        self
    }

    /// Overrides the advertised capabilities.
    ///
    /// Used by tests that need to observe how the host layer reacts to a
    /// backend lacking a capability.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Builds a program artifact from guest bytes.
    ///
    /// The identity is a domain-separated digest of the bytes - deterministic,
    /// so the same guest always yields the same [`ProgramId`].
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::InvalidProgram`] for empty input.
    pub fn build_program(&self, guest_bytes: &[u8]) -> Result<ProgramArtifact, ZkVmError> {
        let mut preimage = Vec::with_capacity(guest_bytes.len() + 24);
        preimage.extend_from_slice(b"unified-zkvm:mock:program:v1");
        preimage.extend_from_slice(&(guest_bytes.len() as u64).to_le_bytes());
        preimage.extend_from_slice(guest_bytes);

        let id = ProgramId::from_digest(BackendId::Mock, sha256(&preimage));
        ProgramArtifact::new(id, guest_bytes.to_vec())
    }

    /// How many times [`BackendAdapter::verify`] has been invoked.
    #[must_use]
    pub fn verify_call_count(&self) -> usize {
        *self
            .verify_calls
            .lock()
            .expect("mock verify counter poisoned")
    }

    fn run_guest(&self, input: &[u8]) -> Result<Vec<u8>, ZkVmError> {
        match &self.guest {
            Some(f) => f(input),
            None => Ok(input.to_vec()),
        }
    }

    /// The keyless checksum that stands in for a proof.
    ///
    /// Binds program identity and output so that tampering with either is
    /// detected. It is **not** a cryptographic proof: anyone can compute it.
    fn mock_tag(program: &ProgramArtifact, output: &[u8]) -> [u8; 32] {
        let pid = program.id().as_bytes();
        let mut preimage = Vec::with_capacity(pid.len() + output.len() + 40);
        preimage.extend_from_slice(b"unified-zkvm:mock:NOT-A-PROOF:v1");
        preimage.extend_from_slice(&(pid.len() as u64).to_le_bytes());
        preimage.extend_from_slice(pid);
        preimage.extend_from_slice(&(output.len() as u64).to_le_bytes());
        preimage.extend_from_slice(output);
        sha256(&preimage)
    }
}

impl BackendAdapter for MockBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Mock
    }

    fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    fn execute(
        &self,
        _program: &ProgramArtifact,
        input: &[u8],
    ) -> Result<ExecutionResult, ZkVmError> {
        let started = Instant::now();
        let output = self.run_guest(input)?;
        Ok(ExecutionResult {
            public_values: PublicValues::new(output)?,
            usage: ResourceUsage {
                // A simulated count, clearly proportional to input size rather
                // than a fabricated "real" measurement.
                cycles: Some(input.len() as u64),
                segments: Some(1),
                execution_time: Some(started.elapsed()),
                proving_time: None,
            },
        })
    }

    fn prove(
        &self,
        program: &ProgramArtifact,
        input: &[u8],
        options: &ProvingOptions,
    ) -> Result<ZkProof, ZkVmError> {
        // Even the mock honours the no-silent-downgrade rule, so tests of that
        // policy exercise the same code path real backends use.
        let kind = options.resolve_kind(BackendId::Mock, &[ProofKind::Mock])?;

        let started = Instant::now();
        let output = self.run_guest(input)?;
        let tag = Self::mock_tag(program, &output);

        ZkProof::new(
            BackendId::Mock,
            program.id().clone(),
            kind,
            PublicValues::new(output)?,
            tag.to_vec(),
            ProofMetadata::new()
                .with_cycles(input.len() as u64)
                .with_proving_time(started.elapsed())
                .with_backend_version(format!("mock/{}", env!("CARGO_PKG_VERSION"))),
        )
    }

    fn verify(
        &self,
        proof: &ZkProof,
        program: &ProgramArtifact,
    ) -> Result<VerificationWitness, ZkVmError> {
        *self
            .verify_calls
            .lock()
            .expect("mock verify counter poisoned") += 1;

        // Same ordering every real adapter must follow: binding first, then the
        // (here: trivial) verifier.
        proof.verify_binding(program)?;

        let expected = Self::mock_tag(program, proof.public_values_unverified().as_bytes());
        if proof.proof_bytes() != expected {
            return Err(ZkVmError::VerificationFailed {
                backend: BackendId::Mock,
                detail: Some("mock checksum mismatch".to_string()),
            });
        }

        // Reached only after both checks pass.
        //
        // The checksum above is keyless and trivially forgeable by design, so
        // this witness attests that the *mock* accepted the artifact - not that
        // anything was cryptographically proven.
        Ok(VerificationWitness::new(self))
    }

    fn backend_version(&self) -> String {
        format!("mock/{} (NOT A PROVING SYSTEM)", env!("CARGO_PKG_VERSION"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unified_zkvm_core::ZkMessage;

    fn doubling_backend() -> MockBackend {
        MockBackend::new().with_guest(|input| {
            let n: u32 = ZkMessage::decode(input)?;
            postcard::to_allocvec(&(u64::from(n) * 2)).map_err(|e| ZkVmError::Serialization {
                context: "mock guest output",
                detail: e.to_string(),
            })
        })
    }

    #[test]
    fn prove_then_verify_succeeds_and_returns_the_guest_output() {
        let backend = doubling_backend();
        let program = backend.build_program(b"doubler").unwrap();
        let input = ZkMessage::encode(&21u32).unwrap();

        let proof = backend
            .prove(&program, &input, &ProvingOptions::new(ProofKind::Mock))
            .unwrap();
        backend.verify(&proof, &program).unwrap();

        let witness = backend.verify(&proof, &program).unwrap();
        let out: u64 = proof.into_verified(witness).decode().unwrap();
        assert_eq!(out, 42);
    }

    #[test]
    fn tampering_with_the_proof_payload_is_detected() {
        let backend = doubling_backend();
        let program = backend.build_program(b"doubler").unwrap();
        let input = ZkMessage::encode(&1u32).unwrap();
        let proof = backend
            .prove(&program, &input, &ProvingOptions::new(ProofKind::Mock))
            .unwrap();

        let mut bytes = proof.proof_bytes().to_vec();
        bytes[0] ^= 0xFF;
        let forged = ZkProof::new(
            BackendId::Mock,
            program.id().clone(),
            ProofKind::Mock,
            proof.public_values_unverified().clone(),
            bytes,
            ProofMetadata::default(),
        )
        .unwrap();

        assert!(matches!(
            backend.verify(&forged, &program),
            Err(ZkVmError::VerificationFailed { .. })
        ));
    }

    #[test]
    fn tampering_with_public_values_is_detected() {
        let backend = doubling_backend();
        let program = backend.build_program(b"doubler").unwrap();
        let input = ZkMessage::encode(&1u32).unwrap();
        let proof = backend
            .prove(&program, &input, &ProvingOptions::new(ProofKind::Mock))
            .unwrap();

        let forged = ZkProof::new(
            BackendId::Mock,
            program.id().clone(),
            ProofKind::Mock,
            PublicValues::new(vec![0xFF; 8]).unwrap(),
            proof.proof_bytes().to_vec(),
            ProofMetadata::default(),
        )
        .unwrap();

        assert!(matches!(
            backend.verify(&forged, &program),
            Err(ZkVmError::VerificationFailed { .. })
        ));
    }

    #[test]
    fn a_proof_of_a_different_program_is_rejected() {
        let backend = doubling_backend();
        let program_a = backend.build_program(b"program-a").unwrap();
        let program_b = backend.build_program(b"program-b").unwrap();
        let input = ZkMessage::encode(&1u32).unwrap();

        let proof = backend
            .prove(&program_a, &input, &ProvingOptions::new(ProofKind::Mock))
            .unwrap();

        assert!(matches!(
            backend.verify(&proof, &program_b),
            Err(ZkVmError::ProgramIdMismatch { .. })
        ));
    }

    #[test]
    fn program_identity_is_deterministic_across_builds() {
        let backend = MockBackend::new();
        assert_eq!(
            backend.build_program(b"same").unwrap().id(),
            backend.build_program(b"same").unwrap().id()
        );
        assert_ne!(
            backend.build_program(b"a").unwrap().id(),
            backend.build_program(b"b").unwrap().id()
        );
    }

    #[test]
    fn the_mock_does_not_claim_capabilities_it_lacks() {
        let caps = MockBackend::new().capabilities();
        assert!(!caps.contains(CapabilitySet::AGGREGATION));
        assert!(!caps.contains(CapabilitySet::SHA256_ACCEL));
        assert!(!caps.contains(CapabilitySet::KECCAK_ACCEL));
        assert!(!caps.contains(CapabilitySet::ONCHAIN_PROOF));
    }

    #[test]
    fn unsupported_proof_kinds_are_refused_even_by_the_mock() {
        let backend = MockBackend::new();
        let program = backend.build_program(b"g").unwrap();
        let err = backend.prove(
            &program,
            b"\x5a\x4b\x01\x00\x00\x00\x00\x00",
            &ProvingOptions::new(ProofKind::Onchain),
        );
        assert!(matches!(err, Err(ZkVmError::UnsupportedProofKind { .. })));
    }

    #[test]
    fn mock_artifacts_are_marked_non_cryptographic() {
        // The guard that stops a mock proof being mistaken for a real one.
        assert!(!BackendId::Mock.is_cryptographic());
        assert!(MockBackend::new()
            .backend_version()
            .contains("NOT A PROVING SYSTEM"));
    }
}
