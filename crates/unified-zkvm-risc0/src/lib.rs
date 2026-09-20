//! **RISC Zero** backend adapter, pinned to `risc0-zkvm` 3.0.6.
//!
//! This crate maps the portable [`BackendAdapter`] contract onto RISC Zero's
//! host API: image IDs become program identities, host input is written with the
//! frame protocol the guest runtime reads back, and verification always runs the
//! receipt's real verifier against the image ID.
//!
//! # What is supported
//!
//! * Execution without proving, via RISC Zero's executor (real cycle counts).
//! * [`ProofKind::Native`] (RISC Zero `Composite`) and [`ProofKind::Compressed`]
//!   (RISC Zero `Succinct`).
//! * Receipt verification through `Receipt::verify`.
//!
//! # What is not supported
//!
//! * **On-chain proofs.** Groth16 wrapping needs an x86 Docker toolchain that
//!   this adapter neither ships nor tests, so [`CapabilitySet::ONCHAIN_PROOF`]
//!   stays unset instead of being advertised and failing at runtime.
//! * **Aggregation and recursion.** No host-level API folds independent
//!   receipts, so [`BackendAdapter::aggregate`] keeps the honest default error.
//! * **Acceleration bits.** Precompile use is a guest-manifest
//!   `[patch.crates-io]` concern invisible from the host.
//!
//! # Toolchain
//!
//! Proving here runs locally with a stock Rust toolchain. *Building* a guest ELF
//! requires RISC Zero's toolchain (`rzup`); this crate only consumes ELF bytes.
//!
//! # Dependency gotchas (why the feature list looks the way it does)
//!
//! * `prove` is **not** a default feature of `risc0-zkvm`. Without it,
//!   `default_prover()` resolves an external `r0vm` binary and panics at runtime
//!   when it is missing — a failure that looks like a bug in this adapter.
//! * `default-features = false` is deliberate: the default `bonsai` feature
//!   silently routes proving to a remote service when `BONSAI_API_URL` and
//!   `BONSAI_API_KEY` are set. Proving must not leave the machine by accident.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::time::Instant;

use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};

use unified_zkvm_core::{
    BackendAdapter, BackendId, CapabilitySet, ExecutionResult, Operation, ProgramArtifact,
    ProgramId, ProofKind, ProofMetadata, ProvingOptions, VerificationWitness, PublicValues, ResourceUsage, Stage,
    ZkProof, ZkVmError,
};

/// The `risc0-zkvm` release this adapter is written and tested against.
///
/// Pinned because receipt encoding and the image-ID derivation are both
/// version-sensitive: a floating upgrade would change bytes already on disk.
pub const RISC0_VERSION: &str = "3.0.6";

/// Error type for SDK failures that arrive as `anyhow::Error`.
///
/// RISC Zero's host API returns `anyhow::Error`, which does not satisfy the
/// `std::error::Error + Send + Sync + 'static` bound [`ZkVmError::backend`]
/// requires. The message is preserved verbatim rather than discarded.
#[derive(Debug)]
pub struct Risc0SdkError(String);

impl std::fmt::Display for Risc0SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Risc0SdkError {}

impl Risc0SdkError {
    fn from_display(e: impl std::fmt::Display) -> Self {
        Self(e.to_string())
    }
}

/// Adapter driving a local RISC Zero prover.
///
/// Holds no state: prover handles are built per call because RISC Zero's
/// default prover is a reference-counted, non-`Send` handle.
#[derive(Debug, Clone, Default)]
pub struct Risc0Backend {
    _private: (),
}

impl Risc0Backend {
    /// Creates an adapter backed by the local RISC Zero prover.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Derives the program artifact — including RISC Zero's real image ID —
    /// from guest ELF bytes.
    ///
    /// The image ID is what a receipt is verified against, so binding our
    /// [`ProgramId`] to it (rather than to an arbitrary digest of the ELF) is
    /// what makes the binding check meaningful: a receipt for a different guest
    /// cannot satisfy it.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Backend`] when the bytes are not a loadable RISC
    /// Zero image.
    pub fn build_program(&self, elf_bytes: &[u8]) -> Result<ProgramArtifact, ZkVmError> {
        let image_id = compute_image_id(elf_bytes).map_err(|e| {
            ZkVmError::backend(
                BackendId::Risc0,
                Operation::Setup,
                Stage::BackendSetup,
                Risc0SdkError::from_display(e),
            )
        })?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(image_id.as_bytes());
        let id = ProgramId::from_digest(BackendId::Risc0, digest);
        ProgramArtifact::new(id, elf_bytes.to_vec())
    }

    /// The proof kinds this adapter can genuinely produce, default first.
    ///
    /// The ordering matters: [`ProvingOptions::resolve_kind`] uses the first
    /// entry as the default for an unset request.
    #[must_use]
    pub fn supported_proof_kinds() -> [ProofKind; 2] {
        [ProofKind::Native, ProofKind::Compressed]
    }

    /// Reconstructs the RISC Zero image ID stored in a program artifact.
    fn image_id(program: &ProgramArtifact) -> Result<risc0_zkvm::sha::Digest, ZkVmError> {
        compute_image_id(program.bytes()).map_err(|e| {
            ZkVmError::backend(
                BackendId::Risc0,
                Operation::Verify,
                Stage::BackendSetup,
                Risc0SdkError::from_display(e),
            )
        })
    }
}

/// Builds an executor environment carrying the host input.
///
/// `write_frame` pairs with the guest's `env::read_frame()`. RISC Zero's serde
/// `write` is intentionally avoided: it would add a second encoding layer on top
/// of the project's canonical postcard bytes.
fn env_for(input: &[u8], operation: Operation) -> Result<ExecutorEnv<'static>, ZkVmError> {
    let mut builder = ExecutorEnv::builder();
    builder.write_frame(input);
    builder.build().map_err(|e| {
        ZkVmError::backend(
            BackendId::Risc0,
            operation,
            Stage::InputEncoding,
            Risc0SdkError::from_display(e),
        )
    })
}

unified_zkvm_core::impl_verifier_identity!(Risc0Backend);

impl BackendAdapter for Risc0Backend {
    fn backend_id(&self) -> BackendId {
        BackendId::Risc0
    }

    fn capabilities(&self) -> CapabilitySet {
        // Exactly the bits this adapter implements: no aggregation, no
        // recursion, no acceleration claims, and no on-chain proof until the
        // Groth16 path is wired and tested.
        CapabilitySet::MINIMUM_VIABLE
            | CapabilitySet::CYCLE_METRICS
            | CapabilitySet::COMPRESSION
    }

    fn execute(
        &self,
        program: &ProgramArtifact,
        input: &[u8],
    ) -> Result<ExecutionResult, ZkVmError> {
        let started = Instant::now();
        let env = env_for(input, Operation::Execute)?;
        let session = risc0_zkvm::default_executor()
            .execute(env, program.bytes())
            .map_err(|e| {
                ZkVmError::backend(
                    BackendId::Risc0,
                    Operation::Execute,
                    Stage::GuestExecution,
                    Risc0SdkError::from_display(e),
                )
            })?;

        // The journal holds the guest's committed bytes verbatim. `decode()` is
        // deliberately not used: these bytes are canonical postcard written by
        // `commit_slice`, not RISC Zero's own serde encoding.
        let journal = session.journal.bytes.clone();

        Ok(ExecutionResult {
            public_values: PublicValues::new(journal)?,
            usage: ResourceUsage {
                cycles: Some(session.cycles()),
                segments: Some(session.segments.len() as u32),
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
        let kind = options.resolve_kind(BackendId::Risc0, &Risc0Backend::supported_proof_kinds())?;
        let opts = match kind {
            ProofKind::Compressed => ProverOpts::succinct(),
            _ => ProverOpts::composite(),
        };

        let env = env_for(input, Operation::Prove)?;
        let started = Instant::now();
        let info = default_prover()
            .prove_with_opts(env, program.bytes(), &opts)
            .map_err(|e| {
                ZkVmError::backend(
                    BackendId::Risc0,
                    Operation::Prove,
                    Stage::ProofGeneration,
                    Risc0SdkError::from_display(e),
                )
            })?;
        let elapsed = started.elapsed();

        let journal = info.receipt.journal.bytes.clone();
        let encoded = bincode::serialize(&info.receipt).map_err(|e| {
            ZkVmError::backend(
                BackendId::Risc0,
                Operation::Prove,
                Stage::Conversion,
                Risc0SdkError::from_display(e),
            )
        })?;

        let metadata = ProofMetadata::new()
            .with_proving_time(elapsed)
            .with_backend_version(format!("risc0-zkvm/{RISC0_VERSION}"));

        ZkProof::new(
            BackendId::Risc0,
            program.id().clone(),
            kind,
            PublicValues::new(journal)?,
            encoded,
            metadata,
        )
    }

    fn verify(
        &self,
        proof: &ZkProof,
        program: &ProgramArtifact,
    ) -> Result<VerificationWitness, ZkVmError> {
        // Binding first: a receipt that is cryptographically valid for another
        // guest must still be refused, and this check is far cheaper than the
        // verifier it guards.
        proof.verify_binding(program)?;

        let receipt: Receipt = bincode::deserialize(proof.proof_bytes()).map_err(|e| {
            ZkVmError::backend(
                BackendId::Risc0,
                Operation::Verify,
                Stage::Conversion,
                Risc0SdkError::from_display(e),
            )
        })?;

        let image_id = Risc0Backend::image_id(program)?;
        receipt
            .verify(image_id)
            .map_err(|e| ZkVmError::VerificationFailed {
                backend: BackendId::Risc0,
                detail: Some(e.to_string()),
            })?;

        // Minted only here: binding checked above, the receipt verified
        // against the real image ID. This permits reading public values.
        Ok(VerificationWitness::new(self))
    }

    fn backend_version(&self) -> String {
        format!("risc0-zkvm/{RISC0_VERSION}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_claim_only_what_is_implemented() {
        let caps = Risc0Backend::new().capabilities();
        assert!(caps.contains(CapabilitySet::PROVE));
        assert!(caps.contains(CapabilitySet::COMPRESSION));
        assert!(!caps.contains(CapabilitySet::AGGREGATION));
        assert!(!caps.contains(CapabilitySet::RECURSION));
        assert!(!caps.contains(CapabilitySet::ONCHAIN_PROOF));
        assert!(!caps.contains(CapabilitySet::SHA256_ACCEL));
        assert!(!caps.contains(CapabilitySet::KECCAK_ACCEL));
        assert!(!caps.contains(CapabilitySet::ELLIPTIC_CURVE_ACCEL));
    }

    #[test]
    fn native_is_the_default_kind_and_onchain_is_refused() {
        let kinds = Risc0Backend::supported_proof_kinds();
        assert_eq!(kinds[0], ProofKind::Native);

        let resolved = ProvingOptions::default()
            .resolve_kind(BackendId::Risc0, &kinds)
            .unwrap();
        assert_eq!(resolved, ProofKind::Native);

        assert!(matches!(
            ProvingOptions::new(ProofKind::Onchain).resolve_kind(BackendId::Risc0, &kinds),
            Err(ZkVmError::UnsupportedProofKind { .. })
        ));
    }

    #[test]
    fn program_identity_is_deterministic_and_distinguishes_guests() {
        // `compute_image_id` needs a loadable ELF, so identity determinism is
        // asserted through the ProgramId constructor here and end-to-end in the
        // ignored toolchain test below.
        let a = ProgramId::from_digest(BackendId::Risc0, [7u8; 32]);
        let b = ProgramId::from_digest(BackendId::Risc0, [7u8; 32]);
        let c = ProgramId::from_digest(BackendId::Risc0, [8u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn a_receipt_bound_to_another_program_is_rejected_before_the_sdk_runs() {
        let program = ProgramArtifact::new(
            ProgramId::from_digest(BackendId::Risc0, [1u8; 32]),
            b"elf-a".to_vec(),
        )
        .unwrap();
        let other = ProgramArtifact::new(
            ProgramId::from_digest(BackendId::Risc0, [2u8; 32]),
            b"elf-b".to_vec(),
        )
        .unwrap();

        let proof = ZkProof::new(
            BackendId::Risc0,
            program.id().clone(),
            ProofKind::Native,
            PublicValues::new(vec![1, 2, 3]).unwrap(),
            vec![0u8; 8],
            ProofMetadata::default(),
        )
        .unwrap();

        assert!(matches!(
            Risc0Backend::new().verify(&proof, &other),
            Err(ZkVmError::ProgramIdMismatch { .. })
        ));
    }

    #[test]
    #[ignore = "requires the RISC Zero vendor toolchain (rzup) and a real guest ELF"]
    fn image_id_is_stable_for_the_same_elf() {
        let backend = Risc0Backend::new();
        let elf_bytes = std::fs::read(
            std::env::var("UZKVM_RISC0_TEST_ELF").expect("set UZKVM_RISC0_TEST_ELF to a guest ELF"),
        )
        .unwrap();
        assert_eq!(
            backend.build_program(&elf_bytes).unwrap().id(),
            backend.build_program(&elf_bytes).unwrap().id()
        );
    }
}
