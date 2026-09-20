//! Succinct **SP1** backend adapter, pinned to `sp1-sdk` 6.8.0.
//!
//! This crate turns the portable [`BackendAdapter`] contract into real SP1 calls:
//! it derives program identity from the verifying key, writes host input in the
//! exact framing the guest runtime reads back, and delegates verification to
//! SP1's own verifier — never to a local shortcut.
//!
//! # What is supported
//!
//! * Execution without proving (SP1's executor reports real cycle counts).
//! * [`ProofKind::Native`] (SP1 `Core`) and [`ProofKind::Compressed`]
//!   (SP1 `Compressed`).
//! * Verification of both kinds through `Prover::verify`.
//!
//! # What is not supported
//!
//! * **On-chain proofs.** Groth16/PLONK wrapping needs vendor artifacts this
//!   adapter does not download or test, so [`CapabilitySet::ONCHAIN_PROOF`] is
//!   deliberately unset rather than advertised and broken.
//! * **Aggregation and recursion.** SP1 exposes no host-level API that folds
//!   independent proofs, so [`BackendAdapter::aggregate`] keeps the honest
//!   default error.
//! * **Acceleration bits.** Precompile usage is a guest-manifest
//!   `[patch.crates-io]` concern this adapter cannot observe, so no `*_ACCEL`
//!   bit is claimed.
//!
//! # Toolchain
//!
//! Host-side proving works with a stock Rust toolchain, but *building a guest*
//! ELF requires Succinct's toolchain (`sp1up`). This crate never builds guests;
//! it consumes ELF bytes you supply.
//!
//! # Runtime gotchas
//!
//! * The `blocking` feature of `sp1-sdk` spins a lazy Tokio runtime internally
//!   and **panics if called from inside an existing Tokio runtime**. Call this
//!   adapter from a plain thread, or from `spawn_blocking`.
//! * `SP1ProofWithPublicValues::bytes()` panics for Core/Compressed proofs, so
//!   this adapter serialises proofs with `bincode` instead.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;
use std::time::Instant;

use sp1_sdk::blocking::{Prover, ProveRequest, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use unified_zkvm_core::{
    BackendAdapter, BackendId, CapabilitySet, ExecutionResult, Operation, ProgramArtifact,
    ProgramId, ProofKind, ProofMetadata, ProvingOptions, PublicValues, ResourceUsage, Stage,
    ZkProof, ZkVmError,
};

/// The `sp1-sdk` release this adapter is written and tested against.
///
/// Pinned rather than floating: SP1's host API has changed shape between minor
/// releases, and a silent upgrade would change proof bytes on disk.
pub const SP1_SDK_VERSION: &str = "6.8.0";

/// Error type for failures that originate outside a typed SDK error.
///
/// Several SP1 entry points return `anyhow::Error`, which does not satisfy the
/// `std::error::Error + Send + Sync` bound [`ZkVmError::backend`] needs. Rather
/// than dropping the message, it is carried here verbatim.
#[derive(Debug)]
pub struct Sp1SdkError(String);

impl std::fmt::Display for Sp1SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Sp1SdkError {}

impl Sp1SdkError {
    fn from_display(e: impl std::fmt::Display) -> Self {
        Self(e.to_string())
    }
}

/// Adapter driving a local SP1 CPU prover.
///
/// Construction is cheap; the SP1 prover client is built per operation because
/// the blocking client is not safe to hold across a Tokio runtime boundary (see
/// the module docs).
#[derive(Debug, Clone, Default)]
pub struct Sp1Backend {
    _private: (),
}

impl Sp1Backend {
    /// Creates an adapter backed by SP1's local CPU prover.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Derives the program artifact — including SP1's real program identity —
    /// from guest ELF bytes.
    ///
    /// Identity is the verifying-key hash, not a digest of the ELF. That matters
    /// for security: the verifying key is what SP1's verifier actually binds a
    /// proof to, so binding our [`ProgramId`] to anything else would let a proof
    /// of a *different* program pass our binding check.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Backend`] if SP1 cannot set up the program (a
    /// malformed or non-SP1 ELF is the usual cause).
    pub fn build_program(&self, elf_bytes: &[u8]) -> Result<ProgramArtifact, ZkVmError> {
        let prover = ProverClient::builder().cpu().build();
        let pk = prover.setup(elf(elf_bytes)).map_err(|e| {
            ZkVmError::backend(
                BackendId::Sp1,
                Operation::Setup,
                Stage::BackendSetup,
                Sp1SdkError::from_display(e),
            )
        })?;
        let id = ProgramId::from_u32_words(BackendId::Sp1, pk.verifying_key().hash_u32());
        ProgramArtifact::new(id, elf_bytes.to_vec())
    }

    /// The proof kinds this adapter can genuinely produce, default first.
    ///
    /// Ordering is load-bearing: [`ProvingOptions::resolve_kind`] treats the
    /// first entry as the default for an unset request.
    #[must_use]
    pub fn supported_proof_kinds() -> [ProofKind; 2] {
        [ProofKind::Native, ProofKind::Compressed]
    }
}

/// Builds SP1's ELF handle from owned bytes.
fn elf(bytes: &[u8]) -> Elf {
    Elf::Dynamic(Arc::from(bytes.to_vec().into_boxed_slice()))
}

/// Writes host input using the framing the guest runtime reads.
///
/// `write_slice` pairs with the guest's `sp1_zkvm::io::read_vec()`. Using SP1's
/// serde `write` instead would insert a second encoding layer and break the
/// canonical postcard contract the rest of the project relies on.
fn stdin_for(input: &[u8]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);
    stdin
}

impl BackendAdapter for Sp1Backend {
    fn backend_id(&self) -> BackendId {
        BackendId::Sp1
    }

    fn capabilities(&self) -> CapabilitySet {
        // Only bits this adapter implements and can exercise: no aggregation,
        // no recursion, no acceleration claims, and no on-chain proof until the
        // Groth16 path is actually wired and tested.
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
        let prover = ProverClient::builder().cpu().build();
        let (public_values, report) = prover
            .execute(elf(program.bytes()), stdin_for(input))
            .run()
            .map_err(|e| {
                ZkVmError::backend(
                    BackendId::Sp1,
                    Operation::Execute,
                    Stage::GuestExecution,
                    Sp1SdkError::from_display(e),
                )
            })?;

        Ok(ExecutionResult {
            public_values: PublicValues::new(public_values.to_vec())?,
            usage: ResourceUsage {
                cycles: Some(report.total_instruction_count()),
                segments: None,
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
        let kind = options.resolve_kind(BackendId::Sp1, &Sp1Backend::supported_proof_kinds())?;

        let prover = ProverClient::builder().cpu().build();
        let pk = prover.setup(elf(program.bytes())).map_err(|e| {
            ZkVmError::backend(
                BackendId::Sp1,
                Operation::Prove,
                Stage::BackendSetup,
                Sp1SdkError::from_display(e),
            )
        })?;

        let started = Instant::now();
        let request = prover.prove(&pk, stdin_for(input));
        let proof = match kind {
            ProofKind::Compressed => request.compressed().run(),
            _ => request.core().run(),
        }
        .map_err(|e| {
            ZkVmError::backend(
                BackendId::Sp1,
                Operation::Prove,
                Stage::ProofGeneration,
                Sp1SdkError::from_display(e),
            )
        })?;
        let elapsed = started.elapsed();

        let public_values = proof.public_values.to_vec();
        let encoded = bincode::serialize(&proof).map_err(|e| {
            ZkVmError::backend(
                BackendId::Sp1,
                Operation::Prove,
                Stage::Conversion,
                Sp1SdkError::from_display(e),
            )
        })?;

        ZkProof::new(
            BackendId::Sp1,
            program.id().clone(),
            kind,
            PublicValues::new(public_values)?,
            encoded,
            ProofMetadata::new()
                .with_proving_time(elapsed)
                .with_backend_version(format!("sp1-sdk/{SP1_SDK_VERSION}")),
        )
    }

    fn verify(&self, proof: &ZkProof, program: &ProgramArtifact) -> Result<(), ZkVmError> {
        // Binding first: a cryptographically valid proof of the *wrong* program
        // must still fail, and checking that before touching the SDK keeps the
        // expensive path off the error route.
        proof.verify_binding(program)?;

        let decoded: SP1ProofWithPublicValues =
            bincode::deserialize(proof.proof_bytes()).map_err(|e| {
                ZkVmError::backend(
                    BackendId::Sp1,
                    Operation::Verify,
                    Stage::Conversion,
                    Sp1SdkError::from_display(e),
                )
            })?;

        let prover = ProverClient::builder().cpu().build();
        let pk = prover.setup(elf(program.bytes())).map_err(|e| {
            ZkVmError::backend(
                BackendId::Sp1,
                Operation::Verify,
                Stage::BackendSetup,
                Sp1SdkError::from_display(e),
            )
        })?;

        prover
            .verify(&decoded, pk.verifying_key(), None)
            .map_err(|e| ZkVmError::VerificationFailed {
                backend: BackendId::Sp1,
                detail: Some(e.to_string()),
            })
    }

    fn backend_version(&self) -> String {
        format!("sp1-sdk/{SP1_SDK_VERSION}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_claim_only_what_is_implemented() {
        let caps = Sp1Backend::new().capabilities();
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
        let kinds = Sp1Backend::supported_proof_kinds();
        assert_eq!(kinds[0], ProofKind::Native);

        let resolved = ProvingOptions::default()
            .resolve_kind(BackendId::Sp1, &kinds)
            .unwrap();
        assert_eq!(resolved, ProofKind::Native);

        assert!(matches!(
            ProvingOptions::new(ProofKind::Onchain).resolve_kind(BackendId::Sp1, &kinds),
            Err(ZkVmError::UnsupportedProofKind { .. })
        ));
    }

    #[test]
    fn a_proof_bound_to_another_program_is_rejected_before_the_sdk_runs() {
        let program = ProgramArtifact::new(
            ProgramId::from_u32_words(BackendId::Sp1, [1, 2, 3, 4, 5, 6, 7, 8]),
            b"elf-a".to_vec(),
        )
        .unwrap();
        let other = ProgramArtifact::new(
            ProgramId::from_u32_words(BackendId::Sp1, [8, 7, 6, 5, 4, 3, 2, 1]),
            b"elf-b".to_vec(),
        )
        .unwrap();

        let proof = ZkProof::new(
            BackendId::Sp1,
            program.id().clone(),
            ProofKind::Native,
            PublicValues::new(vec![1, 2, 3]).unwrap(),
            vec![0u8; 8],
            ProofMetadata::default(),
        )
        .unwrap();

        assert!(matches!(
            Sp1Backend::new().verify(&proof, &other),
            Err(ZkVmError::ProgramIdMismatch { .. })
        ));
    }

    #[test]
    #[ignore = "requires the SP1 vendor toolchain (sp1up) and a real guest ELF"]
    fn program_identity_is_deterministic_for_the_same_elf() {
        let backend = Sp1Backend::new();
        let elf_bytes = std::fs::read(
            std::env::var("UZKVM_SP1_TEST_ELF").expect("set UZKVM_SP1_TEST_ELF to a guest ELF"),
        )
        .unwrap();
        assert_eq!(
            backend.build_program(&elf_bytes).unwrap().id(),
            backend.build_program(&elf_bytes).unwrap().id()
        );
    }
}
