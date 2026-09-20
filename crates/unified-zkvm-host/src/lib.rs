//! The host-side API: run, prove, verify.
//!
//! ```
//! use unified_zkvm_host::ZkHostRunner;
//! # use unified_zkvm_mock::MockBackend;
//! # use unified_zkvm_core::ProgramArtifact;
//!
//! # fn demo(program: ProgramArtifact) -> Result<(), unified_zkvm_core::ZkVmError> {
//! let runner = ZkHostRunner::new(MockBackend::new());
//!
//! let proof = runner.prove(&program, &42u32)?;
//! let output = runner.verify(&proof, &program)?;
//!
//! // Public values are only reachable after verification succeeded.
//! let value: u64 = output.decode()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Static dispatch by default
//!
//! [`ZkHostRunner<B>`] is generic over the backend, so calls are direct and the
//! compiler can inline through them. Runtime selection is available when it is
//! genuinely needed - `ZkHostRunner<Box<dyn BackendAdapter>>` works, because the
//! adapter trait is object safe - but it is opt-in rather than imposed.
//!
//! # Synchronous, on purpose
//!
//! Local proving is CPU-bound and synchronous. Making the whole API `async` to
//! accommodate a future network prover would tax every local user for a feature
//! they are not using. The extension point for remote proving is
//! [`prover::Prover`]; see `docs/host-guide.md`.
//!
//! # Modules
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`runner`] | [`ZkHostRunner`] and its builder |
//! | [`config`] | [`RunnerConfig`] and policy types |
//! | [`prover`] | The proving seam, including remote extension |
//! | [`verifier`] | Standalone verification |
//! | [`aggregator`] | Capability-gated aggregation |

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod aggregator;
pub mod config;
pub mod prover;
pub mod runner;
pub mod verifier;

pub use aggregator::ProofAggregator;
pub use config::{ArtifactPolicy, RunnerConfig, TelemetryConfig};
pub use prover::{ProofRequest, Prover};
pub use runner::{ZkHostRunner, ZkHostRunnerBuilder};
pub use verifier::Verifier;

/// Re-exported so a host application needs one dependency for the common path.
pub use unified_zkvm_core::{
    BackendAdapter, BackendId, Capability, CapabilitySet, ExecutionResult, FallbackPolicy,
    ProgramArtifact, ProgramId, ProofKind, ProofMetadata, ProvingOptions, PublicValues,
    VerifiedPublicValues, ZkProof, ZkVmError,
};
