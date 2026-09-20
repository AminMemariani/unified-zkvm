//! **Write your zkVM application once. Choose the proving backend later.**
//!
//! `unified-zkvm` is a portable Rust abstraction over zkVM proving backends. A
//! guest program reads input and commits output through one API; the host
//! proves and verifies through another; and which proving system executes
//! underneath is a build-time choice rather than something woven through your
//! application.
//!
//! ```text
//!                    ┌─────────────────────┐
//!                    │     Application     │
//!                    └──────────┬──────────┘
//!                     unified-zkvm API
//!                    ┌──────────┴──────────┐
//!                    │  Guest I/O · Host   │
//!                    │  Proofs · Crypto    │
//!                    │     Capabilities    │
//!                    └──────────┬──────────┘
//!             ┌─────────────────┼─────────────────┐
//!             ▼                 ▼                 ▼
//!          SP1 adapter    RISC Zero adapter   Mock backend
//! ```
//!
//! # Quick start
//!
//! Guest:
//!
//! ```ignore
//! // Requires the `guest` feature; see examples/fibonacci/guest for a
//! // complete, compiled guest crate.
//! use unified_zkvm::guest::{zk_commit, zk_read};
//!
//! #[unified_zkvm::entrypoint]
//! fn main() {
//!     let n: u32 = zk_read().unwrap();
//!     zk_commit(&(u64::from(n) * u64::from(n))).unwrap();
//! }
//! ```
//!
//! Host:
//!
//! ```
//! use unified_zkvm::host::ZkHostRunner;
//! # use unified_zkvm::mock::MockBackend;
//! # fn demo() -> Result<(), unified_zkvm::ZkVmError> {
//! # let backend = MockBackend::new();
//! # let program = backend.build_program(b"guest-elf")?;
//! let runner = ZkHostRunner::new(backend);
//!
//! let proof = runner.prove(&program, &7u32)?;
//! let verified = runner.verify(&proof, &program)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature flags
//!
//! | Feature | Enables | Default |
//! |---|---|---|
//! | `std` | Standard library support | ✅ |
//! | `host` | [`host`] — proving and verification | ✅ |
//! | `guest` | the guest I/O module — `zk_read` / `zk_commit` | — |
//! | `macros` | `#[entrypoint]` | — |
//! | `mock` | [`mock`] — development backend, **no real proofs** | ✅ |
//! | `sp1` | SP1 guest runtime | — |
//! | `risc0` | RISC Zero guest runtime | — |
//!
//! Backend features are never default: each pulls a proving SDK of several
//! hundred crates, and most builds need at most one.
//!
//! # What "portable" does and does not mean
//!
//! It means your application code — business logic, I/O, proof handling — does
//! not change when you switch backends. It does **not** mean every guest runs
//! unchanged on every zkVM, that proving costs are comparable, or that proof
//! bytes are interchangeable. Those differences are real, and the library
//! surfaces them through [`CapabilitySet`] rather than hiding them. See the
//! limitations section of the README.
//!
//! # Security
//!
//! Public values are meaningless until the proof carrying them has been
//! verified against a known program. The API enforces this: verification
//! returns a [`VerifiedPublicValues`], and that is the only comfortable way to
//! decode output. See `docs/security-model.md`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use unified_zkvm_core::{
    BackendAdapter, BackendId, Capability, CapabilitySet, CryptoImplementation, CryptoPrimitive,
    CryptoSupport, ExecutionResult, FallbackPolicy, IntegrationStatus, ProgramArtifact, ProgramId,
    ProofKind, ProofMetadata, ProvingOptions, PublicValues, ResourceUsage, VerifiedPublicValues,
    ZkMessage, ZkProof, ZkVmError,
};

/// Backend-neutral core types.
pub use unified_zkvm_core as core_types;

/// The on-disk proof container.
pub use unified_zkvm_core::container;

#[cfg(feature = "guest")]
#[cfg_attr(docsrs, doc(cfg(feature = "guest")))]
/// The guest API: [`zk_read`](guest::zk_read) and
/// [`zk_commit`](guest::zk_commit).
pub use unified_zkvm_guest as guest;

#[cfg(feature = "host")]
#[cfg_attr(docsrs, doc(cfg(feature = "host")))]
/// The host API: [`ZkHostRunner`](host::ZkHostRunner) and friends.
pub use unified_zkvm_host as host;

#[cfg(feature = "mock")]
#[cfg_attr(docsrs, doc(cfg(feature = "mock")))]
/// The development mock backend.
///
/// # Security
///
/// Produces **no cryptographic proofs**. See [`mock::MockBackend`].
pub use unified_zkvm_mock as mock;

#[cfg(feature = "macros")]
#[cfg_attr(docsrs, doc(cfg(feature = "macros")))]
pub use unified_zkvm_macros::entrypoint;

/// Reports which backend adapters this build can actually use.
///
/// Returns only backends whose feature is enabled **and** whose adapter is
/// implemented. A backend absent from this list will fail with
/// [`ZkVmError::BackendNotEnabled`] rather than a confusing import error.
///
/// ```
/// let available = unified_zkvm::available_backends();
///
/// // The default feature set includes the mock backend.
/// assert!(available.contains(&unified_zkvm::BackendId::Mock));
/// ```
#[must_use]
// Each push is `#[cfg]`-gated, so the `vec![]` form clippy suggests is not
// expressible here without duplicating the whole literal per feature
// combination.
#[allow(clippy::vec_init_then_push)]
pub fn available_backends() -> Vec<BackendId> {
    let mut out = Vec::new();

    #[cfg(feature = "mock")]
    out.push(BackendId::Mock);

    // Adapter crates live outside the default workspace because they require
    // vendor toolchains; when built with their feature they register here.
    #[cfg(feature = "sp1")]
    out.push(BackendId::Sp1);

    #[cfg(feature = "risc0")]
    out.push(BackendId::Risc0);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_build_exposes_a_usable_backend() {
        assert!(
            !available_backends().is_empty(),
            "a default `cargo add unified-zkvm` must be explorable without an SDK"
        );
    }

    #[test]
    fn availability_reflects_features_not_wishful_thinking() {
        let available = available_backends();
        // sp1/risc0 are not default features, so they must be absent here.
        assert!(!available.contains(&BackendId::Jolt));
        assert!(!available.contains(&BackendId::Pico));
    }
}
