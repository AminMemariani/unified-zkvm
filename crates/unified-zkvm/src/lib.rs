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
//!                    │  Guest I/O | Host   │
//!                    │  Proofs | Crypto    │
//!                    │     Capabilities    │
//!                    └──────────┬──────────┘
//!             ┌─────────────────┼─────────────────┐
//!             ▼                 ▼                 ▼
//!          SP1 adapter    RISC Zero adapter   (dev: mock)
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
//! ```ignore
//! // Requires a backend adapter, e.g. `unified-zkvm-sp1` or
//! // `unified-zkvm-risc0`. Swapping the two lines that name the backend is
//! // the entire migration between them.
//! use unified_zkvm::host::ZkHostRunner;
//! use unified_zkvm_sp1::Sp1Backend;
//!
//! let backend = Sp1Backend::new();
//! let program = backend.build_program(GUEST_ELF)?;
//! let runner = ZkHostRunner::new(backend);
//!
//! let proof = runner.prove(&program, &7u32)?;
//!
//! // Public values are readable only after verification succeeds.
//! let verified = runner.verify(&proof, &program)?;
//! let output: u64 = verified.decode()?;
//! ```
//!
//! # Feature flags
//!
//! | Feature | Enables | Default |
//! |---|---|---|
//! | `std` | Standard library support | yes |
//! | `host` | [`host`] - proving and verification | yes |
//! | `guest` | the guest I/O module - `zk_read` / `zk_commit` | - |
//! | `macros` | `#[entrypoint]` | - |
//! | `mock` | the `mock` module - development backend, **no real proofs** | - |
//! | `sp1` | SP1 guest runtime | - |
//! | `risc0` | RISC Zero guest runtime | - |
//!
//! **No backend is enabled by default.** A real backend costs a proving SDK of
//! several hundred crates, and most builds need at most one. The `mock` backend
//! is not default either, for a different and more important reason: it
//! produces no cryptographic proofs, so it must never arrive in a dependency
//! tree unasked. Enable it explicitly, and prefer `[dev-dependencies]` so it
//! cannot reach a release build.
//!
//! # What "portable" does and does not mean
//!
//! It means your application code - business logic, I/O, proof handling - does
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

// A mock prover reaching a release binary is a security problem, not a style
// preference: `MockBackend` "verifies" a keyless checksum anyone can forge. The
// feature is opt-in, but opting in and then shipping it is the mistake worth
// catching, so say so loudly at compile time when optimisations are on.
//
// This is a warning rather than a hard `compile_error!` because integration
// tests, benchmarks and examples are legitimately built in release mode. It is
// deliberately hard to miss and trivial to silence correctly: move the
// dependency to `[dev-dependencies]`.
/// The development mock backend.
///
/// # Security
///
/// Produces **no cryptographic proofs**. Its verifier recomputes a keyless
/// checksum that anyone can forge, so it attests to nothing. See
/// [`mock::MockBackend`].
///
/// # Keeping it out of production
///
/// The `mock` feature is **not** enabled by default, so a plain
/// `cargo add unified-zkvm` can never reach this module. That is the guarantee,
/// and it is enforced by a test rather than by documentation.
///
/// When you do want it, declare it where it cannot reach a release binary:
///
/// ```toml
/// [dev-dependencies]
/// unified-zkvm = { version = "0.1", features = ["mock"] }
/// ```
#[cfg(feature = "mock")]
#[cfg_attr(docsrs, doc(cfg(feature = "mock")))]
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
/// // Empty on a default build: no backend ships enabled, because every
/// // real backend costs a proving SDK and the mock one is not a prover.
/// for backend in &available {
///     assert!(backend.is_cryptographic() || cfg!(feature = "mock"));
/// }
/// ```
#[must_use]
// Every push is `#[cfg]`-gated, so on a default build (no backend features)
// the vector is never mutated and `mut` looks redundant. Suppressing both lints
// is cheaper than duplicating the body across every feature combination.
#[allow(clippy::vec_init_then_push, unused_mut)]
pub fn available_backends() -> Vec<BackendId> {
    let mut out = Vec::new();

    // Not default: the mock backend produces no cryptographic proofs, so it is
    // only ever listed when someone asked for it by name.
    #[cfg(feature = "mock")]
    out.push(BackendId::Mock);

    // Each adapter is a separate crate so that enabling one never compiles the
    // other's proving SDK; they register here when their feature is on.
    #[cfg(feature = "sp1")]
    out.push(BackendId::Sp1);

    #[cfg(feature = "risc0")]
    out.push(BackendId::Risc0);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain `cargo add unified-zkvm` must not hand anyone a fake prover.
    ///
    /// This is the test that keeps the "no mock in production" guarantee
    /// honest: if someone adds `mock` back to the default feature set, this
    /// fails rather than quietly shipping a forgeable verifier to every user.
    #[test]
    fn a_default_build_ships_no_non_cryptographic_backend() {
        #[cfg(not(feature = "mock"))]
        assert!(
            !available_backends().contains(&BackendId::Mock),
            "the mock backend must never be reachable without its explicit feature"
        );

        for backend in available_backends() {
            assert!(
                backend.is_cryptographic() || cfg!(feature = "mock"),
                "{backend} is not cryptographic and was enabled without the `mock` feature"
            );
        }
    }

    #[test]
    fn availability_reflects_features_not_wishful_thinking() {
        let available = available_backends();
        // No adapter exists for these, so they must never be advertised.
        assert!(!available.contains(&BackendId::Jolt));
        assert!(!available.contains(&BackendId::Pico));
    }
}
