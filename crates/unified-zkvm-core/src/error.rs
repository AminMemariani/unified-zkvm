//! The error hierarchy shared by every backend.
//!
//! Two principles govern this module:
//!
//! 1. **Categories are portable, messages are not.** Application code may
//!    reasonably `match` on the variants here; it must never depend on the
//!    text a backend produced. Different proving systems report the same
//!    logical failure with wildly different wording.
//! 2. **Backend context survives.** A failure carries *which* backend, *which*
//!    operation and *which* stage produced it, so a bug report contains enough
//!    to act on without re-running the proof.
//!
//! `thiserror` is intentionally not used: it would either force `std` or pull a
//! proc-macro into a crate whose whole purpose is to stay small and `no_std`.
//! The impls below are mechanical and cost nothing at runtime.

use alloc::boxed::Box;
use alloc::string::String;
use core::fmt;

use crate::backend::BackendId;
use crate::capabilities::Capability;
use crate::proof::ProofKind;

/// A boxed backend error.
///
/// `Send + Sync` so that a `ZkVmError` can cross thread boundaries in a host
/// application (proving is frequently moved onto a worker thread).
#[cfg(feature = "std")]
pub type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A boxed backend error.
///
/// Without `std` there is no `Error` trait to box, so the payload degrades to a
/// displayable message. Backends that need rich error chaining require `std`
/// anyway.
#[cfg(not(feature = "std"))]
pub type BoxedError = Box<String>;

/// The high-level operation that was being attempted when a failure occurred.
///
/// Recorded on backend errors so that `prove` failures and `verify` failures
/// are distinguishable without parsing text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Building or loading a program artifact.
    Setup,
    /// Running the guest without producing a proof.
    Execute,
    /// Producing a proof.
    Prove,
    /// Checking a proof.
    Verify,
    /// Combining several proofs into one.
    Aggregate,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Setup => "setup",
            Self::Execute => "execute",
            Self::Prove => "prove",
            Self::Verify => "verify",
            Self::Aggregate => "aggregate",
        };
        f.write_str(s)
    }
}

/// The phase within an [`Operation`] that failed.
///
/// Distinguishing these matters in practice: a guest panic during execution and
/// a prover OOM during proving are both "prove failed" to a naive wrapper, but
/// they need completely different fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Encoding inputs into the backend's native format.
    InputEncoding,
    /// Running the guest program.
    GuestExecution,
    /// Generating the cryptographic proof.
    ProofGeneration,
    /// Checking the cryptographic proof.
    ProofVerification,
    /// Converting between native and portable representations.
    Conversion,
    /// Backend client/runtime construction.
    BackendSetup,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InputEncoding => "input encoding",
            Self::GuestExecution => "guest execution",
            Self::ProofGeneration => "proof generation",
            Self::ProofVerification => "proof verification",
            Self::Conversion => "conversion",
            Self::BackendSetup => "backend setup",
        };
        f.write_str(s)
    }
}

/// The portable error type returned by every unified-zkvm operation.
///
/// # Matching on categories
///
/// ```
/// use unified_zkvm_core::{ZkVmError, Capability, BackendId};
///
/// fn is_retryable(e: &ZkVmError) -> bool {
///     // A capability gap will never succeed on retry; a backend error might.
///     !matches!(e, ZkVmError::UnsupportedCapability { .. })
/// }
///
/// let e = ZkVmError::UnsupportedCapability {
///     backend: BackendId::Mock,
///     capability: Capability::Aggregation,
/// };
/// assert!(!is_retryable(&e));
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum ZkVmError {
    /// The backend does not implement the requested capability.
    ///
    /// This is returned *instead of* silently substituting a different
    /// mechanism. A backend that lacks hardware-accelerated Keccak will not
    /// quietly run a software implementation and report success, because that
    /// would change proving cost by orders of magnitude without telling anyone.
    UnsupportedCapability {
        /// Backend that was asked.
        backend: BackendId,
        /// Capability that is missing.
        capability: Capability,
    },

    /// The requested proof kind is not produced by this backend.
    ///
    /// Notably this is returned rather than downgrading (for example
    /// `Compressed` -> `Native`), because a downgrade changes proof size,
    /// verification cost and on-chain compatibility. Opt into downgrades
    /// explicitly with [`crate::proof::FallbackPolicy`].
    UnsupportedProofKind {
        /// Backend that was asked.
        backend: BackendId,
        /// Proof kind that was requested.
        requested: ProofKind,
    },

    /// A backend feature was requested but not compiled in.
    BackendNotEnabled {
        /// Backend that was requested.
        backend: BackendId,
        /// The cargo feature that would enable it.
        feature: &'static str,
    },

    /// The program artifact is malformed, empty, or not valid for the backend.
    InvalidProgram {
        /// Human-readable reason.
        reason: String,
    },

    /// A proof was structurally invalid — it failed parsing, not cryptography.
    ///
    /// Distinct from [`Self::VerificationFailed`]: this means the bytes were
    /// never a well-formed proof, which usually indicates corruption or a
    /// version mismatch rather than a forgery attempt.
    InvalidProof {
        /// Human-readable reason.
        reason: String,
    },

    /// Cryptographic verification rejected the proof.
    ///
    /// # Security
    ///
    /// Treat this as adversarial input. Do not retry, do not fall back, and do
    /// not read the proof's public values.
    VerificationFailed {
        /// Backend whose verifier rejected the proof.
        backend: BackendId,
        /// Backend-supplied detail, if any. Never trusted for control flow.
        detail: Option<String>,
    },

    /// The proof was produced by a different program than the one supplied.
    ///
    /// # Security
    ///
    /// This is the check that stops a valid proof of the *wrong computation*
    /// being accepted. It is enforced before any cryptographic verification so
    /// that a mismatch is cheap to reject.
    ProgramIdMismatch {
        /// Identity carried by the proof.
        expected: Box<crate::program::ProgramId>,
        /// Identity of the program supplied to the verifier.
        actual: Box<crate::program::ProgramId>,
    },

    /// The proof was produced by a different backend than the verifier.
    BackendMismatch {
        /// Backend that produced the proof.
        proof_backend: BackendId,
        /// Backend asked to verify it.
        verifier_backend: BackendId,
    },

    /// Canonical encoding or decoding failed.
    Serialization {
        /// What was being processed.
        context: &'static str,
        /// Underlying detail.
        detail: String,
    },

    /// A length prefix or artifact size exceeded the configured limit.
    ///
    /// # Security
    ///
    /// Raised *before* allocating, so that attacker-controlled length fields
    /// cannot trigger an out-of-memory abort.
    SizeLimitExceeded {
        /// What was being decoded.
        context: &'static str,
        /// Size the input claimed.
        claimed: usize,
        /// Maximum accepted.
        limit: usize,
    },

    /// An unsupported encoding version was encountered.
    UnsupportedVersion {
        /// What was being decoded.
        context: &'static str,
        /// Version found in the input.
        found: u16,
        /// Highest version this build understands.
        supported: u16,
    },

    /// An error originating inside a backend SDK, with context preserved.
    Backend {
        /// Which backend failed.
        backend: BackendId,
        /// What it was doing.
        operation: Operation,
        /// Which phase failed.
        stage: Stage,
        /// The original SDK error.
        source: BoxedError,
    },

    /// Host-side configuration is invalid or self-contradictory.
    Configuration {
        /// Human-readable reason, phrased as an actionable fix.
        reason: String,
    },

    /// Filesystem or other I/O failure.
    #[cfg(feature = "std")]
    Io {
        /// What was being read or written.
        context: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

impl ZkVmError {
    /// Wraps a backend SDK error with full operational context.
    ///
    /// Prefer this over `map_err(|e| ZkVmError::Backend { .. })` spelled out at
    /// each call site — it keeps adapters terse and guarantees the context
    /// fields are actually populated.
    #[cfg(feature = "std")]
    pub fn backend<E>(backend: BackendId, operation: Operation, stage: Stage, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Backend {
            backend,
            operation,
            stage,
            source: Box::new(source),
        }
    }

    /// Returns the backend responsible for this error, when one is known.
    ///
    /// Useful for routing: a multi-backend host can attribute a failure without
    /// matching every variant.
    pub fn backend_id(&self) -> Option<BackendId> {
        match self {
            Self::UnsupportedCapability { backend, .. }
            | Self::UnsupportedProofKind { backend, .. }
            | Self::BackendNotEnabled { backend, .. }
            | Self::VerificationFailed { backend, .. }
            | Self::Backend { backend, .. } => Some(*backend),
            Self::BackendMismatch { proof_backend, .. } => Some(*proof_backend),
            _ => None,
        }
    }

    /// Returns `true` when the error indicates a security-relevant rejection
    /// rather than an operational problem.
    ///
    /// A `true` result must never be retried or worked around: it means some
    /// input failed an integrity or authenticity check.
    pub fn is_security_rejection(&self) -> bool {
        matches!(
            self,
            Self::VerificationFailed { .. }
                | Self::ProgramIdMismatch { .. }
                | Self::BackendMismatch { .. }
                | Self::InvalidProof { .. }
                | Self::SizeLimitExceeded { .. }
        )
    }
}

impl fmt::Display for ZkVmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCapability {
                backend,
                capability,
            } => write!(
                f,
                "backend `{backend}` does not support capability `{capability}`"
            ),
            Self::UnsupportedProofKind { backend, requested } => write!(
                f,
                "backend `{backend}` cannot produce a `{requested}` proof; \
                 request a supported kind or set an explicit fallback policy"
            ),
            Self::BackendNotEnabled { backend, feature } => write!(
                f,
                "the `{backend}` backend is not enabled.\n\nEnable it with:\n\n    \
                 cargo build --features {feature}\n"
            ),
            Self::InvalidProgram { reason } => write!(f, "invalid program artifact: {reason}"),
            Self::InvalidProof { reason } => write!(f, "malformed proof: {reason}"),
            Self::VerificationFailed { backend, detail } => match detail {
                Some(d) => write!(f, "proof verification failed on backend `{backend}`: {d}"),
                None => write!(f, "proof verification failed on backend `{backend}`"),
            },
            Self::ProgramIdMismatch { expected, actual } => write!(
                f,
                "program identity mismatch: proof is bound to {expected}, \
                 but verification was attempted against {actual}"
            ),
            Self::BackendMismatch {
                proof_backend,
                verifier_backend,
            } => write!(
                f,
                "proof was produced by `{proof_backend}` but `{verifier_backend}` \
                 was asked to verify it; proof formats are not interchangeable"
            ),
            Self::Serialization { context, detail } => {
                write!(f, "serialization error while handling {context}: {detail}")
            }
            Self::SizeLimitExceeded {
                context,
                claimed,
                limit,
            } => write!(
                f,
                "{context} declared a size of {claimed} bytes, exceeding the \
                 {limit} byte limit; refusing to allocate"
            ),
            Self::UnsupportedVersion {
                context,
                found,
                supported,
            } => write!(
                f,
                "{context} uses format version {found}, but this build supports \
                 at most version {supported}"
            ),
            Self::Backend {
                backend,
                operation,
                stage,
                source,
            } => write!(
                f,
                "backend `{backend}` failed during {operation} at stage `{stage}`: {source}"
            ),
            Self::Configuration { reason } => write!(f, "invalid configuration: {reason}"),
            #[cfg(feature = "std")]
            Self::Io { context, source } => write!(f, "I/O error on {context}: {source}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ZkVmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend { source, .. } => Some(source.as_ref()),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn backend_not_enabled_message_tells_the_user_the_exact_fix() {
        let e = ZkVmError::BackendNotEnabled {
            backend: BackendId::Sp1,
            feature: "sp1",
        };
        let msg = e.to_string();
        assert!(
            msg.contains("cargo build --features sp1"),
            "message must contain a copy-pasteable fix, got: {msg}"
        );
    }

    #[test]
    fn security_rejections_are_classified_separately_from_operational_errors() {
        assert!(ZkVmError::VerificationFailed {
            backend: BackendId::Mock,
            detail: None,
        }
        .is_security_rejection());

        assert!(!ZkVmError::Configuration {
            reason: "x".to_string(),
        }
        .is_security_rejection());
    }

    #[test]
    fn backend_id_is_recoverable_from_wrapped_errors() {
        let e = ZkVmError::UnsupportedCapability {
            backend: BackendId::Risc0,
            capability: Capability::Aggregation,
        };
        assert_eq!(e.backend_id(), Some(BackendId::Risc0));
    }
}
