//! Backend identity and the adapter contract.
//!
//! [`BackendAdapter`] is the single trait an integration must implement. It is
//! deliberately small - five methods - because every method added here is a
//! method that five backends must implement correctly and that the project must
//! support forever.
//!
//! Anything a backend offers beyond this trait belongs in the adapter's own
//! crate as an inherent method (see `docs/adding-a-backend.md`), reachable
//! through the host runner's escape hatch. That keeps the portable surface
//! honest without trapping advanced users.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use serde::{Deserialize, Serialize};

use crate::capabilities::{Capability, CapabilitySet};
use crate::error::ZkVmError;
use crate::program::ProgramArtifact;
use crate::proof::{ProvingOptions, VerificationWitness, ZkProof};
use crate::public_values::PublicValues;

/// Identifies a proving backend.
///
/// The discriminants are explicit and **stable**: they are written into the
/// proof container on disk, so renumbering them would silently invalidate
/// previously saved proofs. Add new backends with new numbers; never reuse one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[repr(u16)]
pub enum BackendId {
    /// Development-only backend. Produces **no cryptographic proof**.
    ///
    /// See [`crate::proof::ProofKind::Mock`]; artifacts from this backend are
    /// rejected by every real verifier.
    Mock = 0,
    /// Succinct SP1.
    Sp1 = 1,
    /// RISC Zero.
    Risc0 = 2,
    /// a16z Jolt.
    Jolt = 3,
    /// OpenVM.
    OpenVm = 4,
    /// Brevis Pico.
    Pico = 5,
}

impl BackendId {
    /// Every backend the abstraction knows about, including unimplemented ones.
    ///
    /// Presence here means "the abstraction has a slot for it", **not** "an
    /// adapter exists". Use [`Self::integration_status`] for that.
    pub const ALL: &'static [BackendId] = &[
        BackendId::Mock,
        BackendId::Sp1,
        BackendId::Risc0,
        BackendId::Jolt,
        BackendId::OpenVm,
        BackendId::Pico,
    ];

    /// The cargo feature that enables this backend in the `unified-zkvm` facade.
    #[must_use]
    pub const fn feature_name(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Sp1 => "sp1",
            Self::Risc0 => "risc0",
            Self::Jolt => "jolt",
            Self::OpenVm => "openvm",
            Self::Pico => "pico",
        }
    }

    /// Whether proofs from this backend are cryptographically meaningful.
    ///
    /// # Security
    ///
    /// Any code path that accepts a proof from an untrusted party must reject
    /// backends for which this returns `false`. The host verifier enforces it,
    /// but application code that inspects proofs directly should check too.
    #[must_use]
    pub const fn is_cryptographic(self) -> bool {
        !matches!(self, Self::Mock)
    }

    /// The maturity of this project's adapter for the backend.
    ///
    /// Reflects what is implemented **here**, not upstream's own maturity
    /// claims. See `docs/backend-compatibility.md` for the evidence behind each
    /// classification.
    #[must_use]
    pub const fn integration_status(self) -> IntegrationStatus {
        match self {
            Self::Mock => IntegrationStatus::Stable,
            Self::Sp1 | Self::Risc0 => IntegrationStatus::Supported,
            Self::OpenVm => IntegrationStatus::Planned,
            Self::Jolt | Self::Pico => IntegrationStatus::Planned,
        }
    }

    /// Reconstructs a backend from its stable numeric discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::InvalidProof`] for unknown values. Decoding fails
    /// closed rather than defaulting, so a corrupted or forward-version
    /// container is never silently attributed to the wrong backend.
    pub fn from_u16(raw: u16) -> Result<Self, ZkVmError> {
        match raw {
            0 => Ok(Self::Mock),
            1 => Ok(Self::Sp1),
            2 => Ok(Self::Risc0),
            3 => Ok(Self::Jolt),
            4 => Ok(Self::OpenVm),
            5 => Ok(Self::Pico),
            other => Err(ZkVmError::InvalidProof {
                reason: alloc::format!("unknown backend discriminant {other}"),
            }),
        }
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Mock => "mock",
            Self::Sp1 => "sp1",
            Self::Risc0 => "risc0",
            Self::Jolt => "jolt",
            Self::OpenVm => "openvm",
            Self::Pico => "pico",
        };
        f.write_str(s)
    }
}

/// How complete and trustworthy an adapter is.
///
/// A backend is only promoted past [`Self::Experimental`] when an end-to-end
/// prove-and-verify test runs in CI against a pinned upstream release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IntegrationStatus {
    /// Fully implemented and covered end-to-end by tests.
    Stable,
    /// Implemented against a pinned release, covered by end-to-end tests that
    /// require a vendor toolchain to run.
    Supported,
    /// Implemented but with known gaps or unstable upstream APIs.
    Experimental,
    /// The abstraction reserves a slot; no adapter exists yet.
    Planned,
}

impl fmt::Display for IntegrationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Stable => "stable",
            Self::Supported => "supported",
            Self::Experimental => "experimental",
            Self::Planned => "planned",
        };
        f.write_str(s)
    }
}

/// Resource metrics reported by a backend.
///
/// Every field is [`Option`] because backends genuinely differ in what they
/// measure. A missing metric is `None` - never a fabricated zero, which would
/// be indistinguishable from a real measurement of zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Guest cycles executed.
    pub cycles: Option<u64>,
    /// Number of execution segments or shards.
    pub segments: Option<u32>,
    /// Wall-clock time spent executing the guest.
    pub execution_time: Option<Duration>,
    /// Wall-clock time spent generating the proof.
    pub proving_time: Option<Duration>,
}

/// The result of running a guest program without proving it.
///
/// # Security
///
/// The `public_values` here are **unproven**. They are the output of an
/// unattested local run and carry no cryptographic guarantee. Only
/// [`crate::proof::VerifiedPublicValues`], obtained after verification, is
/// trustworthy.
#[derive(Clone, Debug)]
pub struct ExecutionResult {
    /// Values the guest committed during this run.
    pub public_values: PublicValues,
    /// Metrics the backend reported.
    pub usage: ResourceUsage,
}

/// The contract every backend adapter implements.
///
/// # Object safety
///
/// This trait is object safe on purpose. Static dispatch is the default and the
/// fast path, but runtime backend selection (`Box<dyn BackendAdapter>`) is a
/// real requirement for tools that benchmark several backends in one process.
///
/// # Implementing
///
/// * [`Self::capabilities`] must report only what is implemented **and tested**.
/// * [`Self::prove`] must return a genuine backend proof or an error - never a
///   placeholder. The only exception in this workspace is the clearly named
///   mock backend.
/// * [`Self::verify`] must delegate to the backend's real verifier. Returning
///   `Ok(())` without checking is a soundness bug, not a stub.
///
/// See `docs/adding-a-backend.md` for the full checklist.
pub trait BackendAdapter: Send + Sync {
    /// The backend this adapter drives.
    fn backend_id(&self) -> BackendId;

    /// The capabilities this adapter actually implements.
    ///
    /// Must be stable for the lifetime of the adapter instance: the host layer
    /// caches capability checks and a changing answer would make errors
    /// nondeterministic.
    fn capabilities(&self) -> CapabilitySet;

    /// Runs the guest without producing a proof.
    ///
    /// Useful for fast iteration and for measuring cycle counts before paying
    /// for a proof.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedCapability`] if the backend cannot
    /// execute without proving, or [`ZkVmError::Backend`] if the guest fails.
    fn execute(
        &self,
        program: &ProgramArtifact,
        input: &[u8],
    ) -> Result<ExecutionResult, ZkVmError>;

    /// Generates a proof of the guest's execution.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedProofKind`] if `options` requests a proof
    /// kind this backend cannot produce - it must not silently downgrade - and
    /// [`ZkVmError::Backend`] if proving fails.
    fn prove(
        &self,
        program: &ProgramArtifact,
        input: &[u8],
        options: &ProvingOptions,
    ) -> Result<ZkProof, ZkVmError>;

    /// Verifies a proof against a program.
    ///
    /// # Contract
    ///
    /// Implementations **must**, in this order:
    ///
    /// 1. call [`ZkProof::verify_binding`] - a proof of the wrong program is a
    ///    failure even when its cryptography is valid;
    /// 2. delegate to the backend's real cryptographic verifier;
    /// 3. only then mint the returned [`VerificationWitness`].
    ///
    /// Returning a witness is what allows a caller to read the proof's public
    /// values, so minting one on any other path silently converts an unchecked
    /// proof into a trusted one. The witness is zero-sized and costs nothing.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::ProgramIdMismatch`], [`ZkVmError::BackendMismatch`]
    /// or [`ZkVmError::VerificationFailed`].
    fn verify(
        &self,
        proof: &ZkProof,
        program: &ProgramArtifact,
    ) -> Result<VerificationWitness, ZkVmError>;

    /// Folds several proofs into one.
    ///
    /// # Default behaviour
    ///
    /// Returns [`ZkVmError::UnsupportedCapability`]. Most backends do not expose
    /// SDK-level aggregation over independent proofs, so the default is the
    /// honest answer rather than something that concatenates proofs and calls
    /// it aggregation. See `docs/aggregation.md`.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedCapability`] unless overridden.
    fn aggregate(&self, _proofs: &[ZkProof]) -> Result<ZkProof, ZkVmError> {
        Err(ZkVmError::UnsupportedCapability {
            backend: self.backend_id(),
            capability: Capability::Aggregation,
        })
    }

    /// A human-readable description of the pinned upstream version.
    ///
    /// Surfaced in diagnostics so a bug report identifies the exact SDK build.
    fn backend_version(&self) -> String {
        String::from("unknown")
    }
}

/// Helper for adapters: fail unless a capability is present.
///
/// Centralising the check keeps the error shape consistent across adapters and
/// makes the "capability gate before work" pattern a one-liner.
///
/// # Errors
///
/// Returns [`ZkVmError::UnsupportedCapability`] when `caps` lacks `required`.
pub fn require_capability(
    backend: BackendId,
    caps: CapabilitySet,
    required: Capability,
) -> Result<(), ZkVmError> {
    if caps.supports(required) {
        Ok(())
    } else {
        Err(ZkVmError::UnsupportedCapability {
            backend,
            capability: required,
        })
    }
}

/// Type-erased handle used for runtime backend selection.
pub type DynBackend = alloc::boxed::Box<dyn BackendAdapter>;

/// Lets a boxed adapter be used anywhere a concrete one is expected.
///
/// Without this, `ZkHostRunner<Box<dyn BackendAdapter>>` would not compile and
/// the object safety of the trait would be decorative. With it, choosing a
/// backend from a CLI flag or config file is a one-line change and every host
/// API works unmodified.
impl<T: BackendAdapter + ?Sized> BackendAdapter for alloc::boxed::Box<T> {
    fn backend_id(&self) -> BackendId {
        (**self).backend_id()
    }

    fn capabilities(&self) -> CapabilitySet {
        (**self).capabilities()
    }

    fn execute(
        &self,
        program: &ProgramArtifact,
        input: &[u8],
    ) -> Result<ExecutionResult, ZkVmError> {
        (**self).execute(program, input)
    }

    fn prove(
        &self,
        program: &ProgramArtifact,
        input: &[u8],
        options: &ProvingOptions,
    ) -> Result<ZkProof, ZkVmError> {
        (**self).prove(program, input, options)
    }

    fn verify(
        &self,
        proof: &ZkProof,
        program: &ProgramArtifact,
    ) -> Result<VerificationWitness, ZkVmError> {
        (**self).verify(proof, program)
    }

    fn aggregate(&self, proofs: &[ZkProof]) -> Result<ZkProof, ZkVmError> {
        (**self).aggregate(proofs)
    }

    fn backend_version(&self) -> String {
        (**self).backend_version()
    }
}

/// Describes a backend for display in tooling and documentation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendDescriptor {
    /// Which backend.
    pub id: BackendId,
    /// Adapter maturity in this project.
    pub status: IntegrationStatus,
    /// Pinned upstream version, if an adapter exists.
    pub upstream_version: Option<String>,
    /// Capabilities the adapter implements, if an adapter exists.
    pub capabilities: Option<CapabilitySet>,
    /// Known limitations, phrased for a user deciding whether to adopt it.
    pub notes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_discriminants_are_stable_across_releases() {
        // These numbers are written into on-disk proof containers. Changing one
        // silently invalidates every previously saved proof, so this test is a
        // tripwire, not a tautology.
        assert_eq!(BackendId::Mock as u16, 0);
        assert_eq!(BackendId::Sp1 as u16, 1);
        assert_eq!(BackendId::Risc0 as u16, 2);
        assert_eq!(BackendId::Jolt as u16, 3);
        assert_eq!(BackendId::OpenVm as u16, 4);
        assert_eq!(BackendId::Pico as u16, 5);
    }

    #[test]
    fn discriminant_round_trip_holds_for_every_backend() {
        for b in BackendId::ALL {
            assert_eq!(BackendId::from_u16(*b as u16).unwrap(), *b);
        }
    }

    #[test]
    fn unknown_discriminants_fail_closed() {
        assert!(BackendId::from_u16(9999).is_err());
    }

    #[test]
    fn only_the_mock_backend_is_non_cryptographic() {
        assert!(!BackendId::Mock.is_cryptographic());
        for b in BackendId::ALL.iter().filter(|b| **b != BackendId::Mock) {
            assert!(b.is_cryptographic(), "{b} must be cryptographic");
        }
    }
}
