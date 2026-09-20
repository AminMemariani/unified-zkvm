//! The capability system: what a backend *actually implements*.
//!
//! This module exists because the honest answer to "do all zkVMs support
//! feature X?" is almost always "no, and the differences matter". Rather than
//! reducing every backend to the lowest common denominator, unified-zkvm
//! publishes a [`CapabilitySet`] per backend and fails loudly when an
//! unsupported path is requested.
//!
//! # The rule adapters must follow
//!
//! A capability bit means **"this adapter implements this, and a test proves
//! it"**. It does not mean "the upstream project could theoretically do this".
//! In particular, an acceleration bit such as [`Capability::Sha256Accel`] must
//! only be set when a backend *precompile or syscall* is used — never when a
//! software fallback is silently substituted, because the proving-cost
//! difference is orders of magnitude. Use [`crate::crypto`] to report the
//! distinction.
//!
//! ```
//! use unified_zkvm_core::{Capability, CapabilitySet};
//!
//! let caps = CapabilitySet::EXECUTE | CapabilitySet::PROVE | CapabilitySet::VERIFY;
//!
//! assert!(caps.supports(Capability::Prove));
//! assert!(!caps.supports(Capability::Aggregation));
//!
//! // Missing capabilities are enumerable, which makes error messages specific.
//! let missing = caps.missing_from(CapabilitySet::PROVE | CapabilitySet::AGGREGATION);
//! assert_eq!(missing, CapabilitySet::AGGREGATION);
//! ```

use core::fmt;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    /// The set of capabilities a backend adapter implements.
    ///
    /// A bitflag set is used rather than a struct of `bool` fields so that new
    /// capabilities can be added without breaking exhaustive construction in
    /// downstream adapters, and so that capability *requirements* can be
    /// expressed and diffed as a single value.
    ///
    /// Reserved bits above [`Self::ELLIPTIC_CURVE_ACCEL`] are intentionally
    /// left free; the type is `u64` to leave room for growth.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct CapabilitySet: u64 {
        /// Guest can read host-provided input.
        const GUEST_IO = 1 << 0;
        /// Guest can commit public values readable after verification.
        const PUBLIC_VALUES = 1 << 1;
        /// Guest can be run locally without producing a proof.
        const EXECUTE = 1 << 2;
        /// Proofs can be generated on the local machine.
        const PROVE = 1 << 3;
        /// Proofs can be verified on the local machine.
        const VERIFY = 1 << 4;
        /// Several independent proofs can be folded into one.
        ///
        /// See `docs/aggregation.md`: this is a demanding bit and most
        /// backends do not satisfy it at the SDK level.
        const AGGREGATION = 1 << 5;
        /// A proof can be verified inside a guest program.
        const RECURSION = 1 << 6;
        /// A proof can be compressed to a constant-size representation.
        const COMPRESSION = 1 << 7;
        /// Proofs can be produced in a format verifiable by an EVM contract.
        const ONCHAIN_PROOF = 1 << 8;
        /// SHA-256 is accelerated by a precompile or syscall.
        const SHA256_ACCEL = 1 << 16;
        /// Keccak-256 is accelerated by a precompile or syscall.
        const KECCAK_ACCEL = 1 << 17;
        /// Elliptic-curve arithmetic is accelerated by a precompile.
        const ELLIPTIC_CURVE_ACCEL = 1 << 18;
        /// Cycle counts are reported by the executor.
        const CYCLE_METRICS = 1 << 32;
        /// Proving can be delegated to a remote service.
        const REMOTE_PROVING = 1 << 33;
    }
}

impl CapabilitySet {
    /// The capabilities any adapter must implement to be usable at all.
    ///
    /// An adapter that cannot execute, prove and verify is not a backend; it is
    /// a stub. [`crate::BackendAdapter`] implementations are expected to be a
    /// superset of this.
    pub const MINIMUM_VIABLE: Self = Self::GUEST_IO
        .union(Self::PUBLIC_VALUES)
        .union(Self::EXECUTE)
        .union(Self::PROVE)
        .union(Self::VERIFY);

    /// Returns `true` if a single [`Capability`] is present.
    #[must_use]
    pub const fn supports(self, capability: Capability) -> bool {
        self.contains(capability.as_flag())
    }

    /// Returns the capabilities in `required` that `self` lacks.
    ///
    /// Used to build precise error messages: reporting exactly which bits are
    /// absent is far more actionable than "unsupported".
    #[must_use]
    pub const fn missing_from(self, required: Self) -> Self {
        required.difference(self)
    }

    /// Returns `true` when every capability in `required` is present.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        self.contains(required)
    }

    /// Iterates the individual [`Capability`] values present in this set.
    ///
    /// Bits with no named [`Capability`] counterpart are skipped.
    pub fn iter_capabilities(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .iter()
            .copied()
            .filter(move |c| self.supports(*c))
    }
}

/// A single named capability.
///
/// This is the value carried by [`crate::ZkVmError::UnsupportedCapability`], so
/// a caller can programmatically discover what was missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Capability {
    /// Guest input reading. Maps to [`CapabilitySet::GUEST_IO`].
    GuestIo,
    /// Public value commitment. Maps to [`CapabilitySet::PUBLIC_VALUES`].
    PublicValues,
    /// Local execution without proving. Maps to [`CapabilitySet::EXECUTE`].
    Execute,
    /// Local proof generation. Maps to [`CapabilitySet::PROVE`].
    Prove,
    /// Local proof verification. Maps to [`CapabilitySet::VERIFY`].
    Verify,
    /// Folding independent proofs. Maps to [`CapabilitySet::AGGREGATION`].
    Aggregation,
    /// In-guest proof verification. Maps to [`CapabilitySet::RECURSION`].
    Recursion,
    /// Constant-size proof compression. Maps to [`CapabilitySet::COMPRESSION`].
    Compression,
    /// EVM-verifiable proof output. Maps to [`CapabilitySet::ONCHAIN_PROOF`].
    OnchainProof,
    /// Accelerated SHA-256. Maps to [`CapabilitySet::SHA256_ACCEL`].
    Sha256Accel,
    /// Accelerated Keccak-256. Maps to [`CapabilitySet::KECCAK_ACCEL`].
    KeccakAccel,
    /// Accelerated elliptic-curve arithmetic.
    EllipticCurveAccel,
    /// Cycle-count reporting. Maps to [`CapabilitySet::CYCLE_METRICS`].
    CycleMetrics,
    /// Remote/delegated proving. Maps to [`CapabilitySet::REMOTE_PROVING`].
    RemoteProving,
}

impl Capability {
    /// Every named capability, used for iteration and exhaustiveness tests.
    pub const ALL: &'static [Capability] = &[
        Capability::GuestIo,
        Capability::PublicValues,
        Capability::Execute,
        Capability::Prove,
        Capability::Verify,
        Capability::Aggregation,
        Capability::Recursion,
        Capability::Compression,
        Capability::OnchainProof,
        Capability::Sha256Accel,
        Capability::KeccakAccel,
        Capability::EllipticCurveAccel,
        Capability::CycleMetrics,
        Capability::RemoteProving,
    ];

    /// Returns the single-bit [`CapabilitySet`] corresponding to this capability.
    #[must_use]
    pub const fn as_flag(self) -> CapabilitySet {
        match self {
            Self::GuestIo => CapabilitySet::GUEST_IO,
            Self::PublicValues => CapabilitySet::PUBLIC_VALUES,
            Self::Execute => CapabilitySet::EXECUTE,
            Self::Prove => CapabilitySet::PROVE,
            Self::Verify => CapabilitySet::VERIFY,
            Self::Aggregation => CapabilitySet::AGGREGATION,
            Self::Recursion => CapabilitySet::RECURSION,
            Self::Compression => CapabilitySet::COMPRESSION,
            Self::OnchainProof => CapabilitySet::ONCHAIN_PROOF,
            Self::Sha256Accel => CapabilitySet::SHA256_ACCEL,
            Self::KeccakAccel => CapabilitySet::KECCAK_ACCEL,
            Self::EllipticCurveAccel => CapabilitySet::ELLIPTIC_CURVE_ACCEL,
            Self::CycleMetrics => CapabilitySet::CYCLE_METRICS,
            Self::RemoteProving => CapabilitySet::REMOTE_PROVING,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::GuestIo => "guest I/O",
            Self::PublicValues => "public values",
            Self::Execute => "local execution",
            Self::Prove => "local proving",
            Self::Verify => "local verification",
            Self::Aggregation => "proof aggregation",
            Self::Recursion => "recursion",
            Self::Compression => "proof compression",
            Self::OnchainProof => "on-chain proof",
            Self::Sha256Accel => "accelerated SHA-256",
            Self::KeccakAccel => "accelerated Keccak-256",
            Self::EllipticCurveAccel => "accelerated elliptic-curve arithmetic",
            Self::CycleMetrics => "cycle metrics",
            Self::RemoteProving => "remote proving",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_capability_maps_to_a_distinct_bit() {
        // Guards against a copy-paste error in `as_flag` silently aliasing two
        // capabilities onto the same bit, which would make one of them
        // unreportable.
        let mut seen = CapabilitySet::empty();
        for cap in Capability::ALL {
            let flag = cap.as_flag();
            assert_eq!(flag.bits().count_ones(), 1, "{cap:?} is not a single bit");
            assert!(
                !seen.contains(flag),
                "{cap:?} aliases a bit already used by another capability"
            );
            seen |= flag;
        }
    }

    #[test]
    fn missing_from_reports_only_absent_bits() {
        let have = CapabilitySet::EXECUTE | CapabilitySet::PROVE;
        let want = CapabilitySet::PROVE | CapabilitySet::VERIFY | CapabilitySet::AGGREGATION;

        assert_eq!(
            have.missing_from(want),
            CapabilitySet::VERIFY | CapabilitySet::AGGREGATION
        );
        assert!(!have.satisfies(want));
    }

    #[test]
    fn minimum_viable_is_what_a_real_backend_must_offer() {
        assert!(CapabilitySet::MINIMUM_VIABLE.supports(Capability::Prove));
        assert!(CapabilitySet::MINIMUM_VIABLE.supports(Capability::Verify));
        // Aggregation is explicitly NOT part of the baseline.
        assert!(!CapabilitySet::MINIMUM_VIABLE.supports(Capability::Aggregation));
    }

    #[test]
    fn capability_iteration_round_trips_through_a_set() {
        let set = CapabilitySet::EXECUTE | CapabilitySet::KECCAK_ACCEL;
        let collected: alloc::vec::Vec<_> = set.iter_capabilities().collect();
        assert_eq!(
            collected,
            alloc::vec![Capability::Execute, Capability::KeccakAccel]
        );
    }
}
