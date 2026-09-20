//! Crypto capability reporting and portable fallbacks.
//!
//! # The problem this solves
//!
//! Every supported zkVM can compute SHA-256 inside a guest. Not every one does
//! it in the same number of cycles - a backend precompile can be **orders of
//! magnitude** cheaper than the same hash implemented in pure Rust and proven
//! instruction by instruction. A library that exposed one `sha256()` function
//! and quietly picked whichever was available would make proving cost
//! unpredictable and invisible.
//!
//! So unified-zkvm separates two questions:
//!
//! 1. *What does this compute?* - answered identically on every backend.
//! 2. *How is it proven?* - answered by [`CryptoSupport`], per backend, per
//!    primitive.
//!
//! ```
//! use unified_zkvm_core::{CryptoImplementation, CryptoPrimitive, CryptoSupport};
//!
//! # let support = CryptoSupport::portable_only();
//! match support.implementation(CryptoPrimitive::Keccak256) {
//!     CryptoImplementation::NativePrecompile => { /* cheap */ }
//!     CryptoImplementation::Portable => { /* correct, but costly to prove */ }
//!     CryptoImplementation::Unsupported => { /* pick another primitive */ }
//! }
//! ```
//!
//! # Scope
//!
//! This crate implements **no new cryptography**. SHA-256 comes from the
//! audited `sha2` crate; primitives without a vetted `no_std` implementation
//! are reported as [`CryptoImplementation::Unsupported`] rather than
//! hand-rolled. See `docs/crypto.md`.

use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capabilities::CapabilitySet;

/// A cryptographic primitive a guest may use.
///
/// The list is deliberately short. A primitive appears here only when it is
/// implemented and tested against official vectors - adding a name without an
/// implementation would make the capability report a lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoPrimitive {
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// Keccak-256 as used by Ethereum (pre-NIST padding).
    Keccak256,
}

impl fmt::Display for CryptoPrimitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("sha256"),
            Self::Keccak256 => f.write_str("keccak256"),
        }
    }
}

/// How a primitive is realised on a given backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoImplementation {
    /// A backend precompile or syscall proves this primitive directly.
    ///
    /// Dramatically cheaper than proving the equivalent instruction sequence.
    NativePrecompile,
    /// A pure-Rust implementation compiled into the guest.
    ///
    /// Produces identical output, but every instruction is proven, so the cost
    /// is far higher. Correct - not free.
    Portable,
    /// Not available on this backend in any form.
    Unsupported,
}

impl fmt::Display for CryptoImplementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativePrecompile => f.write_str("native precompile"),
            Self::Portable => f.write_str("portable software"),
            Self::Unsupported => f.write_str("unsupported"),
        }
    }
}

/// A backend's per-primitive crypto support report.
///
/// Built by adapters from their [`CapabilitySet`] so the two can never
/// disagree - a mismatch between "advertises SHA-256 acceleration" and "what
/// the guest actually links against" is exactly the bug this type prevents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSupport {
    sha256: CryptoImplementation,
    keccak256: CryptoImplementation,
}

impl CryptoSupport {
    /// Derives a report from a backend's capability set.
    ///
    /// An acceleration bit yields [`CryptoImplementation::NativePrecompile`];
    /// its absence yields [`CryptoImplementation::Portable`], because both
    /// primitives have vetted software implementations that any guest can link.
    #[must_use]
    pub const fn from_capabilities(caps: CapabilitySet) -> Self {
        Self {
            sha256: if caps.contains(CapabilitySet::SHA256_ACCEL) {
                CryptoImplementation::NativePrecompile
            } else {
                CryptoImplementation::Portable
            },
            keccak256: if caps.contains(CapabilitySet::KECCAK_ACCEL) {
                CryptoImplementation::NativePrecompile
            } else {
                CryptoImplementation::Portable
            },
        }
    }

    /// A report in which nothing is accelerated.
    ///
    /// The honest answer for the mock backend and for any adapter that has not
    /// yet verified its precompile wiring.
    #[must_use]
    pub const fn portable_only() -> Self {
        Self {
            sha256: CryptoImplementation::Portable,
            keccak256: CryptoImplementation::Portable,
        }
    }

    /// How `primitive` is realised on this backend.
    #[must_use]
    pub const fn implementation(self, primitive: CryptoPrimitive) -> CryptoImplementation {
        match primitive {
            CryptoPrimitive::Sha256 => self.sha256,
            CryptoPrimitive::Keccak256 => self.keccak256,
        }
    }

    /// Returns `true` when `primitive` is proven by a backend precompile.
    ///
    /// Use this to choose between algorithms when proving cost matters - for
    /// example preferring SHA-256 over Keccak-256 on a backend that accelerates
    /// only the former.
    #[must_use]
    pub const fn is_accelerated(self, primitive: CryptoPrimitive) -> bool {
        matches!(
            self.implementation(primitive),
            CryptoImplementation::NativePrecompile
        )
    }
}

/// Portable SHA-256, used by the host and by guests with no precompile.
///
/// Delegates to the audited `sha2` crate. Guests on a backend that reports
/// [`CryptoImplementation::NativePrecompile`] should use the accelerated path
/// exposed by `unified-zkvm-guest` instead; the output is identical, the
/// proving cost is not.
///
/// ```
/// // FIPS 180-4 vector for the empty input.
/// let d = unified_zkvm_core::crypto::sha256(b"");
/// assert_eq!(
///     d[..4],
///     [0xe3, 0xb0, 0xc4, 0x42],
/// );
/// ```
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_official_vectors() {
        // FIPS 180-4 / NIST CAVP.
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn acceleration_is_reported_only_when_the_capability_bit_is_set() {
        let accel = CryptoSupport::from_capabilities(CapabilitySet::SHA256_ACCEL);
        assert!(accel.is_accelerated(CryptoPrimitive::Sha256));
        // Keccak was not claimed, so it must fall back to portable, not inherit
        // the SHA-256 claim.
        assert!(!accel.is_accelerated(CryptoPrimitive::Keccak256));
        assert_eq!(
            accel.implementation(CryptoPrimitive::Keccak256),
            CryptoImplementation::Portable
        );
    }

    #[test]
    fn portable_only_claims_no_acceleration_at_all() {
        let p = CryptoSupport::portable_only();
        assert!(!p.is_accelerated(CryptoPrimitive::Sha256));
        assert!(!p.is_accelerated(CryptoPrimitive::Keccak256));
    }
}
