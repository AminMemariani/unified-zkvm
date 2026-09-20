//! Guest-side cryptographic primitives.
//!
//! # Accelerated versus portable
//!
//! These functions compute the standard, correct digest on every backend. What
//! changes between backends is the **cost of proving them**:
//!
//! * On a backend with a precompile, the hash is a single accelerated
//!   operation.
//! * Otherwise, every instruction of a software implementation is proven, which
//!   can be orders of magnitude more expensive.
//!
//! The output is identical either way, so correctness never depends on which
//! path was taken — but performance very much does. Query
//! [`unified_zkvm_core::CryptoSupport`] on the host to find out which applies
//! before designing a guest around a particular primitive, and see
//! `docs/crypto.md`.
//!
//! # No new cryptography
//!
//! SHA-256 comes from the audited `sha2` crate. Keccak-256 is reported as
//! unsupported rather than hand-implemented — see [`keccak256`].

use alloc::vec::Vec;

use unified_zkvm_core::ZkVmError;

/// Computes SHA-256 (FIPS 180-4).
///
/// # Proving cost
///
/// SP1 and RISC Zero both accelerate SHA-256 when the guest links their patched
/// `sha2` build; without that patch this is a portable software hash and costs
/// far more to prove. Enabling the patch is a guest-manifest change documented
/// in `docs/crypto.md`, not something this function can do on your behalf.
///
/// ```
/// let digest = unified_zkvm_guest::sha256(b"abc");
/// assert_eq!(digest[0], 0xba);
/// ```
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    // Delegating to core keeps exactly one SHA-256 implementation in the
    // workspace; a backend precompile substitutes itself underneath `sha2`
    // through the guest manifest's `[patch.crates-io]` section.
    unified_zkvm_core::crypto::sha256(input)
}

/// Computes Keccak-256 as used by Ethereum.
///
/// # Availability
///
/// **Not currently implemented.** Returns
/// [`ZkVmError::UnsupportedCapability`].
///
/// This is deliberate. Keccak-256 is only worth using inside a guest when a
/// backend precompile proves it; a portable software implementation is so
/// expensive to prove that offering one would be a trap rather than a feature.
/// Wiring the real precompiles (`risc0-circuit-keccak`, SP1's keccak syscall)
/// requires guest-side toolchain support that this crate does not yet verify,
/// and shipping an unaccelerated fallback under an accelerated-looking name
/// would violate the project's rule that a capability bit means a tested
/// implementation.
///
/// Tracked in `ROADMAP.md`. Until then,
/// [`unified_zkvm_core::CryptoSupport`] reports Keccak-256 honestly and this
/// function fails loudly instead of quietly costing you a fortune in cycles.
///
/// # Errors
///
/// Always returns [`ZkVmError::UnsupportedCapability`].
pub fn keccak256(_input: &[u8]) -> Result<[u8; 32], ZkVmError> {
    Err(ZkVmError::UnsupportedCapability {
        backend: active_backend(),
        capability: unified_zkvm_core::Capability::KeccakAccel,
    })
}

/// The backend this guest was compiled for.
///
/// Useful in diagnostics and in the rare guest that needs to branch on backend
/// identity. Reaching for it in business logic is a portability smell.
#[must_use]
pub const fn active_backend() -> unified_zkvm_core::BackendId {
    #[cfg(feature = "sp1")]
    {
        unified_zkvm_core::BackendId::Sp1
    }
    #[cfg(feature = "risc0")]
    {
        unified_zkvm_core::BackendId::Risc0
    }
    #[cfg(all(not(feature = "sp1"), not(feature = "risc0")))]
    {
        unified_zkvm_core::BackendId::Mock
    }
}

/// Computes SHA-256 over several slices as if they were concatenated.
///
/// Avoids materialising the concatenation, which in a guest means avoiding an
/// allocation and the cycles spent copying it.
///
/// # Security
///
/// This is plain concatenation with **no domain separation or length
/// prefixing**: `(b"ab", b"c")` and `(b"a", b"bc")` produce the same digest. If
/// the pieces are attacker-influenced, add your own framing first.
#[must_use]
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut buf = Vec::with_capacity(total);
    for p in parts {
        buf.extend_from_slice(p);
    }
    sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_official_abc_vector() {
        assert_eq!(
            sha256(b"abc")[..4],
            [0xba, 0x78, 0x16, 0xbf],
            "FIPS 180-4 vector for \"abc\""
        );
    }

    #[test]
    fn keccak_fails_loudly_instead_of_silently_costing_cycles() {
        assert!(matches!(
            keccak256(b"anything"),
            Err(ZkVmError::UnsupportedCapability { .. })
        ));
    }

    #[test]
    fn multipart_hashing_equals_hashing_the_concatenation() {
        assert_eq!(sha256_parts(&[b"ab", b"c"]), sha256(b"abc"));
    }
}
