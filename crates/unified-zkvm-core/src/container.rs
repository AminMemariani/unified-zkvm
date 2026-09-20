//! The `UZKVMPRF` proof container: a stable on-disk format for [`ZkProof`].
//!
//! # Why a container exists
//!
//! Each SDK has its own save/load convention, and several have none. A proof
//! that cannot be handed to another process is not much use, and "just
//! `bincode` the struct" would tie the file format to a dependency's internal
//! encoding choices - a silent breaking change every time that dependency
//! bumps.
//!
//! The container is deliberately thin. It adds a self-identifying header and
//! delegates the body to the same canonical codec used everywhere else.
//!
//! # Layout
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | magic `UZKVMPRF` |
//! | 8 | 2 | container version, `u16` little-endian |
//! | 10 | 2 | backend discriminant, `u16` little-endian |
//! | 12 | 4 | body length, `u32` little-endian |
//! | 16 | n | canonically encoded [`ZkProof`] |
//!
//! The backend appears in the header as well as the body so that tooling can
//! route a file without deserializing it, and so a corrupted body is caught by
//! a cheap cross-check.
//!
//! # Security
//!
//! Every header field is validated before the body is touched, and the declared
//! length is checked against both [`MAX_CONTAINER_BODY_BYTES`] and the bytes
//! actually present. Loading a container performs **no verification** - it
//! returns an unverified [`ZkProof`], and the caller must still verify it.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::backend::BackendId;
use crate::error::ZkVmError;
use crate::proof::ZkProof;
use crate::version::{CONTAINER_MAGIC, PROOF_CONTAINER_VERSION};

/// Size of the container header in bytes.
pub const CONTAINER_HEADER_LEN: usize = 16;

/// Maximum accepted container body size, in bytes (512 MiB).
pub const MAX_CONTAINER_BODY_BYTES: usize = 512 * 1024 * 1024;

/// Serializes a proof into the container format.
///
/// # Errors
///
/// Returns [`ZkVmError::Serialization`] if encoding fails, or
/// [`ZkVmError::SizeLimitExceeded`] if the encoded body is too large.
///
/// ```
/// # use unified_zkvm_core::{container, BackendId, ProgramId, ProofKind, ProofMetadata, PublicValues, ZkProof};
/// # let proof = ZkProof::new(
/// #     BackendId::Mock,
/// #     ProgramId::from_digest(BackendId::Mock, [1u8; 32]),
/// #     ProofKind::Mock,
/// #     PublicValues::empty(),
/// #     vec![1, 2, 3],
/// #     ProofMetadata::default(),
/// # )?;
/// let bytes = container::to_bytes(&proof)?;
/// let restored = container::from_bytes(&bytes)?;
///
/// assert_eq!(proof, restored);
/// # Ok::<(), unified_zkvm_core::ZkVmError>(())
/// ```
pub fn to_bytes(proof: &ZkProof) -> Result<Vec<u8>, ZkVmError> {
    let body = postcard::to_allocvec(proof).map_err(|e| ZkVmError::Serialization {
        context: "proof container body",
        detail: e.to_string(),
    })?;

    if body.len() > MAX_CONTAINER_BODY_BYTES {
        return Err(ZkVmError::SizeLimitExceeded {
            context: "proof container body",
            claimed: body.len(),
            limit: MAX_CONTAINER_BODY_BYTES,
        });
    }

    let mut out = Vec::with_capacity(CONTAINER_HEADER_LEN + body.len());
    out.extend_from_slice(&CONTAINER_MAGIC);
    out.extend_from_slice(&PROOF_CONTAINER_VERSION.to_le_bytes());
    out.extend_from_slice(&(proof.backend() as u16).to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Header fields read from a container without decoding its body.
///
/// Lets tooling answer "which backend produced this file?" cheaply, and lets a
/// host reject a proof for a backend it has not enabled before paying to
/// deserialize it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerHeader {
    /// Container format version.
    pub version: u16,
    /// Backend that produced the proof.
    pub backend: BackendId,
    /// Declared body length in bytes.
    pub body_len: usize,
}

/// Reads and validates a container header.
///
/// # Errors
///
/// Returns [`ZkVmError::InvalidProof`] for a bad magic or truncated buffer,
/// [`ZkVmError::UnsupportedVersion`] for an unknown container version, and
/// [`ZkVmError::SizeLimitExceeded`] for an implausible declared length.
pub fn read_header(bytes: &[u8]) -> Result<ContainerHeader, ZkVmError> {
    if bytes.len() < CONTAINER_HEADER_LEN {
        return Err(ZkVmError::InvalidProof {
            reason: format!(
                "proof container is {} bytes, shorter than the {CONTAINER_HEADER_LEN}-byte header",
                bytes.len()
            ),
        });
    }
    if bytes[0..8] != CONTAINER_MAGIC {
        return Err(ZkVmError::InvalidProof {
            reason: String::from("proof container magic mismatch; not a unified-zkvm proof file"),
        });
    }

    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != PROOF_CONTAINER_VERSION {
        return Err(ZkVmError::UnsupportedVersion {
            context: "proof container",
            found: version,
            supported: PROOF_CONTAINER_VERSION,
        });
    }

    let backend = BackendId::from_u16(u16::from_le_bytes([bytes[10], bytes[11]]))?;

    let body_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    if body_len > MAX_CONTAINER_BODY_BYTES {
        return Err(ZkVmError::SizeLimitExceeded {
            context: "proof container body",
            claimed: body_len,
            limit: MAX_CONTAINER_BODY_BYTES,
        });
    }

    Ok(ContainerHeader {
        version,
        backend,
        body_len,
    })
}

/// Deserializes a proof from the container format.
///
/// # Security
///
/// The returned proof is **unverified**. Loading a file proves nothing; call a
/// verifier before trusting its public values.
///
/// # Errors
///
/// Propagates header errors from [`read_header`], and returns
/// [`ZkVmError::InvalidProof`] if the body is truncated or if the header's
/// backend disagrees with the body's.
pub fn from_bytes(bytes: &[u8]) -> Result<ZkProof, ZkVmError> {
    let header = read_header(bytes)?;

    let available = bytes.len() - CONTAINER_HEADER_LEN;
    if header.body_len != available {
        return Err(ZkVmError::InvalidProof {
            reason: format!(
                "proof container declares a {} byte body but {available} bytes are present",
                header.body_len
            ),
        });
    }

    let proof: ZkProof = postcard::from_bytes(&bytes[CONTAINER_HEADER_LEN..]).map_err(|e| {
        ZkVmError::Serialization {
            context: "proof container body",
            detail: e.to_string(),
        }
    })?;

    // Cross-check: a header/body disagreement means corruption or tampering,
    // and routing on the header would then load the wrong verifier.
    if proof.backend() != header.backend {
        return Err(ZkVmError::InvalidProof {
            reason: format!(
                "proof container header names backend `{}` but the body contains `{}`",
                header.backend,
                proof.backend()
            ),
        });
    }

    Ok(proof)
}

#[cfg(feature = "std")]
mod fs {
    use super::*;
    use std::path::Path;

    /// Writes a proof to `path` in container format.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Io`] on write failure, or a serialization error
    /// from [`to_bytes`].
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn save(proof: &ZkProof, path: impl AsRef<Path>) -> Result<(), ZkVmError> {
        let path = path.as_ref();
        let bytes = to_bytes(proof)?;
        std::fs::write(path, bytes).map_err(|source| ZkVmError::Io {
            context: path.display().to_string(),
            source,
        })
    }

    /// Reads a proof from `path`.
    ///
    /// # Security
    ///
    /// The proof is returned **unverified**; a file on disk carries no
    /// authenticity guarantee. Verify before use.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Io`] on read failure, or a parse error from
    /// [`from_bytes`].
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn load(path: impl AsRef<Path>) -> Result<ZkProof, ZkVmError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|source| ZkVmError::Io {
            context: path.display().to_string(),
            source,
        })?;
        from_bytes(&bytes)
    }
}

#[cfg(feature = "std")]
pub use fs::{load, save};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::ProgramId;
    use crate::proof::{ProofKind, ProofMetadata};
    use crate::public_values::PublicValues;
    use alloc::vec;

    fn sample() -> ZkProof {
        ZkProof::new(
            BackendId::Mock,
            ProgramId::from_digest(BackendId::Mock, [0xAB; 32]),
            ProofKind::Mock,
            PublicValues::new(vec![1, 2, 3, 4]).unwrap(),
            vec![0xCD; 128],
            ProofMetadata::default(),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_preserves_the_proof_exactly() {
        let p = sample();
        assert_eq!(from_bytes(&to_bytes(&p).unwrap()).unwrap(), p);
    }

    #[test]
    fn header_is_readable_without_decoding_the_body() {
        let bytes = to_bytes(&sample()).unwrap();
        let h = read_header(&bytes).unwrap();
        assert_eq!(h.backend, BackendId::Mock);
        assert_eq!(h.version, PROOF_CONTAINER_VERSION);
        assert_eq!(h.body_len, bytes.len() - CONTAINER_HEADER_LEN);
    }

    #[test]
    fn every_truncation_is_rejected() {
        let bytes = to_bytes(&sample()).unwrap();
        for cut in 0..bytes.len() {
            assert!(
                from_bytes(&bytes[..cut]).is_err(),
                "truncation at byte {cut} must be rejected"
            );
        }
    }

    #[test]
    fn a_hostile_length_field_is_refused_before_allocation() {
        let mut bytes = to_bytes(&sample()).unwrap();
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            from_bytes(&bytes),
            Err(ZkVmError::SizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn a_rewritten_header_backend_is_caught_by_the_cross_check() {
        // Simulates tampering that tries to route a mock proof to a real
        // verifier by editing only the header.
        let mut bytes = to_bytes(&sample()).unwrap();
        bytes[10..12].copy_from_slice(&(BackendId::Sp1 as u16).to_le_bytes());
        assert!(matches!(
            from_bytes(&bytes),
            Err(ZkVmError::InvalidProof { .. })
        ));
    }

    #[test]
    fn unknown_container_versions_fail_closed() {
        let mut bytes = to_bytes(&sample()).unwrap();
        bytes[8..10].copy_from_slice(&42u16.to_le_bytes());
        assert!(matches!(
            from_bytes(&bytes),
            Err(ZkVmError::UnsupportedVersion { found: 42, .. })
        ));
    }

    #[test]
    fn unknown_backend_discriminants_are_rejected() {
        let mut bytes = to_bytes(&sample()).unwrap();
        bytes[10..12].copy_from_slice(&777u16.to_le_bytes());
        assert!(from_bytes(&bytes).is_err());
    }

    #[test]
    fn foreign_files_are_rejected_by_the_magic_check() {
        assert!(from_bytes(b"this is definitely not a proof container").is_err());
    }
}
