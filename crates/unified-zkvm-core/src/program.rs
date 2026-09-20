//! Program identity and program artifacts.
//!
//! # Why identity is not just a 32-byte hash
//!
//! It is tempting to define `ProgramId([u8; 32])` and be done. That would be
//! wrong, because the supported backends do not agree on the shape of program
//! identity:
//!
//! * RISC Zero uses an **image ID** - a 32-byte Poseidon/SHA digest of the
//!   initial memory image.
//! * SP1 uses a **verifying key** whose canonical digest is 8 `u32` words
//!   (32 bytes when packed little-endian).
//! * OpenVM uses a pair of commitments (`app_exe_commit`, `app_vm_commit`).
//!
//! The first two fit a 32-byte digest; the third does not. So [`ProgramIdValue`]
//! is an enum with a fast path for the common case and an escape hatch for
//! backends that genuinely need more, rather than forcing every backend to lie
//! about its identity representation.
//!
//! # Security
//!
//! Verification **must** bind proof, program identity and public values
//! together. A proof that verifies cryptographically but was produced by a
//! different program proves nothing about your computation. See
//! [`crate::proof::ZkProof::verify_binding`].

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backend::BackendId;
use crate::error::ZkVmError;

/// Maximum accepted size of a program artifact, in bytes (64 MiB).
///
/// Guest ELF binaries are typically well under a megabyte. The limit exists so
/// that loading an untrusted artifact cannot trigger an unbounded allocation.
pub const MAX_PROGRAM_BYTES: usize = 64 * 1024 * 1024;

/// Maximum accepted length of a non-digest program identifier, in bytes.
pub const MAX_PROGRAM_ID_BYTES: usize = 1024;

/// The backend-specific representation of a program's identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProgramIdValue {
    /// A 32-byte digest.
    ///
    /// Used by backends whose native identity is exactly 32 bytes: RISC Zero
    /// image IDs and SP1 verifying-key digests both land here.
    Digest32([u8; 32]),

    /// An opaque backend-defined identifier.
    ///
    /// Used when identity is not a single digest - for example OpenVM's pair of
    /// commitments. The bytes are compared for equality and never interpreted
    /// by the core crate.
    Opaque(Vec<u8>),
}

impl ProgramIdValue {
    /// Returns the identifier as a byte slice for comparison or hashing.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Digest32(d) => d.as_slice(),
            Self::Opaque(b) => b.as_slice(),
        }
    }

    /// Returns the 32-byte digest, if this identity is a digest.
    ///
    /// Returns `None` for [`Self::Opaque`] identities rather than hashing them
    /// into a digest, because a derived digest would not match anything the
    /// backend itself recognises.
    #[must_use]
    pub fn as_digest32(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Digest32(d) => Some(d),
            Self::Opaque(_) => None,
        }
    }
}

/// The identity of a compiled guest program, scoped to a backend.
///
/// Two `ProgramId`s are equal only if both the backend and the identifier match.
/// This is deliberate: the same guest source compiled for SP1 and for RISC Zero
/// produces two unrelated identities, and treating them as interchangeable
/// would be a soundness bug in the abstraction layer.
///
/// ```
/// use unified_zkvm_core::{BackendId, ProgramId};
///
/// let a = ProgramId::from_digest(BackendId::Sp1, [7u8; 32]);
/// let b = ProgramId::from_digest(BackendId::Risc0, [7u8; 32]);
///
/// // Same bytes, different backends: NOT the same program.
/// assert_ne!(a, b);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProgramId {
    backend: BackendId,
    value: ProgramIdValue,
}

impl ProgramId {
    /// Builds an identity from a backend-native 32-byte digest.
    #[must_use]
    pub const fn from_digest(backend: BackendId, digest: [u8; 32]) -> Self {
        Self {
            backend,
            value: ProgramIdValue::Digest32(digest),
        }
    }

    /// Builds an identity from an opaque backend-defined identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::SizeLimitExceeded`] if `bytes` is longer than
    /// [`MAX_PROGRAM_ID_BYTES`], or [`ZkVmError::InvalidProgram`] if empty.
    pub fn from_opaque(backend: BackendId, bytes: Vec<u8>) -> Result<Self, ZkVmError> {
        if bytes.is_empty() {
            return Err(ZkVmError::InvalidProgram {
                reason: String::from("program identifier must not be empty"),
            });
        }
        if bytes.len() > MAX_PROGRAM_ID_BYTES {
            return Err(ZkVmError::SizeLimitExceeded {
                context: "program identifier",
                claimed: bytes.len(),
                limit: MAX_PROGRAM_ID_BYTES,
            });
        }
        Ok(Self {
            backend,
            value: ProgramIdValue::Opaque(bytes),
        })
    }

    /// Builds an identity from eight little-endian `u32` words.
    ///
    /// SP1 reports verifying-key digests as `[u32; 8]`; this is the canonical
    /// conversion used by that adapter. The word order and endianness are fixed
    /// here so that the same key always yields the same [`ProgramId`] on every
    /// host architecture.
    #[must_use]
    pub fn from_u32_words(backend: BackendId, words: [u32; 8]) -> Self {
        let mut digest = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        Self::from_digest(backend, digest)
    }

    /// The backend this identity belongs to.
    #[must_use]
    pub const fn backend(&self) -> BackendId {
        self.backend
    }

    /// The backend-specific identifier value.
    #[must_use]
    pub const fn value(&self) -> &ProgramIdValue {
        &self.value
    }

    /// The identifier bytes, for logging or comparison.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// Renders the identity as a short hex string suitable for logs.
    ///
    /// Truncated to 8 bytes: enough to distinguish programs during debugging,
    /// short enough to keep log lines readable. Never use this for comparison -
    /// use [`PartialEq`] on the full value.
    #[must_use]
    pub fn short_hex(&self) -> String {
        let bytes = self.as_bytes();
        let take = bytes.len().min(8);
        let mut s = String::with_capacity(take * 2);
        for b in &bytes[..take] {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Display for ProgramId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.backend, self.short_hex())
    }
}

/// A compiled guest program together with its backend identity.
///
/// The artifact owns the program bytes (typically a RISC-V ELF). Backends that
/// need a further-processed form - OpenVM transpiles the ELF into a `VmExe`,
/// SP1 wraps it in its own `Elf` type - perform that conversion inside the
/// adapter, keeping vendor types out of the portable layer.
#[derive(Clone, PartialEq, Eq)]
pub struct ProgramArtifact {
    id: ProgramId,
    bytes: Vec<u8>,
}

impl ProgramArtifact {
    /// Creates an artifact from program bytes and a precomputed identity.
    ///
    /// The identity is supplied by the adapter rather than derived here,
    /// because only the backend can compute an identifier its own verifier will
    /// accept.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::InvalidProgram`] if `bytes` is empty, or
    /// [`ZkVmError::SizeLimitExceeded`] if it exceeds [`MAX_PROGRAM_BYTES`].
    pub fn new(id: ProgramId, bytes: Vec<u8>) -> Result<Self, ZkVmError> {
        if bytes.is_empty() {
            return Err(ZkVmError::InvalidProgram {
                reason: String::from("program artifact is empty"),
            });
        }
        if bytes.len() > MAX_PROGRAM_BYTES {
            return Err(ZkVmError::SizeLimitExceeded {
                context: "program artifact",
                claimed: bytes.len(),
                limit: MAX_PROGRAM_BYTES,
            });
        }
        Ok(Self { id, bytes })
    }

    /// The program's backend-scoped identity.
    #[must_use]
    pub const fn id(&self) -> &ProgramId {
        &self.id
    }

    /// The raw program bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Size of the program in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the artifact holds no bytes.
    ///
    /// Always `false` for artifacts built through [`Self::new`], which rejects
    /// empty input; present because clippy expects it alongside `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Computes a domain-separated digest of the artifact contents.
    ///
    /// # Construction
    ///
    /// ```text
    /// SHA-256( "unified-zkvm:program:v1" || backend_u16_le || len_u64_le || bytes )
    /// ```
    ///
    /// The domain tag prevents this digest colliding with any other hash in the
    /// project, and the explicit length prefix prevents the concatenation
    /// ambiguity that unprefixed hashing would allow.
    ///
    /// # Security
    ///
    /// This digest is an **integrity aid for caching and logging only**. It is
    /// not the backend's notion of program identity and must never be
    /// substituted for [`Self::id`] during verification.
    #[must_use]
    pub fn content_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"unified-zkvm:program:v1");
        hasher.update((self.id.backend() as u16).to_le_bytes());
        hasher.update((self.bytes.len() as u64).to_le_bytes());
        hasher.update(&self.bytes);
        hasher.finalize().into()
    }
}

impl fmt::Debug for ProgramArtifact {
    /// Prints size and identity but never the program bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProgramArtifact")
            .field("id", &self.id)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn identity_is_scoped_to_its_backend() {
        let sp1 = ProgramId::from_digest(BackendId::Sp1, [1u8; 32]);
        let r0 = ProgramId::from_digest(BackendId::Risc0, [1u8; 32]);
        assert_ne!(
            sp1, r0,
            "identical digests on different backends must differ"
        );
    }

    #[test]
    fn u32_word_conversion_is_little_endian_and_stable() {
        let id = ProgramId::from_u32_words(BackendId::Sp1, [0x0403_0201, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&id.as_bytes()[..4], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn opaque_identifiers_reject_empty_and_oversized_input() {
        assert!(ProgramId::from_opaque(BackendId::OpenVm, vec![]).is_err());
        let huge = vec![0u8; MAX_PROGRAM_ID_BYTES + 1];
        assert!(matches!(
            ProgramId::from_opaque(BackendId::OpenVm, huge),
            Err(ZkVmError::SizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn opaque_identity_has_no_digest_rather_than_a_fabricated_one() {
        let id = ProgramId::from_opaque(BackendId::OpenVm, vec![9, 9]).unwrap();
        assert!(
            id.value().as_digest32().is_none(),
            "must not invent a digest the backend would not recognise"
        );
    }

    #[test]
    fn artifact_rejects_empty_programs() {
        let id = ProgramId::from_digest(BackendId::Mock, [0u8; 32]);
        assert!(matches!(
            ProgramArtifact::new(id, vec![]),
            Err(ZkVmError::InvalidProgram { .. })
        ));
    }

    #[test]
    fn content_digest_is_domain_separated_across_backends() {
        // Same bytes under different backends must not collide, or a cache
        // keyed on the digest could serve an SP1 artifact for a RISC Zero run.
        let a = ProgramArtifact::new(
            ProgramId::from_digest(BackendId::Sp1, [0u8; 32]),
            vec![1, 2, 3],
        )
        .unwrap();
        let b = ProgramArtifact::new(
            ProgramId::from_digest(BackendId::Risc0, [0u8; 32]),
            vec![1, 2, 3],
        )
        .unwrap();
        assert_ne!(a.content_digest(), b.content_digest());
    }

    #[test]
    fn debug_output_never_leaks_program_bytes() {
        let a = ProgramArtifact::new(
            ProgramId::from_digest(BackendId::Mock, [0u8; 32]),
            vec![0xde, 0xad, 0xbe, 0xef],
        )
        .unwrap();
        let rendered = format!("{a:?}");
        assert!(!rendered.contains("deadbeef"));
        assert!(!rendered.contains("222"), "no raw byte values: {rendered}");
    }
}
