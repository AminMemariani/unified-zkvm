//! Public values committed by a guest program.
//!
//! # The trust boundary
//!
//! Public values are just bytes until a proof binding them to a program has
//! been verified. This module deliberately makes the untrusted case slightly
//! inconvenient to use: [`PublicValues::decode_unverified`] is spelled out in
//! full so it cannot be reached for by accident, while the pleasant API lives
//! on [`crate::proof::VerifiedPublicValues`], which can only be obtained after
//! a successful verification.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ZkVmError;
use crate::io::MAX_MESSAGE_BYTES;

/// Bytes a guest committed as its public output.
///
/// The encoding is the canonical unified-zkvm codec (see [`crate::io`]), so the
/// same guest struct decodes identically regardless of which backend produced
/// the proof. That portability is the point: without a canonical codec, "the
/// same program on a different backend" would return subtly different bytes.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicValues {
    bytes: Vec<u8>,
}

impl PublicValues {
    /// Wraps raw committed bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::SizeLimitExceeded`] if the buffer exceeds
    /// [`MAX_MESSAGE_BYTES`], bounding memory use when handling values that
    /// arrived from an untrusted source.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ZkVmError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(ZkVmError::SizeLimitExceeded {
                context: "public values",
                claimed: bytes.len(),
                limit: MAX_MESSAGE_BYTES,
            });
        }
        Ok(Self { bytes })
    }

    /// Creates an empty set of public values, for guests that commit nothing.
    #[must_use]
    pub const fn empty() -> Self {
        Self { bytes: Vec::new() }
    }

    /// The raw committed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes this value and returns the owned bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of committed bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the guest committed nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Decodes the committed bytes **without any proof having been verified**.
    ///
    /// # Security
    ///
    /// The returned value carries **no guarantee whatsoever**. It is the
    /// attacker-controlled content of a proof you have not checked. Legitimate
    /// uses are limited to:
    ///
    /// * inspecting the output of a local [`crate::BackendAdapter::execute`]
    ///   run, which was never proven in the first place;
    /// * debugging and tooling.
    ///
    /// For anything that influences a decision, verify first and use
    /// [`crate::proof::VerifiedPublicValues::decode`].
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Serialization`] if the bytes are not valid
    /// canonical encoding for `T`.
    pub fn decode_unverified<T: DeserializeOwned>(&self) -> Result<T, ZkVmError> {
        postcard::from_bytes(&self.bytes).map_err(|e| ZkVmError::Serialization {
            context: "public values",
            detail: e.to_string(),
        })
    }

    /// Encodes a value into public values using the canonical codec.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Serialization`] if `value` cannot be encoded, or
    /// [`ZkVmError::SizeLimitExceeded`] if the result is too large.
    pub fn encode<T: Serialize>(value: &T) -> Result<Self, ZkVmError> {
        let bytes = postcard::to_allocvec(value).map_err(|e| ZkVmError::Serialization {
            context: "public values",
            detail: e.to_string(),
        })?;
        Self::new(bytes)
    }

    /// A domain-separated digest of the committed bytes.
    ///
    /// # Construction
    ///
    /// ```text
    /// SHA-256( "unified-zkvm:public-values:v1" || len_u64_le || bytes )
    /// ```
    ///
    /// The length prefix removes concatenation ambiguity: without it, the
    /// commitments `("ab", "c")` and `("a", "bc")` would hash identically.
    ///
    /// # Security
    ///
    /// This digest is for comparison and logging. It is **not** the commitment
    /// a backend's verifier checks — each backend has its own construction.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"unified-zkvm:public-values:v1");
        h.update((self.bytes.len() as u64).to_le_bytes());
        h.update(&self.bytes);
        h.finalize().into()
    }

    /// Renders the bytes as hex, for test vectors and debugging output.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.bytes.len() * 2);
        for b in &self.bytes {
            s.push_str(&alloc::format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Debug for PublicValues {
    /// Shows length and digest rather than contents.
    ///
    /// Public values are not secret, but they can be large, and dumping them
    /// into every log line is noise. The digest is enough to correlate.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = self.digest();
        write!(
            f,
            "PublicValues {{ len: {}, digest: {:02x}{:02x}{:02x}{:02x}.. }}",
            self.bytes.len(),
            d[0],
            d[1],
            d[2],
            d[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_preserves_typed_values() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Out {
            n: u32,
            tag: [u8; 4],
        }
        let original = Out {
            n: 6765,
            tag: *b"fib!",
        };
        let pv = PublicValues::encode(&original).unwrap();
        assert_eq!(pv.decode_unverified::<Out>().unwrap(), original);
    }

    #[test]
    fn digest_is_length_prefixed_so_splits_do_not_collide() {
        let a = PublicValues::new(vec![b'a', b'b']).unwrap();
        let b = PublicValues::new(vec![b'a']).unwrap();
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn oversized_values_are_rejected_before_use() {
        let too_big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(
            PublicValues::new(too_big),
            Err(ZkVmError::SizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn malformed_bytes_fail_to_decode_rather_than_producing_garbage() {
        // postcard varint with a continuation bit but no following byte.
        let pv = PublicValues::new(vec![0xFF]).unwrap();
        assert!(pv.decode_unverified::<u64>().is_err());
    }

    #[test]
    fn debug_shows_digest_not_contents() {
        let pv = PublicValues::new(vec![0xAA; 64]).unwrap();
        let s = alloc::format!("{pv:?}");
        assert!(s.contains("len: 64"));
        assert!(!s.contains("aaaaaaaa"));
    }
}
