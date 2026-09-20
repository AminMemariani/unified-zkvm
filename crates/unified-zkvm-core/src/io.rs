//! The canonical guest I/O encoding.
//!
//! # Why a canonical codec at all
//!
//! Each backend has its own host-to-guest channel, and each SDK applies its own
//! serialization on the way through. SP1 uses `bincode`-flavoured framing;
//! RISC Zero has its own word-oriented `serde` implementation; OpenVM works in
//! field elements. If unified-zkvm simply forwarded a Rust struct to whichever
//! SDK was active, then *the same struct would arrive with different bytes on
//! different backends* — and a guest reading a fixed-size array or relying on
//! field order would behave differently per backend. That failure is silent and
//! extremely hard to debug, and it would make the project's central promise
//! false.
//!
//! So unified-zkvm encodes once, canonically, and treats the backend channel as
//! an opaque byte pipe.
//!
//! ```text
//!   Application value
//!         │  postcard (canonical, deterministic)
//!         ▼
//!    ZkMessage { version, payload }
//!         │  framed: magic ‖ version ‖ len ‖ payload
//!         ▼
//!    opaque bytes ──► SP1 stdin / RISC Zero env / OpenVM StdIn
//! ```
//!
//! # Format specification
//!
//! | Offset | Size | Field | Notes |
//! |---|---|---|---|
//! | 0 | 2 | magic | `0x5A`, `0x4B` (`"ZK"`) |
//! | 2 | 2 | version | `u16` little-endian |
//! | 4 | 4 | length | `u32` little-endian, payload byte count |
//! | 8 | n | payload | canonical `postcard` encoding |
//!
//! * **Endianness** is little-endian everywhere, matching the RISC-V guests all
//!   supported backends target, so no byte swapping occurs on the hot path.
//! * **Length** is a `u32`, bounded further by [`MAX_MESSAGE_BYTES`].
//! * **Versioning**: a decoder rejects any version it does not know rather than
//!   attempting a best-effort parse.
//! * **Malformed input** always produces an error; the decoder never panics and
//!   never allocates based on an unvalidated length field.
//!
//! # Why postcard
//!
//! It is `no_std`-friendly, has no padding or alignment surprises, and encodes
//! deterministically — the same value always produces the same bytes, which is
//! a prerequisite for the golden test vectors in `tests/vectors/`.

use alloc::string::ToString;
use alloc::vec::Vec;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::ZkVmError;

/// Current canonical encoding version.
///
/// Bumping this is a breaking change for guests: a host encoding v2 and a guest
/// decoding v1 must fail loudly, which it does — see [`ZkMessage::decode`].
pub const ENCODING_VERSION: u16 = 1;

/// Magic bytes prefixing every framed message.
pub const MESSAGE_MAGIC: [u8; 2] = [0x5A, 0x4B];

/// Size of the frame header in bytes.
pub const HEADER_LEN: usize = 8;

/// Maximum accepted payload size, in bytes (256 MiB).
///
/// Bounds allocation when decoding data that may be attacker-controlled. Guest
/// inputs this large are already impractical to prove, so the limit does not
/// constrain legitimate use.
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024 * 1024;

/// A versioned, length-framed message carrying canonically encoded data.
///
/// ```
/// use unified_zkvm_core::ZkMessage;
///
/// let framed = ZkMessage::encode(&(42u32, "hello"))?;
/// let (n, s): (u32, String) = ZkMessage::decode(&framed)?;
///
/// assert_eq!(n, 42);
/// assert_eq!(s, "hello");
/// # Ok::<(), unified_zkvm_core::ZkVmError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkMessage {
    /// Encoding version this message was produced with.
    pub version: u16,
    /// Canonically encoded payload.
    pub payload: Vec<u8>,
}

impl ZkMessage {
    /// Encodes a value into a complete framed message.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Serialization`] if `value` cannot be encoded, or
    /// [`ZkVmError::SizeLimitExceeded`] if the result exceeds
    /// [`MAX_MESSAGE_BYTES`].
    pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ZkVmError> {
        let payload = postcard::to_allocvec(value).map_err(|e| ZkVmError::Serialization {
            context: "guest message payload",
            detail: e.to_string(),
        })?;
        Self::frame(&payload)
    }

    /// Frames already-encoded payload bytes.
    ///
    /// Used by the byte-oriented guest API, which passes data through without
    /// interpreting it.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::SizeLimitExceeded`] if `payload` is too large.
    pub fn frame(payload: &[u8]) -> Result<Vec<u8>, ZkVmError> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(ZkVmError::SizeLimitExceeded {
                context: "guest message payload",
                claimed: payload.len(),
                limit: MAX_MESSAGE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&MESSAGE_MAGIC);
        out.extend_from_slice(&ENCODING_VERSION.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Parses a framed message without decoding its payload.
    ///
    /// # Security
    ///
    /// Validates magic, version and declared length against the buffer actually
    /// present **before** allocating, so a hostile length field cannot cause an
    /// out-of-memory abort.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::InvalidProof`] for a bad magic or truncated frame,
    /// [`ZkVmError::UnsupportedVersion`] for an unknown version, and
    /// [`ZkVmError::SizeLimitExceeded`] for an oversized declared length.
    pub fn parse(bytes: &[u8]) -> Result<Self, ZkVmError> {
        if bytes.len() < HEADER_LEN {
            return Err(ZkVmError::InvalidProof {
                reason: alloc::format!(
                    "guest message is {} bytes, shorter than the {HEADER_LEN}-byte header",
                    bytes.len()
                ),
            });
        }
        if bytes[0..2] != MESSAGE_MAGIC {
            return Err(ZkVmError::InvalidProof {
                reason: alloc::string::String::from(
                    "guest message magic mismatch; data is not a unified-zkvm message",
                ),
            });
        }

        let version = u16::from_le_bytes([bytes[2], bytes[3]]);
        if version != ENCODING_VERSION {
            return Err(ZkVmError::UnsupportedVersion {
                context: "guest message",
                found: version,
                supported: ENCODING_VERSION,
            });
        }

        let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        if declared > MAX_MESSAGE_BYTES {
            return Err(ZkVmError::SizeLimitExceeded {
                context: "guest message payload",
                claimed: declared,
                limit: MAX_MESSAGE_BYTES,
            });
        }

        let available = bytes.len() - HEADER_LEN;
        if declared != available {
            return Err(ZkVmError::InvalidProof {
                reason: alloc::format!(
                    "guest message declares {declared} payload bytes but {available} are present"
                ),
            });
        }

        Ok(Self {
            version,
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }

    /// Parses and decodes a framed message into a typed value.
    ///
    /// # Errors
    ///
    /// Propagates framing errors from [`Self::parse`] and returns
    /// [`ZkVmError::Serialization`] if the payload does not decode into `T`.
    pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ZkVmError> {
        let msg = Self::parse(bytes)?;
        postcard::from_bytes(&msg.payload).map_err(|e| ZkVmError::Serialization {
            context: "guest message payload",
            detail: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Nested {
        id: u64,
        name: String,
        tags: Vec<u8>,
        inner: Option<alloc::boxed::Box<Nested>>,
    }

    #[test]
    fn round_trip_holds_for_nested_structures() {
        let v = Nested {
            id: u64::MAX,
            name: String::from("order"),
            tags: vec![1, 2, 3],
            inner: Some(alloc::boxed::Box::new(Nested {
                id: 0,
                name: String::new(),
                tags: vec![],
                inner: None,
            })),
        };
        let framed = ZkMessage::encode(&v).unwrap();
        assert_eq!(ZkMessage::decode::<Nested>(&framed).unwrap(), v);
    }

    #[test]
    fn encoding_is_deterministic() {
        // Golden vectors and cross-backend comparison both depend on this.
        let v = (1u32, "a", [9u8; 3]);
        assert_eq!(
            ZkMessage::encode(&v).unwrap(),
            ZkMessage::encode(&v).unwrap()
        );
    }

    #[test]
    fn header_layout_matches_the_documented_specification() {
        let framed = ZkMessage::frame(&[0xAA, 0xBB]).unwrap();
        assert_eq!(&framed[0..2], &MESSAGE_MAGIC);
        assert_eq!(&framed[2..4], &1u16.to_le_bytes());
        assert_eq!(&framed[4..8], &2u32.to_le_bytes());
        assert_eq!(&framed[8..], &[0xAA, 0xBB]);
    }

    #[test]
    fn empty_payloads_round_trip() {
        let framed = ZkMessage::frame(&[]).unwrap();
        assert_eq!(ZkMessage::parse(&framed).unwrap().payload.len(), 0);
    }

    #[test]
    fn truncated_frames_are_rejected() {
        let framed = ZkMessage::frame(&[1, 2, 3, 4]).unwrap();
        for cut in 0..framed.len() {
            assert!(
                ZkMessage::parse(&framed[..cut]).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
    }

    #[test]
    fn a_lying_length_prefix_never_causes_a_huge_allocation() {
        // Declares 4 GiB of payload while carrying none. Must be refused on the
        // declared value alone, before any allocation is attempted.
        let mut framed = ZkMessage::frame(&[]).unwrap();
        framed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            ZkMessage::parse(&framed),
            Err(ZkVmError::SizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn unknown_versions_fail_closed_rather_than_guessing() {
        let mut framed = ZkMessage::frame(&[1]).unwrap();
        framed[2..4].copy_from_slice(&999u16.to_le_bytes());
        assert!(matches!(
            ZkMessage::parse(&framed),
            Err(ZkVmError::UnsupportedVersion { found: 999, .. })
        ));
    }

    #[test]
    fn foreign_data_is_rejected_by_the_magic_check() {
        assert!(ZkMessage::parse(b"not a zk message at all").is_err());
    }

    #[test]
    fn declared_length_must_match_the_bytes_actually_present() {
        let mut framed = ZkMessage::frame(&[1, 2, 3, 4]).unwrap();
        framed[4..8].copy_from_slice(&3u32.to_le_bytes());
        assert!(ZkMessage::parse(&framed).is_err());
    }
}
