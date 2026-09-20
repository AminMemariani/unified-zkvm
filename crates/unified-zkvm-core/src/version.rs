//! Version constants that participate in compatibility checks.
//!
//! These are **not** decorative. Each is part of a wire or disk format and is
//! validated on the decode path; bumping one is a semver-relevant event. See
//! `docs/versioning.md` for the compatibility policy.

/// Semantic version of this crate, taken from Cargo at compile time.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the on-disk proof container produced by
/// [`crate::container`].
///
/// Incremented only when the container layout changes in a way that older
/// readers cannot parse. Decoding rejects unknown versions rather than
/// guessing, so a forward-incompatible file fails closed.
pub const PROOF_CONTAINER_VERSION: u16 = 1;

/// Magic bytes identifying a unified-zkvm proof container.
///
/// Chosen to be 8 ASCII bytes so a `file`/hexdump inspection is legible and so
/// that a truncated or mistyped file is rejected before any length prefix is
/// trusted.
pub const CONTAINER_MAGIC: [u8; 8] = *b"UZKVMPRF";
