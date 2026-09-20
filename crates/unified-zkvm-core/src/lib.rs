//! Backend-neutral core types for [`unified-zkvm`].
//!
//! This crate is the stable center of the project. It deliberately depends on
//! **no** zkVM SDK: adding `unified-zkvm-core` to a project pulls in `serde`,
//! `postcard`, `bitflags` and `sha2` — nothing else. Every heavyweight proving
//! dependency lives behind a backend adapter crate.
//!
//! # What lives here
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`error`] | The [`ZkVmError`] hierarchy shared by every backend |
//! | [`backend`] | [`BackendId`] and the [`BackendAdapter`] contract |
//! | [`capabilities`] | [`CapabilitySet`] — what a backend *actually* implements |
//! | [`program`] | [`ProgramId`] / [`ProgramArtifact`] — program identity |
//! | [`proof`] | [`ZkProof`] — the portable proof envelope |
//! | [`public_values`] | [`PublicValues`] — committed output bytes |
//! | [`io`] | Canonical guest I/O encoding ([`ZkMessage`]) |
//! | [`crypto`] | Crypto capability reporting and portable fallbacks |
//! | [`container`] | The on-disk `UZKVMPRF` proof container |
//!
//! # Design rule
//!
//! *Portable by default, backend-specific by capability.* Anything that cannot
//! be expressed identically across backends is surfaced through
//! [`CapabilitySet`] and fails loudly with
//! [`ZkVmError::UnsupportedCapability`] rather than being silently emulated.
//!
//! # `no_std`
//!
//! The crate is `no_std + alloc` when built with `default-features = false`.
//! The `std` feature adds [`std::error::Error`] impls and filesystem helpers.
//!
//! # Security
//!
//! Reading [`PublicValues`] from an unverified [`ZkProof`] is meaningless.
//! The API is arranged so that verification happens first — see
//! [`proof::VerifiedPublicValues`] and `docs/security-model.md`.
//!
//! [`unified-zkvm`]: https://github.com/unified-zkvm/unified-zkvm

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

pub mod backend;
pub mod capabilities;
pub mod container;
pub mod crypto;
pub mod error;
pub mod io;
pub mod program;
pub mod proof;
pub mod public_values;
pub mod version;

pub use backend::{
    BackendAdapter, BackendDescriptor, BackendId, ExecutionResult, IntegrationStatus, ResourceUsage,
};
pub use capabilities::{Capability, CapabilitySet};
pub use crypto::{CryptoImplementation, CryptoPrimitive, CryptoSupport};
pub use error::{Operation, Stage, ZkVmError};
pub use io::{ZkMessage, ENCODING_VERSION, MAX_MESSAGE_BYTES, MESSAGE_MAGIC};
pub use program::{ProgramArtifact, ProgramId, ProgramIdValue};
pub use proof::{
    FallbackPolicy, ProofKind, ProofMetadata, ProvingOptions, VerificationWitness,
    VerifiedPublicValues, VerifierIdentity, ZkProof,
};
pub use public_values::PublicValues;
pub use version::{CORE_VERSION, PROOF_CONTAINER_VERSION};

/// Convenient result alias used throughout the workspace.
pub type Result<T, E = ZkVmError> = core::result::Result<T, E>;
