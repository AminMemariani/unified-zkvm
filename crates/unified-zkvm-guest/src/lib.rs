//! The backend-neutral guest API.
//!
//! A guest program written against this crate reads its input, computes, and
//! commits its output without naming a zkVM:
//!
//! ```
//! use unified_zkvm_guest::{zk_commit, zk_read};
//! # use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct Input { n: u32 }
//!
//! # fn demo() -> Result<(), unified_zkvm_core::ZkVmError> {
//! let input: Input = zk_read()?;
//! let result = fibonacci(input.n);
//! zk_commit(&result)?;
//! # Ok(())
//! # }
//!
//! // Business logic stays an ordinary Rust function, so it is testable
//! // without a zkVM at all. This is the pattern the guide recommends.
//! fn fibonacci(n: u32) -> u64 {
//!     (0..n).fold((0u64, 1u64), |(a, b), _| (b, a.wrapping_add(b))).0
//! }
//! ```
//!
//! # No `#[cfg(feature = "sp1")]` in your code
//!
//! Conditional compilation over backends is this crate's job, not yours. The
//! backend is chosen by a cargo feature at build time; the calls above are
//! identical either way.
//!
//! # Runtime selection
//!
//! | Features enabled | Runtime | Use |
//! |---|---|---|
//! | none | [`runtime::HostTestRuntime`] | `cargo test` on the host |
//! | `sp1` | SP1 zkVM | proving with SP1 |
//! | `risc0` | RISC Zero zkVM | proving with RISC Zero |
//!
//! Enabling two backend features at once is a compile error — a guest binary
//! targets exactly one zkVM.
//!
//! # Encoding
//!
//! All I/O uses the canonical codec from [`unified_zkvm_core::io`], so a struct
//! written by the host decodes to identical bytes on every backend. See
//! `docs/guest-guide.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

// A guest binary is compiled for one zkVM. Two runtimes would mean two
// conflicting entrypoints and two incompatible syscall ABIs, so catch it here
// with an actionable message rather than at link time.
#[cfg(all(feature = "sp1", feature = "risc0"))]
compile_error!(
    "Multiple zkVM guest backends are enabled (`sp1` and `risc0`).\n\n\
     A guest program targets exactly one zkVM. Enable one backend feature:\n\n    \
     cargo build --no-default-features --features sp1\n\n\
     Building for several backends means several builds, not one binary with \
     several runtimes. See docs/guest-guide.md."
);

pub mod crypto;
pub mod io;
pub mod runtime;

pub use crypto::{keccak256, sha256};
pub use io::{zk_commit, zk_commit_bytes, zk_read, zk_read_bytes};
pub use runtime::GuestRuntime;

/// Re-exported so guests need only one dependency.
pub use unified_zkvm_core::ZkVmError;
