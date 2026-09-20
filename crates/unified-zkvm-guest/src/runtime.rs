//! The guest runtime abstraction and its backend implementations.
//!
//! [`GuestRuntime`] is the single seam between portable guest code and a zkVM's
//! native I/O. It has two methods, because that is genuinely all a guest needs:
//! read a blob from the host, and commit a blob as public output. Everything
//! else in this crate — typed I/O, crypto — is built on top of those two.
//!
//! Which implementation is active is decided by cargo features at compile time,
//! so there is no dispatch cost: the selected runtime's methods are the only
//! ones compiled in.

use alloc::vec::Vec;

use unified_zkvm_core::ZkVmError;

/// A zkVM's raw guest I/O channel.
///
/// # Implementing
///
/// Backend adapters implement this to map onto their native API. The contract:
///
/// * [`read_bytes`](Self::read_bytes) returns exactly the framed blob the host
///   wrote, with no truncation or re-framing.
/// * [`commit_bytes`](Self::commit_bytes) appends to the public output in call
///   order; ordering is observable to the verifier.
///
/// Both are associated functions rather than methods because guest runtimes are
/// process-global — there is exactly one host channel per guest execution, and
/// modelling it as an instance would imply a choice that does not exist.
pub trait GuestRuntime {
    /// Reads the next input blob from the host.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Serialization`] if the host channel yields no
    /// well-formed message.
    fn read_bytes() -> Result<Vec<u8>, ZkVmError>;

    /// Commits bytes as public output.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend rejects the commitment. Most native
    /// implementations are infallible and always return `Ok`.
    fn commit_bytes(bytes: &[u8]) -> Result<(), ZkVmError>;
}

/// The runtime selected by the active feature set.
///
/// Portable guest code refers to this alias rather than a concrete type, which
/// is what keeps `#[cfg]` out of application code.
#[cfg(all(not(feature = "sp1"), not(feature = "risc0")))]
pub type ActiveRuntime = HostTestRuntime;

/// The runtime selected by the active feature set.
#[cfg(feature = "sp1")]
pub type ActiveRuntime = sp1_runtime::Sp1Runtime;

/// The runtime selected by the active feature set.
#[cfg(feature = "risc0")]
pub type ActiveRuntime = risc0_runtime::Risc0Runtime;

#[cfg(all(not(feature = "sp1"), not(feature = "risc0")))]
mod host_test {
    use super::*;
    use core::cell::RefCell;

    // A guest execution is single-threaded by construction; thread-local state
    // keeps the test runtime free of locks and of `unsafe`, and keeps parallel
    // `cargo test` threads from stepping on each other.
    thread_local! {
        static INPUT: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
        static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    /// The runtime used when no backend feature is enabled.
    ///
    /// It makes guest programs runnable as ordinary Rust, so business logic can
    /// be unit-tested with `cargo test` and no zkVM toolchain. This is the
    /// single biggest contributor to a fast debugging loop — see
    /// `docs/guest-guide.md`.
    ///
    /// # Security
    ///
    /// Executing a guest here produces **no proof of anything**. It is a test
    /// harness, not a zkVM.
    #[derive(Debug, Clone, Copy)]
    pub struct HostTestRuntime;

    impl HostTestRuntime {
        /// Installs the input a subsequent [`GuestRuntime::read_bytes`] returns.
        pub fn set_input(bytes: Vec<u8>) {
            INPUT.with(|i| *i.borrow_mut() = Some(bytes));
        }

        /// Returns everything committed so far and clears the buffer.
        #[must_use]
        pub fn take_output() -> Vec<u8> {
            OUTPUT.with(|o| core::mem::take(&mut *o.borrow_mut()))
        }

        /// Clears both input and output. Call between test cases.
        pub fn reset() {
            INPUT.with(|i| *i.borrow_mut() = None);
            OUTPUT.with(|o| o.borrow_mut().clear());
        }
    }

    impl GuestRuntime for HostTestRuntime {
        fn read_bytes() -> Result<Vec<u8>, ZkVmError> {
            INPUT
                .with(|i| i.borrow_mut().take())
                .ok_or_else(|| ZkVmError::Serialization {
                    context: "host test runtime input",
                    detail: alloc::string::String::from(
                        "no input installed; call HostTestRuntime::set_input first",
                    ),
                })
        }

        fn commit_bytes(bytes: &[u8]) -> Result<(), ZkVmError> {
            OUTPUT.with(|o| o.borrow_mut().extend_from_slice(bytes));
            Ok(())
        }
    }
}

#[cfg(all(not(feature = "sp1"), not(feature = "risc0")))]
pub use host_test::HostTestRuntime;

#[cfg(feature = "sp1")]
mod sp1_runtime {
    use super::*;

    /// Guest runtime backed by SP1's `sp1_zkvm::io`.
    #[derive(Debug, Clone, Copy)]
    pub struct Sp1Runtime;

    impl GuestRuntime for Sp1Runtime {
        fn read_bytes() -> Result<Vec<u8>, ZkVmError> {
            // `read_vec` returns the length-prefixed blob the host wrote with
            // `SP1Stdin::write_slice`, which is exactly our framed message.
            Ok(sp1_zkvm::io::read_vec())
        }

        fn commit_bytes(bytes: &[u8]) -> Result<(), ZkVmError> {
            sp1_zkvm::io::commit_slice(bytes);
            Ok(())
        }
    }
}

#[cfg(feature = "risc0")]
mod risc0_runtime {
    use super::*;

    /// Guest runtime backed by `risc0_zkvm::guest::env`.
    #[derive(Debug, Clone, Copy)]
    pub struct Risc0Runtime;

    impl GuestRuntime for Risc0Runtime {
        fn read_bytes() -> Result<Vec<u8>, ZkVmError> {
            // `read_frame` pairs with the host's `write_frame`, giving a
            // length-delimited blob rather than risc0's word-oriented serde —
            // which is what keeps our canonical framing intact.
            Ok(risc0_zkvm::guest::env::read_frame())
        }

        fn commit_bytes(bytes: &[u8]) -> Result<(), ZkVmError> {
            risc0_zkvm::guest::env::commit_slice(bytes);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_test_runtime_round_trips_a_blob() {
        HostTestRuntime::reset();
        HostTestRuntime::set_input(alloc::vec![1, 2, 3]);
        assert_eq!(HostTestRuntime::read_bytes().unwrap(), alloc::vec![1, 2, 3]);

        HostTestRuntime::commit_bytes(&[9, 9]).unwrap();
        assert_eq!(HostTestRuntime::take_output(), alloc::vec![9, 9]);
    }

    #[test]
    fn reading_without_input_errors_rather_than_returning_empty() {
        // Returning an empty vec would let a guest silently compute on nothing.
        HostTestRuntime::reset();
        assert!(HostTestRuntime::read_bytes().is_err());
    }

    #[test]
    fn commits_accumulate_in_call_order() {
        HostTestRuntime::reset();
        HostTestRuntime::commit_bytes(&[1]).unwrap();
        HostTestRuntime::commit_bytes(&[2]).unwrap();
        assert_eq!(HostTestRuntime::take_output(), alloc::vec![1, 2]);
    }
}
