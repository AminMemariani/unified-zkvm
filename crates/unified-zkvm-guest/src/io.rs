//! Typed and byte-oriented guest I/O.
//!
//! These four functions are the entire portable guest surface. They delegate
//! framing to [`unified_zkvm_core::ZkMessage`] and transport to the active
//! [`GuestRuntime`], so the encoding a guest sees is identical on every backend.

use alloc::vec::Vec;

use serde::de::DeserializeOwned;
use serde::Serialize;
use unified_zkvm_core::{ZkMessage, ZkVmError};

use crate::runtime::{ActiveRuntime, GuestRuntime};

/// Reads and decodes a typed value supplied by the host.
///
/// # Errors
///
/// Returns [`ZkVmError::Serialization`] if the host wrote a value that does not
/// decode into `T`, or [`ZkVmError::UnsupportedVersion`] if the host uses a
/// newer encoding than this guest was built against — a real hazard when a
/// guest ELF is cached and the host is upgraded.
///
/// ```
/// # use unified_zkvm_guest::zk_read;
/// # fn demo() -> Result<(), unified_zkvm_core::ZkVmError> {
/// let n: u32 = zk_read()?;
/// # Ok(())
/// # }
/// ```
pub fn zk_read<T: DeserializeOwned>() -> Result<T, ZkVmError> {
    let framed = ActiveRuntime::read_bytes()?;
    ZkMessage::decode(&framed)
}

/// Reads a raw blob supplied by the host, unframed.
///
/// Use when the guest handles bytes directly — hashing a payload, say — and no
/// typed structure is involved.
///
/// # Errors
///
/// Returns an error if the host channel yields no well-formed message.
pub fn zk_read_bytes() -> Result<Vec<u8>, ZkVmError> {
    let framed = ActiveRuntime::read_bytes()?;
    Ok(ZkMessage::parse(&framed)?.payload)
}

/// Commits a typed value as public output.
///
/// # Security
///
/// Committed values are public: they appear in the proof and are readable by
/// anyone who holds it. Never commit a secret input or an intermediate value
/// derived from one — the whole point of the private witness is that it stays
/// out of here.
///
/// # Errors
///
/// Returns [`ZkVmError::Serialization`] if `value` cannot be encoded.
///
/// ```
/// # use unified_zkvm_guest::zk_commit;
/// # fn demo() -> Result<(), unified_zkvm_core::ZkVmError> {
/// zk_commit(&6765u64)?;
/// # Ok(())
/// # }
/// ```
pub fn zk_commit<T: Serialize + ?Sized>(value: &T) -> Result<(), ZkVmError> {
    let encoded = postcard::to_allocvec_wrapper(value)?;
    ActiveRuntime::commit_bytes(&encoded)
}

/// Commits raw bytes as public output.
///
/// The bytes are committed verbatim, with no framing, so a host reading them
/// back sees exactly what was written.
///
/// # Security
///
/// The same rule applies as for [`zk_commit`]: these bytes are public.
///
/// # Errors
///
/// Returns an error if the backend rejects the commitment.
pub fn zk_commit_bytes(bytes: &[u8]) -> Result<(), ZkVmError> {
    ActiveRuntime::commit_bytes(bytes)
}

// Encoding helper kept private so the guest surface stays at four functions.
mod postcard {
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use serde::Serialize;
    use unified_zkvm_core::ZkVmError;

    pub fn to_allocvec_wrapper<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>, ZkVmError> {
        ::postcard::to_allocvec(v).map_err(|e| ZkVmError::Serialization {
            context: "guest public value",
            detail: e.to_string(),
        })
    }
}

#[cfg(all(test, not(feature = "sp1"), not(feature = "risc0")))]
mod tests {
    use super::*;
    use crate::runtime::HostTestRuntime;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Order {
        id: u64,
        amount: u64,
        owner: [u8; 32],
    }

    #[test]
    fn typed_values_survive_the_host_to_guest_round_trip() {
        HostTestRuntime::reset();
        let order = Order {
            id: 42,
            amount: 1_000,
            owner: [7u8; 32],
        };
        HostTestRuntime::set_input(ZkMessage::encode(&order).unwrap());

        assert_eq!(zk_read::<Order>().unwrap(), order);
    }

    #[test]
    fn raw_blobs_survive_the_round_trip_unframed() {
        HostTestRuntime::reset();
        HostTestRuntime::set_input(ZkMessage::frame(&[1, 2, 3]).unwrap());
        assert_eq!(zk_read_bytes().unwrap(), alloc::vec![1, 2, 3]);
    }

    #[test]
    fn committed_values_are_decodable_by_the_host() {
        HostTestRuntime::reset();
        zk_commit(&12345u64).unwrap();
        let out = HostTestRuntime::take_output();
        assert_eq!(::postcard::from_bytes::<u64>(&out).unwrap(), 12345);
    }

    #[test]
    fn a_type_mismatch_is_an_error_not_silent_garbage() {
        HostTestRuntime::reset();
        // Host wrote a string; guest expects a fixed-size array.
        HostTestRuntime::set_input(ZkMessage::encode("not an array").unwrap());
        assert!(zk_read::<[u8; 32]>().is_err());
    }

    #[test]
    fn a_future_encoding_version_is_rejected_loudly() {
        HostTestRuntime::reset();
        let mut framed = ZkMessage::encode(&1u32).unwrap();
        framed[2..4].copy_from_slice(&2u16.to_le_bytes());
        HostTestRuntime::set_input(framed);
        assert!(matches!(
            zk_read::<u32>(),
            Err(ZkVmError::UnsupportedVersion { .. })
        ));
    }
}
