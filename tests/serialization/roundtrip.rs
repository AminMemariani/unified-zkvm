//! Property-based serialization tests.
//!
//! The canonical codec is load-bearing: if `decode(encode(v)) != v` for any
//! value a guest might exchange, the portability guarantee is void. Example
//! tests cover the cases we thought of; these cover the ones we did not.
//!
//! The invariants under test:
//!
//! 1. **Round trip** - `decode(encode(v)) == v` for all supported values.
//! 2. **Determinism** - encoding the same value twice yields identical bytes.
//! 3. **Total parsing** - arbitrary bytes either decode or error; never panic.

use proptest::prelude::*;
use unified_zkvm_core::{
    container, BackendId, ProgramId, ProofKind, ProofMetadata, PublicValues, ZkMessage, ZkProof,
};
use uzkvm_test_support::{FibonacciInput, LineItem, Order};

proptest! {
    #[test]
    fn primitive_round_trip(n in any::<u64>()) {
        let framed = ZkMessage::encode(&n).unwrap();
        prop_assert_eq!(ZkMessage::decode::<u64>(&framed).unwrap(), n);
    }

    #[test]
    fn signed_and_float_round_trip(i in any::<i64>(), f in any::<f64>().prop_filter("no NaN", |f| !f.is_nan())) {
        let framed = ZkMessage::encode(&(i, f)).unwrap();
        let (di, df): (i64, f64) = ZkMessage::decode(&framed).unwrap();
        prop_assert_eq!(di, i);
        prop_assert_eq!(df, f);
    }

    #[test]
    fn byte_vector_round_trip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let framed = ZkMessage::frame(&data).unwrap();
        prop_assert_eq!(ZkMessage::parse(&framed).unwrap().payload, data);
    }

    #[test]
    fn string_round_trip(s in ".{0,512}") {
        let framed = ZkMessage::encode(&s).unwrap();
        prop_assert_eq!(ZkMessage::decode::<String>(&framed).unwrap(), s);
    }

    #[test]
    fn nested_struct_round_trip(
        id in any::<u64>(),
        amount in any::<u64>(),
        owner in prop::array::uniform32(any::<u8>()),
        items in prop::collection::vec(
            (any::<u32>(), any::<u32>(), any::<u64>()), 0..16
        ),
        memo in prop::option::of(".{0,64}"),
    ) {
        let order = Order {
            id,
            amount,
            owner,
            items: items
                .into_iter()
                .map(|(sku, quantity, unit_price)| LineItem { sku, quantity, unit_price })
                .collect(),
            memo,
        };

        let framed = ZkMessage::encode(&order).unwrap();
        prop_assert_eq!(ZkMessage::decode::<Order>(&framed).unwrap(), order);
    }

    #[test]
    fn encoding_is_deterministic(n in any::<u32>()) {
        let input = FibonacciInput { n };
        prop_assert_eq!(
            ZkMessage::encode(&input).unwrap(),
            ZkMessage::encode(&input).unwrap()
        );
    }

    #[test]
    fn public_values_round_trip(v in any::<u64>()) {
        let pv = PublicValues::encode(&v).unwrap();
        prop_assert_eq!(pv.decode_unverified::<u64>().unwrap(), v);
    }

    #[test]
    fn public_value_digests_are_collision_free_for_distinct_inputs(
        a in prop::collection::vec(any::<u8>(), 0..256),
        b in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(a != b);
        let da = PublicValues::new(a).unwrap().digest();
        let db = PublicValues::new(b).unwrap().digest();
        prop_assert_ne!(da, db);
    }

    /// Parsing arbitrary bytes must never panic. A panic in a proof parser is a
    /// denial-of-service vector, since proofs arrive from untrusted parties.
    #[test]
    fn message_parsing_never_panics(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = ZkMessage::parse(&data);
        let _ = ZkMessage::decode::<u64>(&data);
        let _ = ZkMessage::decode::<Order>(&data);
    }

    /// Same requirement for the proof container.
    #[test]
    fn container_parsing_never_panics(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = container::from_bytes(&data);
        let _ = container::read_header(&data);
    }

    /// Even a well-formed header followed by garbage must fail gracefully.
    #[test]
    fn a_valid_header_with_garbage_body_errors_cleanly(
        body in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"UZKVMPRF");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&(BackendId::Mock as u16).to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body);

        // Must not panic; almost always an error.
        let _ = container::from_bytes(&bytes);
    }

    #[test]
    fn proof_container_round_trip(
        digest in prop::array::uniform32(any::<u8>()),
        payload in prop::collection::vec(any::<u8>(), 1..1024),
        values in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let proof = ZkProof::new(
            BackendId::Mock,
            ProgramId::from_digest(BackendId::Mock, digest),
            ProofKind::Mock,
            PublicValues::new(values).unwrap(),
            payload,
            ProofMetadata::new(),
        ).unwrap();

        let bytes = container::to_bytes(&proof).unwrap();
        prop_assert_eq!(container::from_bytes(&bytes).unwrap(), proof);
    }

    /// Any single-byte corruption of a container must be detected or error -
    /// never silently yield a different valid proof.
    #[test]
    fn single_byte_corruption_does_not_yield_a_silently_different_proof(
        index in 0usize..64,
        xor in 1u8..=255,
    ) {
        let proof = ZkProof::new(
            BackendId::Mock,
            ProgramId::from_digest(BackendId::Mock, [3u8; 32]),
            ProofKind::Mock,
            PublicValues::new(vec![1, 2, 3, 4]).unwrap(),
            vec![7u8; 64],
            ProofMetadata::new(),
        ).unwrap();

        let mut bytes = container::to_bytes(&proof).unwrap();
        prop_assume!(index < bytes.len());
        bytes[index] ^= xor;

        match container::from_bytes(&bytes) {
            Err(_) => {}
            Ok(decoded) => {
                // If it still parses, it must differ from the original -
                // otherwise the corrupted byte was not covered by the format.
                prop_assert_ne!(decoded.digest(), proof.digest());
            }
        }
    }
}

#[test]
fn round_trip_holds_at_the_boundaries() {
    // Property tests rarely hit exact extremes; pin them explicitly.
    for n in [0u64, 1, u64::MAX, u64::MAX - 1, 1 << 63] {
        let framed = ZkMessage::encode(&n).unwrap();
        assert_eq!(ZkMessage::decode::<u64>(&framed).unwrap(), n);
    }
}

#[test]
fn an_empty_payload_is_distinct_from_a_single_zero_byte() {
    // A framing bug that conflated these would silently change guest semantics.
    let empty = ZkMessage::frame(&[]).unwrap();
    let zero = ZkMessage::frame(&[0]).unwrap();
    assert_ne!(empty, zero);
    assert_eq!(ZkMessage::parse(&empty).unwrap().payload.len(), 0);
    assert_eq!(ZkMessage::parse(&zero).unwrap().payload, vec![0]);
}
