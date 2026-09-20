//! Golden test vectors pinning the canonical encoding.
//!
//! # Why these exist
//!
//! The round-trip property tests prove the codec is *self-consistent*. They do
//! not prove it is *unchanged*. Swapping the codec, reordering a struct field,
//! or bumping a dependency could keep every round trip passing while silently
//! changing the bytes a guest sees - and a deployed guest ELF cannot be
//! renegotiated after the fact.
//!
//! These vectors freeze the wire format. A failure here is not a bug in the
//! test; it means the encoding changed and the change is **semver-breaking**.
//! See `docs/versioning.md`.
//!
//! # Vector format
//!
//! Each case states the Rust value, the expected hex of the framed message, and
//! why the case is interesting. Hex is written inline rather than in separate
//! files so a reviewer sees the value and its encoding side by side.

use unified_zkvm_core::{
    container, BackendId, ProgramId, ProofKind, ProofMetadata, PublicValues, ZkMessage, ZkProof,
    ENCODING_VERSION, MESSAGE_MAGIC,
};
use uzkvm_test_support::{fibonacci, FibonacciInput, FibonacciOutput};

/// Asserts that `value` encodes to exactly `expected_hex`.
fn assert_encoding<T: serde::Serialize>(value: &T, expected_hex: &str, why: &str) {
    let framed = ZkMessage::encode(value).expect("encodes");
    let actual = hex::encode(&framed);
    assert_eq!(
        actual, expected_hex,
        "\nCANONICAL ENCODING CHANGED ({why}).\n\
         This is a BREAKING change: deployed guests decode the old bytes.\n\
         expected: {expected_hex}\n\
         actual:   {actual}\n\
         If intentional, bump ENCODING_VERSION and document it in CHANGELOG.md."
    );
}

#[test]
fn frame_header_is_pinned() {
    // magic "ZK", version 1 LE, length 0 LE.
    assert_eq!(
        hex::encode(ZkMessage::frame(&[]).unwrap()),
        "5a4b010000000000"
    );
    assert_eq!(MESSAGE_MAGIC, [0x5A, 0x4B]);
    assert_eq!(ENCODING_VERSION, 1);
}

#[test]
fn small_integers_use_a_single_varint_byte() {
    assert_encoding(&0u32, "5a4b01000100000000", "u32 zero");
    assert_encoding(&1u32, "5a4b01000100000001", "u32 one");
    assert_encoding(&127u32, "5a4b0100010000007f", "u32 varint boundary");
}

#[test]
fn varint_boundary_widens_at_128() {
    // 128 needs two bytes in a LEB128-style varint. Pinning this catches a
    // codec swap that changes integer width encoding.
    assert_encoding(&128u32, "5a4b0100020000008001", "u32 varint widening");
}

#[test]
fn u64_max_is_pinned() {
    assert_encoding(
        &u64::MAX,
        "5a4b01000a000000ffffffffffffffffff01",
        "u64 maximum",
    );
}

#[test]
fn fixed_size_arrays_are_not_length_prefixed() {
    // A fixed array's length is known from the type, so it must NOT carry a
    // prefix. A codec that added one would break guests reading `[u8; 4]`.
    // Note the 4-byte payload versus 5 for the Vec below - that difference is
    // the property under test.
    assert_encoding(&[1u8, 2, 3, 4], "5a4b01000400000001020304", "[u8; 4]");
}

#[test]
fn variable_collections_are_length_prefixed() {
    assert_encoding(
        &vec![1u8, 2, 3, 4],
        "5a4b0100050000000401020304",
        "Vec<u8> carries a length",
    );
}

#[test]
fn strings_are_length_prefixed_utf8() {
    assert_encoding(&"abc", "5a4b01000400000003616263", "&str");
}

#[test]
fn options_encode_a_discriminant() {
    assert_encoding(&Option::<u32>::None, "5a4b01000100000000", "None");
    assert_encoding(&Some(1u32), "5a4b0100020000000101", "Some(1)");
}

#[test]
fn structs_encode_fields_in_declaration_order_without_names() {
    // Field order is part of the wire format: reordering the struct is a
    // breaking change even though the Rust type still compiles.
    assert_encoding(
        &FibonacciInput { n: 20 },
        "5a4b01000100000014",
        "FibonacciInput { n: 20 }",
    );
}

#[test]
fn the_canonical_fibonacci_vector_is_stable() {
    // The project's headline example. n=20 => 6765.
    let input = FibonacciInput { n: 20 };
    let output = fibonacci(input);
    assert_eq!(output.value, 6765);

    let encoded = PublicValues::encode(&output).unwrap();
    assert_eq!(
        encoded.to_hex(),
        "ed3414",
        "the documented fibonacci(20) commitment changed"
    );

    // And it must decode back to the same logical value.
    let decoded: FibonacciOutput = encoded.decode_unverified().unwrap();
    assert_eq!(decoded, output);
}

#[test]
fn public_value_digest_is_pinned() {
    // Domain-separated SHA-256 over the length-prefixed bytes.
    let pv = PublicValues::new(vec![1, 2, 3, 4]).unwrap();
    assert_eq!(
        hex::encode(pv.digest()),
        "15ee9cc5687afc95f094862211d2c631e552e9c5ca847787f45698092b903fb2",
        "the public-value digest construction changed"
    );
}

#[test]
fn container_header_layout_is_pinned() {
    let proof = ZkProof::new(
        BackendId::Mock,
        ProgramId::from_digest(BackendId::Mock, [0u8; 32]),
        ProofKind::Mock,
        PublicValues::empty(),
        vec![0u8; 4],
        ProofMetadata::new(),
    )
    .unwrap();

    let bytes = container::to_bytes(&proof).unwrap();

    assert_eq!(&bytes[0..8], b"UZKVMPRF", "container magic changed");
    assert_eq!(
        &bytes[8..10],
        &1u16.to_le_bytes(),
        "container version changed"
    );
    assert_eq!(
        &bytes[10..12],
        &(BackendId::Mock as u16).to_le_bytes(),
        "backend discriminant changed"
    );
}

#[test]
fn backend_discriminants_are_pinned_to_disk() {
    // These are written into every saved proof. Renumbering silently
    // invalidates archived artifacts.
    assert_eq!(BackendId::Mock as u16, 0);
    assert_eq!(BackendId::Sp1 as u16, 1);
    assert_eq!(BackendId::Risc0 as u16, 2);
    assert_eq!(BackendId::Jolt as u16, 3);
    assert_eq!(BackendId::OpenVm as u16, 4);
    assert_eq!(BackendId::Pico as u16, 5);
}

#[test]
fn edge_cases_of_the_same_type_encode_distinctly() {
    // Within a single type, distinct values must never collide - that is the
    // property the codec owes us. Across *different* types collisions are
    // expected and documented below.
    let vectors: Vec<(&str, Vec<u8>)> = vec![
        ("empty vec", ZkMessage::encode(&Vec::<u8>::new()).unwrap()),
        ("vec of one zero", ZkMessage::encode(&vec![0u8]).unwrap()),
        (
            "vec of two zeros",
            ZkMessage::encode(&vec![0u8, 0]).unwrap(),
        ),
        ("vec of one max", ZkMessage::encode(&vec![0xFFu8]).unwrap()),
    ];

    for (i, (name_a, a)) in vectors.iter().enumerate() {
        for (name_b, b) in vectors.iter().skip(i + 1) {
            assert_ne!(a, b, "`{name_a}` and `{name_b}` must encode differently");
        }
    }

    let integers: Vec<(&str, Vec<u8>)> = vec![
        ("zero", ZkMessage::encode(&0u64).unwrap()),
        ("one", ZkMessage::encode(&1u64).unwrap()),
        ("varint boundary", ZkMessage::encode(&128u64).unwrap()),
        ("max", ZkMessage::encode(&u64::MAX).unwrap()),
    ];

    for (i, (name_a, a)) in integers.iter().enumerate() {
        for (name_b, b) in integers.iter().skip(i + 1) {
            assert_ne!(a, b, "`{name_a}` and `{name_b}` must encode differently");
        }
    }
}

#[test]
fn the_codec_is_not_self_describing_and_the_docs_say_so() {
    // Values of DIFFERENT types can share an encoding: postcard is a
    // non-self-describing format, so the *type* supplies the meaning. Three
    // distinct values below are byte-identical.
    //
    // The consequence is real and documented in docs/guest-guide.md: host and
    // guest must agree on the type, and `zk_read::<T>()` cannot detect a
    // mismatch that happens to be byte-compatible. Program identity is what
    // actually binds the guest's expected type to the proof.
    //
    // Pinned here so nobody "fixes" it by adding type tags, which would bloat
    // guest cycles and break every deployed guest.
    let none = ZkMessage::encode(&Option::<u32>::None).unwrap();
    let zero = ZkMessage::encode(&0u32).unwrap();
    let empty_string = ZkMessage::encode(&"").unwrap();

    assert_eq!(none, zero, "documented codec property changed");
    assert_eq!(zero, empty_string, "documented codec property changed");
}
