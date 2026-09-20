//! Negative security tests: what the system must **refuse**.
//!
//! Happy-path tests prove a library works. These prove it does not work when it
//! shouldn't — which is the only property that matters when a proof arrives
//! from someone with an incentive to lie.
//!
//! Every test here corresponds to a concrete attack:
//!
//! | Test | Attack it blocks |
//! |---|---|
//! | tampered proof bytes | forging a proof of a different execution |
//! | tampered public values | claiming a different output for a real proof |
//! | wrong program identity | reusing a valid proof of a *different* program |
//! | cross-backend verification | passing a weak proof to a strong verifier |
//! | oversized length prefix | memory-exhaustion denial of service |
//! | truncated / malformed container | parser confusion |
//! | rewritten container header | routing a proof to the wrong verifier |

use unified_zkvm_core::{
    container, BackendAdapter, BackendId, CapabilitySet, ProgramId, ProofKind, ProofMetadata,
    ProvingOptions, PublicValues, ZkMessage, ZkProof, ZkVmError,
};
use unified_zkvm_host::{Verifier, ZkHostRunner};
use unified_zkvm_mock::MockBackend;

fn backend() -> MockBackend {
    MockBackend::new().with_guest(|input| {
        let n: u32 = ZkMessage::decode(input)?;
        postcard::to_allocvec(&(u64::from(n) * 2)).map_err(|e| ZkVmError::Serialization {
            context: "test guest",
            detail: e.to_string(),
        })
    })
}

fn setup() -> (MockBackend, unified_zkvm_core::ProgramArtifact, ZkProof) {
    let b = backend();
    let program = b.build_program(b"victim-program").unwrap();
    let runner = ZkHostRunner::new(b.clone());
    let proof = runner.prove(&program, &21u32).unwrap();
    (b, program, proof)
}

#[test]
fn a_proof_with_flipped_payload_bits_is_rejected() {
    let (b, program, proof) = setup();

    for bit in [0usize, 7, 128, 255] {
        let mut bytes = proof.proof_bytes().to_vec();
        bytes[bit / 8] ^= 1 << (bit % 8);

        let forged = ZkProof::new(
            BackendId::Mock,
            program.id().clone(),
            proof.kind().clone(),
            proof.public_values_unverified().clone(),
            bytes,
            ProofMetadata::new(),
        )
        .unwrap();

        assert!(
            matches!(
                b.verify(&forged, &program),
                Err(ZkVmError::VerificationFailed { .. })
            ),
            "flipping bit {bit} must be detected"
        );
    }
}

#[test]
fn rewriting_public_values_on_a_real_proof_is_rejected() {
    // The highest-value attack: take a genuine proof and claim it attests to a
    // more favourable output.
    let (b, program, proof) = setup();

    let lie = PublicValues::encode(&u64::MAX).unwrap();
    let forged = ZkProof::new(
        BackendId::Mock,
        program.id().clone(),
        proof.kind().clone(),
        lie,
        proof.proof_bytes().to_vec(),
        ProofMetadata::new(),
    )
    .unwrap();

    assert!(matches!(
        b.verify(&forged, &program),
        Err(ZkVmError::VerificationFailed { .. })
    ));
}

#[test]
fn a_valid_proof_of_a_different_program_is_rejected() {
    // The classic mistake: verifying cryptography while ignoring *what* was
    // proven. A perfectly valid proof of program A says nothing about B.
    let (b, program_a, proof_a) = setup();
    let program_b = b.build_program(b"different-program").unwrap();

    assert_ne!(program_a.id(), program_b.id());
    assert!(matches!(
        b.verify(&proof_a, &program_b),
        Err(ZkVmError::ProgramIdMismatch { .. })
    ));
}

#[test]
fn a_proof_cannot_be_relabelled_onto_another_program_identity() {
    let (b, original_program, proof) = setup();
    let other = b.build_program(b"other-program").unwrap();
    assert_ne!(original_program.id(), other.id());

    // Attacker rewrites the envelope's claimed identity to match the target.
    let relabelled = ZkProof::new(
        BackendId::Mock,
        other.id().clone(),
        proof.kind().clone(),
        proof.public_values_unverified().clone(),
        proof.proof_bytes().to_vec(),
        ProofMetadata::new(),
    )
    .unwrap();

    // Binding now passes, so the checksum must catch it: the tag commits to the
    // program identity, so relabelling invalidates it.
    assert!(matches!(
        b.verify(&relabelled, &other),
        Err(ZkVmError::VerificationFailed { .. })
    ));
}

#[test]
fn a_mock_proof_cannot_be_presented_as_a_real_backend_proof() {
    // The guard that keeps the development backend from becoming a forgery
    // tool: the envelope refuses to pair a Mock backend with a foreign
    // program identity at construction time.
    let err = ZkProof::new(
        BackendId::Sp1,
        ProgramId::from_digest(BackendId::Mock, [0u8; 32]),
        ProofKind::Mock,
        PublicValues::empty(),
        vec![1, 2, 3],
        ProofMetadata::new(),
    );
    assert!(matches!(err, Err(ZkVmError::InvalidProof { .. })));
}

#[test]
fn cross_backend_verification_is_refused_before_any_crypto_runs() {
    let (_b, program, _proof) = setup();

    let foreign = ZkProof::new(
        BackendId::Sp1,
        ProgramId::from_digest(BackendId::Sp1, [9u8; 32]),
        ProofKind::Native,
        PublicValues::empty(),
        vec![0u8; 32],
        ProofMetadata::new(),
    )
    .unwrap();

    assert!(matches!(
        foreign.verify_binding(&program),
        Err(ZkVmError::BackendMismatch { .. })
    ));
}

#[test]
fn a_container_with_a_hostile_length_prefix_is_refused_without_allocating() {
    let (_b, _program, proof) = setup();
    let mut bytes = container::to_bytes(&proof).unwrap();

    // Claim a 4 GiB body. Must be rejected on the declared value alone.
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(matches!(
        container::from_bytes(&bytes),
        Err(ZkVmError::SizeLimitExceeded { .. })
    ));
}

#[test]
fn every_truncation_of_a_container_is_rejected() {
    let (_b, _program, proof) = setup();
    let bytes = container::to_bytes(&proof).unwrap();

    for cut in 0..bytes.len() {
        assert!(
            container::from_bytes(&bytes[..cut]).is_err(),
            "truncation at byte {cut} must be rejected, not partially parsed"
        );
    }
}

#[test]
fn a_container_whose_header_backend_was_rewritten_is_rejected() {
    // Attempts to route a mock proof to a real verifier by editing the routing
    // header only. The header/body cross-check catches it.
    let (_b, _program, proof) = setup();
    let mut bytes = container::to_bytes(&proof).unwrap();
    bytes[10..12].copy_from_slice(&(BackendId::Risc0 as u16).to_le_bytes());

    assert!(matches!(
        container::from_bytes(&bytes),
        Err(ZkVmError::InvalidProof { .. })
    ));
}

#[test]
fn arbitrary_bytes_are_never_parsed_as_a_proof() {
    for junk in [
        b"".as_slice(),
        b"UZKVMPRF".as_slice(),
        b"not a proof at all, just some text".as_slice(),
        &[0xFFu8; 64],
        &[0x00u8; 1024],
    ] {
        assert!(
            container::from_bytes(junk).is_err(),
            "junk input must not parse as a proof"
        );
    }
}

#[test]
fn a_guest_message_with_a_lying_length_is_refused() {
    let mut framed = ZkMessage::encode(&42u32).unwrap();
    framed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(matches!(
        ZkMessage::parse(&framed),
        Err(ZkVmError::SizeLimitExceeded { .. })
    ));
}

#[test]
fn an_unsupported_capability_fails_loudly_rather_than_degrading() {
    // A backend that cannot verify must refuse, not return a vacuous success.
    let crippled =
        MockBackend::new().with_capabilities(CapabilitySet::GUEST_IO | CapabilitySet::PROVE);
    let program = crippled.build_program(b"g").unwrap();
    let proof = crippled
        .prove(
            &program,
            &ZkMessage::encode(&1u32).unwrap(),
            &ProvingOptions::default(),
        )
        .unwrap();

    let verifier = Verifier::new(crippled);
    assert!(matches!(
        verifier.verify(&proof, &program),
        Err(ZkVmError::UnsupportedCapability { .. })
    ));
}

#[test]
fn an_unsupported_proof_kind_is_refused_rather_than_downgraded() {
    let b = backend();
    let program = b.build_program(b"g").unwrap();

    let err = b.prove(
        &program,
        &ZkMessage::encode(&1u32).unwrap(),
        &ProvingOptions::new(ProofKind::Onchain),
    );

    assert!(
        matches!(err, Err(ZkVmError::UnsupportedProofKind { .. })),
        "a silent downgrade would change on-chain verifiability without telling the caller"
    );
}

#[test]
fn security_rejections_are_distinguishable_from_operational_failures() {
    // Callers must be able to tell "retry might help" from "someone is lying".
    let (b, program_a, proof) = setup();
    let program_b = b.build_program(b"another").unwrap();

    let err = b.verify(&proof, &program_b).unwrap_err();
    assert!(
        err.is_security_rejection(),
        "a program mismatch is an authenticity failure and must be classified as one"
    );
    assert_ne!(program_a.id(), program_b.id());
}

#[test]
fn the_verifier_is_actually_invoked_and_not_short_circuited() {
    // Guards against a regression where an early return makes verification a
    // no-op: the counter proves the real verify path ran.
    let (b, program, proof) = setup();
    let before = b.verify_call_count();
    b.verify(&proof, &program).unwrap();
    assert_eq!(b.verify_call_count(), before + 1);
}
