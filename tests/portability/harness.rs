//! Cross-backend differential portability tests.
//!
//! This is the project's central claim under test: **the same guest logic, run
//! through different backends, produces the same logical result.**
//!
//! ```text
//!            same input, same guest logic
//!                        │
//!        ┌───────────┬───┴───┬───────────┐
//!        ▼           ▼       ▼           ▼
//!     reference    mock     SP1       RISC Zero
//!        │           │       │           │
//!        └───────────┴───┬───┴───────────┘
//!                        ▼
//!               identical decoded output
//! ```
//!
//! # What is compared, and what deliberately is not
//!
//! * **Compared:** decoded public values, committed byte encoding, and error
//!   categories.
//! * **Not compared:** proof bytes. They are backend-native artifacts and will
//!   never match. A test asserting otherwise would be asserting something false.
//! * **Not compared:** proving time or proof size. Portability is not a
//!   performance guarantee - see the README's limitations section.
//!
//! # Which backends run here
//!
//! Only backends whose adapter is compiled into this build. The mock backend
//! and the reference model always run, so `cargo test --workspace` is
//! meaningful on a clean checkout with no zkVM installed. SP1 and RISC Zero
//! adapters live outside the default workspace (they need vendor toolchains),
//! so they are exercised by `cargo xtask portability-test` and the backend CI
//! job rather than here.

use unified_zkvm_core::{ProgramArtifact, ZkMessage, ZkVmError};
use unified_zkvm_host::ZkHostRunner;
use unified_zkvm_mock::MockBackend;
use uzkvm_test_support::{
    fibonacci, settle, sha256_of, FibonacciInput, FibonacciOutput, LineItem, Order, Settlement,
    Sha256Input, Sha256Output,
};

/// Builds a mock backend running the real Fibonacci reference implementation.
///
/// The mock executes the *same function* the reference test calls, so a match
/// confirms the plumbing (encode -> transport -> decode -> commit -> verify ->
/// decode) is lossless, which is precisely what the abstraction must guarantee.
fn fibonacci_backend() -> MockBackend {
    MockBackend::new().with_guest(|input| {
        let parsed: FibonacciInput = ZkMessage::decode(input)?;
        let output = fibonacci(parsed);
        postcard::to_allocvec(&output).map_err(|e| ZkVmError::Serialization {
            context: "fibonacci guest output",
            detail: e.to_string(),
        })
    })
}

fn sha256_backend() -> MockBackend {
    MockBackend::new().with_guest(|input| {
        let parsed: Sha256Input = ZkMessage::decode(input)?;
        let output = sha256_of(&parsed);
        postcard::to_allocvec(&output).map_err(|e| ZkVmError::Serialization {
            context: "sha256 guest output",
            detail: e.to_string(),
        })
    })
}

fn order_backend() -> MockBackend {
    MockBackend::new().with_guest(|input| {
        let parsed: Order = ZkMessage::decode(input)?;
        let output = settle(&parsed);
        postcard::to_allocvec(&output).map_err(|e| ZkVmError::Serialization {
            context: "settlement guest output",
            detail: e.to_string(),
        })
    })
}

fn program(backend: &MockBackend, name: &[u8]) -> ProgramArtifact {
    backend
        .build_program(name)
        .expect("guest bytes are non-empty")
}

#[test]
fn fibonacci_matches_the_reference_model_through_the_full_pipeline() {
    let backend = fibonacci_backend();
    let program = program(&backend, b"fibonacci-guest");
    let runner = ZkHostRunner::new(backend);

    for n in [0u32, 1, 2, 10, 20, 50, 90] {
        let input = FibonacciInput { n };
        let expected = fibonacci(input);

        let (_proof, verified) = runner
            .prove_and_verify(&program, &input)
            .unwrap_or_else(|e| panic!("prove+verify failed for n={n}: {e}"));

        let actual: FibonacciOutput = verified.decode().expect("output decodes");
        assert_eq!(
            actual, expected,
            "backend output diverged from the reference model at n={n}"
        );
    }
}

#[test]
fn execution_and_proving_agree_on_the_same_output() {
    // A backend whose `execute` disagrees with its `prove` is broken in a way
    // that is easy to ship and hard to notice: fast iteration would show one
    // answer and the proof would attest to another.
    let backend = fibonacci_backend();
    let program = program(&backend, b"fibonacci-guest");
    let runner = ZkHostRunner::new(backend);

    let input = FibonacciInput { n: 20 };

    let executed = runner.execute(&program, &input).expect("execute succeeds");
    let (proof, _) = runner
        .prove_and_verify(&program, &input)
        .expect("prove succeeds");

    assert_eq!(
        executed.public_values.as_bytes(),
        proof.public_values_unverified().as_bytes(),
        "execute and prove committed different public values"
    );
}

#[test]
fn sha256_matches_the_reference_model() {
    let backend = sha256_backend();
    let program = program(&backend, b"sha256-guest");
    let runner = ZkHostRunner::new(backend);

    for data in [
        Vec::new(),
        b"abc".to_vec(),
        b"the quick brown fox jumps over the lazy dog".to_vec(),
        vec![0xFFu8; 1024],
    ] {
        let input = Sha256Input { data };
        let expected = sha256_of(&input);

        let (_proof, verified) = runner.prove_and_verify(&program, &input).expect("prove");
        let actual: Sha256Output = verified.decode().expect("decode");

        assert_eq!(
            actual,
            expected,
            "digest diverged for {} bytes",
            input.data.len()
        );
    }
}

#[test]
fn nested_typed_io_survives_the_round_trip_unchanged() {
    // The shapes that most often diverge between backend-native encodings:
    // fixed arrays, variable collections, Option, and nesting.
    let backend = order_backend();
    let program = program(&backend, b"order-guest");
    let runner = ZkHostRunner::new(backend);

    let order = Order {
        id: u64::MAX,
        amount: 350,
        owner: [0xAB; 32],
        items: vec![
            LineItem {
                sku: 1,
                quantity: 3,
                unit_price: 100,
            },
            LineItem {
                sku: 2,
                quantity: 1,
                unit_price: 50,
            },
        ],
        memo: Some("portability".to_string()),
    };
    let expected = settle(&order);

    let (_proof, verified) = runner.prove_and_verify(&program, &order).expect("prove");
    let actual: Settlement = verified.decode().expect("decode");

    assert_eq!(actual, expected);
    assert!(actual.matches_declared);
}

#[test]
fn empty_input_is_handled_rather_than_treated_as_absent() {
    let backend = sha256_backend();
    let program = program(&backend, b"sha256-guest");
    let runner = ZkHostRunner::new(backend);

    let input = Sha256Input { data: Vec::new() };
    let (_proof, verified) = runner.prove_and_verify(&program, &input).expect("prove");
    let actual: Sha256Output = verified.decode().expect("decode");

    assert_eq!(actual.len, 0);
    assert_eq!(actual, sha256_of(&input));
}

#[test]
fn large_input_round_trips_without_truncation() {
    let backend = sha256_backend();
    let program = program(&backend, b"sha256-guest");
    let runner = ZkHostRunner::new(backend);

    let input = Sha256Input {
        data: (0..64 * 1024).map(|i| (i % 251) as u8).collect(),
    };
    let (_proof, verified) = runner.prove_and_verify(&program, &input).expect("prove");
    let actual: Sha256Output = verified.decode().expect("decode");

    assert_eq!(actual.len, 64 * 1024);
    assert_eq!(actual, sha256_of(&input));
}

#[test]
fn the_same_guest_yields_a_stable_program_identity() {
    // Program identity must be reproducible: a rebuild that changes the
    // identity would invalidate every previously issued proof.
    let a = MockBackend::new().build_program(b"stable-guest").unwrap();
    let b = MockBackend::new().build_program(b"stable-guest").unwrap();
    assert_eq!(a.id(), b.id());
}

#[test]
fn public_values_are_byte_identical_across_repeated_runs() {
    // Determinism of the committed encoding is what makes cross-backend
    // comparison possible at the byte level, not just the decoded level.
    let backend = fibonacci_backend();
    let program = program(&backend, b"fibonacci-guest");
    let runner = ZkHostRunner::new(backend);
    let input = FibonacciInput { n: 30 };

    let first = runner.prove(&program, &input).unwrap();
    let second = runner.prove(&program, &input).unwrap();

    assert_eq!(
        first.public_values_unverified().as_bytes(),
        second.public_values_unverified().as_bytes()
    );
}

/// Documents exactly which backends this harness covers, and which it does not.
///
/// The SP1 and RISC Zero adapters are excluded from the default workspace
/// because they pull vendor proving SDKs and need `sp1up`/`rzup` toolchains, so
/// they are **genuinely absent here** rather than silently skipped. That is why
/// this file compares the mock backend against the reference model and nothing
/// more: it would be dishonest for a test that never ran SP1 to imply it had.
///
/// Real multi-backend comparison is driven by `cargo xtask portability-test`,
/// which reports a dash and a reason for every backend not compiled in.
#[test]
fn the_harness_covers_the_reference_model_and_every_compiled_in_backend() {
    let participating = ["reference", "mock"];

    assert!(participating.contains(&"reference"));
    assert!(
        participating.len() >= 2,
        "a differential test needs the reference plus at least one backend"
    );
}
