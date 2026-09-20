//! Proof-container benchmarks.
//!
//! # What these numbers mean - and what they do not
//!
//! These benchmarks measure **the abstraction layer's overhead only**: writing
//! and parsing the `.uzkvm` container around an already-generated proof. They
//! do **not** measure zkVM proving time, which is orders of magnitude larger
//! and entirely backend-specific. Container work is pure byte shuffling; it
//! should stay negligible relative to proving, and this bench exists to notice
//! if it ever stops being negligible.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use unified_zkvm_core::{
    container, BackendId, ProgramId, ProofKind, ProofMetadata, PublicValues, ZkProof,
};

/// Proof body sizes spanning a plausible range, from a compressed proof to a
/// large native one.
const PROOF_SIZES: &[usize] = &[1024, 64 * 1024, 1024 * 1024];

fn proof(size: usize) -> ZkProof {
    let program_id = ProgramId::from_digest(BackendId::Mock, [0x11; 32]);
    let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let public_values = PublicValues::new(vec![0xAB; 64]).expect("public values");
    ZkProof::new(
        BackendId::Mock,
        program_id,
        ProofKind::Mock,
        public_values,
        bytes,
        ProofMetadata::new(),
    )
    .expect("proof")
}

fn bench_container(c: &mut Criterion) {
    let mut group = c.benchmark_group("container");
    for &size in PROOF_SIZES {
        let proof = proof(size);
        let encoded = container::to_bytes(&proof).expect("to_bytes");

        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(BenchmarkId::new("to_bytes", size), &proof, |b, proof| {
            b.iter(|| container::to_bytes(black_box(proof)).expect("to_bytes"));
        });
        group.bench_with_input(
            BenchmarkId::new("from_bytes", size),
            &encoded,
            |b, bytes| {
                b.iter(|| container::from_bytes(black_box(bytes)).expect("from_bytes"));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("read_header", size),
            &encoded,
            |b, bytes| {
                b.iter(|| container::read_header(black_box(bytes)).expect("read_header"));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_container);
criterion_main!(benches);
