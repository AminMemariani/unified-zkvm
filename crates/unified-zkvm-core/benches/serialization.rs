//! Serialization benchmarks for the canonical codec.
//!
//! # What these numbers mean - and what they do not
//!
//! These benchmarks measure **the abstraction layer's overhead only**: framing,
//! encoding, decoding and digesting. They do **not** measure zkVM proving time,
//! which is orders of magnitude larger and entirely backend-specific. A
//! microsecond saved here is invisible next to a proof that takes seconds to
//! minutes. The reason to track them at all is to catch a regression that would
//! make the abstraction itself a bottleneck - not to compare backends.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde::{Deserialize, Serialize};
use std::hint::black_box;
use unified_zkvm_core::{crypto::sha256, ZkMessage};

/// A nested payload with the shapes that stress a codec: fixed array, variable
/// collection, `Option`, and nesting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Order {
    id: u64,
    amount: u64,
    owner: [u8; 32],
    items: Vec<LineItem>,
    memo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LineItem {
    sku: u32,
    quantity: u32,
    unit_price: u64,
}

const SIZES: &[usize] = &[64, 1024, 16 * 1024, 64 * 1024];

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn order(items: usize) -> Order {
    Order {
        id: u64::MAX,
        amount: 350,
        owner: [0xAB; 32],
        items: (0..items)
            .map(|i| LineItem {
                sku: i as u32,
                quantity: 3,
                unit_price: 100,
            })
            .collect(),
        memo: Some("benchmark".to_string()),
    }
}

fn bench_bytes_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec/bytes");
    for &size in SIZES {
        let data = payload(size);
        let encoded = ZkMessage::encode(&data).expect("encode");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encode", size), &data, |b, data| {
            b.iter(|| ZkMessage::encode(black_box(data)).expect("encode"));
        });
        group.bench_with_input(BenchmarkId::new("decode", size), &encoded, |b, bytes| {
            b.iter(|| ZkMessage::decode::<Vec<u8>>(black_box(bytes)).expect("decode"));
        });
    }
    group.finish();
}

fn bench_nested_struct(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec/nested");
    for &items in &[1usize, 16, 256] {
        let value = order(items);
        let encoded = ZkMessage::encode(&value).expect("encode");

        group.bench_with_input(BenchmarkId::new("encode", items), &value, |b, value| {
            b.iter(|| ZkMessage::encode(black_box(value)).expect("encode"));
        });
        group.bench_with_input(BenchmarkId::new("decode", items), &encoded, |b, bytes| {
            b.iter(|| ZkMessage::decode::<Order>(black_box(bytes)).expect("decode"));
        });
    }
    group.finish();
}

fn bench_digest(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto/sha256");
    for &size in SIZES {
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sha256(black_box(data)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_bytes_roundtrip,
    bench_nested_struct,
    bench_digest
);
criterion_main!(benches);
