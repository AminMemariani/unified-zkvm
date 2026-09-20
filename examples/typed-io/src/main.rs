//! Typed I/O through the canonical codec.
//!
//! Host and guest exchange real Rust types, not hand-packed bytes. The shapes
//! exercised here are exactly the ones where backend-native encodings most
//! often diverge:
//!
//! * a fixed-size array (`owner: [u8; 32]`),
//! * a variable-length collection (`items: Vec<LineItem>`),
//! * an `Option<String>` in both `Some` and `None` form,
//! * nesting (`LineItem` inside `Order`).
//!
//! The interesting zero-knowledge property: the verifier learns whether the
//! declared total was correct **without** learning the line items.
//!
//! Run it:
//!
//! ```text
//! cargo run -p typed-io-example
//! ```

use anyhow::{bail, Result};
use unified_zkvm_core::{ZkMessage, ZkVmError};
use unified_zkvm_host::ZkHostRunner;
use unified_zkvm_mock::MockBackend;
use uzkvm_test_support::{settle, LineItem, Order, Settlement};

fn guest(input: &[u8]) -> Result<Vec<u8>, ZkVmError> {
    let order: Order = ZkMessage::decode(input)?;
    let settlement = settle(&order);
    postcard::to_allocvec(&settlement).map_err(|e| ZkVmError::Serialization {
        context: "settlement guest output",
        detail: e.to_string(),
    })
}

fn sample_orders() -> Vec<Order> {
    vec![
        Order {
            id: 1001,
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
            memo: Some("typed round trip".to_string()),
        },
        // `memo: None` and an empty `Vec` — the edge cases that a sloppy
        // encoding silently mangles.
        Order {
            id: u64::MAX,
            amount: 0,
            owner: [0x00; 32],
            items: Vec::new(),
            memo: None,
        },
        Order {
            id: 7,
            amount: 999,
            owner: [0x11; 32],
            items: vec![LineItem {
                sku: 42,
                quantity: 2,
                unit_price: 100,
            }],
            memo: None,
        },
    ]
}

fn main() -> Result<()> {
    let backend = MockBackend::new().with_guest(guest);
    let program = backend.build_program(b"order-guest")?;
    let runner = ZkHostRunner::new(backend);

    println!("unified-zkvm typed-io example");
    println!();
    println!("  encoded input is the canonical framed message; the guest gets");
    println!("  a typed `Order` back out and commits a typed `Settlement`.");
    println!();
    println!(
        "  {:<8} {:>6} {:>10} {:>10} {:>10} {:>8}",
        "order", "items", "declared", "computed", "matches", "in-bytes"
    );

    for order in sample_orders() {
        let encoded = ZkMessage::encode(&order)?;
        let expected = settle(&order);

        let (_proof, verified) = runner.prove_and_verify(&program, &order)?;
        let actual: Settlement = verified.decode()?;

        if actual != expected {
            bail!(
                "guest settlement diverged from the host reference for order {}",
                order.id
            );
        }

        println!(
            "  {:<8} {:>6} {:>10} {:>10} {:>10} {:>8}",
            order.id.min(9_999_999),
            order.items.len(),
            order.amount,
            actual.computed_total,
            actual.matches_declared,
            encoded.len()
        );
    }

    println!();
    println!("  every decoded `Settlement` matched the host-side reference.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_codec_round_trips_the_nested_type() {
        for order in sample_orders() {
            let bytes = ZkMessage::encode(&order).unwrap();
            let back: Order = ZkMessage::decode(&bytes).unwrap();
            assert_eq!(back, order);
        }
    }
}
