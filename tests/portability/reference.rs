//! Reference implementations of the guest computations used in portability tests.
//!
//! # Why a reference model exists
//!
//! Comparing backends only against each other proves they agree, not that they
//! are **right** — five backends could be consistently wrong. Every portability
//! test therefore compares each backend against a plain Rust implementation
//! that no zkVM ever touches.
//!
//! These functions are also the guest bodies themselves. A guest program is a
//! thin wrapper: read, call one of these, commit. That is the pattern
//! `docs/guest-guide.md` recommends, and it is what makes guest logic testable
//! with an ordinary `cargo test`.

use serde::{Deserialize, Serialize};

/// Input to the Fibonacci computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FibonacciInput {
    /// Index of the Fibonacci number to compute.
    pub n: u32,
}

/// Output of the Fibonacci computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FibonacciOutput {
    /// The requested Fibonacci number.
    pub value: u64,
    /// Echo of the input index, so the commitment is self-describing.
    pub n: u32,
}

/// Computes the `n`th Fibonacci number.
///
/// Uses `wrapping_add` so that large `n` has defined behaviour rather than
/// panicking in release and aborting in debug — a guest panic is an execution
/// failure, and the overflow point should not differ between a host test build
/// and a zkVM build.
#[must_use]
pub fn fibonacci(input: FibonacciInput) -> FibonacciOutput {
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 0..input.n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    FibonacciOutput {
        value: a,
        n: input.n,
    }
}

/// Input to the SHA-256 computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha256Input {
    /// Bytes to hash.
    pub data: Vec<u8>,
}

/// Output of the SHA-256 computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha256Output {
    /// The digest.
    pub digest: [u8; 32],
    /// Length of the input, committed so the digest cannot be reinterpreted
    /// against a different-length preimage.
    pub len: u64,
}

/// Computes the SHA-256 digest of `data`.
#[must_use]
pub fn sha256_of(input: &Sha256Input) -> Sha256Output {
    Sha256Output {
        digest: unified_zkvm_core::crypto::sha256(&input.data),
        len: input.data.len() as u64,
    }
}

/// A nested structure exercising non-trivial serialization.
///
/// Deliberately mixes a fixed-size array, a variable-length collection, an
/// `Option` and a nested struct — the shapes where backend-native encodings
/// most often diverge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// Order identifier.
    pub id: u64,
    /// Amount in minor units.
    pub amount: u64,
    /// Owner's 32-byte address.
    pub owner: [u8; 32],
    /// Line items.
    pub items: Vec<LineItem>,
    /// Optional memo.
    pub memo: Option<String>,
}

/// A single line in an [`Order`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineItem {
    /// Stock-keeping unit.
    pub sku: u32,
    /// Quantity ordered.
    pub quantity: u32,
    /// Unit price in minor units.
    pub unit_price: u64,
}

/// Result of settling an [`Order`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settlement {
    /// The order that was settled.
    pub order_id: u64,
    /// Sum of line-item totals.
    pub computed_total: u64,
    /// Whether the declared amount matched the computed total.
    pub matches_declared: bool,
}

/// Settles an order by recomputing its total from the line items.
///
/// The interesting property for a zkVM: the verifier learns whether the
/// declared amount was correct without learning the line items.
#[must_use]
pub fn settle(order: &Order) -> Settlement {
    let computed_total = order.items.iter().fold(0u64, |acc, item| {
        acc.wrapping_add(u64::from(item.quantity).wrapping_mul(item.unit_price))
    });
    Settlement {
        order_id: order.id,
        computed_total,
        matches_declared: computed_total == order.amount,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fibonacci_matches_known_values() {
        assert_eq!(fibonacci(FibonacciInput { n: 0 }).value, 0);
        assert_eq!(fibonacci(FibonacciInput { n: 1 }).value, 1);
        assert_eq!(fibonacci(FibonacciInput { n: 10 }).value, 55);
        assert_eq!(fibonacci(FibonacciInput { n: 20 }).value, 6765);
        assert_eq!(
            fibonacci(FibonacciInput { n: 90 }).value,
            2_880_067_194_370_816_120
        );
    }

    #[test]
    fn fibonacci_wraps_instead_of_panicking_past_u64() {
        // Must not panic: a guest panic is an execution failure, and the host
        // test build must agree with the zkVM build about where that happens.
        let _ = fibonacci(FibonacciInput { n: 1000 });
    }

    #[test]
    fn sha256_commits_the_length_alongside_the_digest() {
        let out = sha256_of(&Sha256Input {
            data: b"abc".to_vec(),
        });
        assert_eq!(out.len, 3);
        assert_eq!(out.digest[0], 0xba);
    }

    #[test]
    fn settlement_detects_a_mismatched_declared_total() {
        let order = Order {
            id: 1,
            amount: 999,
            owner: [0u8; 32],
            items: vec![LineItem {
                sku: 1,
                quantity: 2,
                unit_price: 100,
            }],
            memo: None,
        };
        let s = settle(&order);
        assert_eq!(s.computed_total, 200);
        assert!(!s.matches_declared);
    }

    #[test]
    fn settlement_accepts_a_correct_declared_total() {
        let order = Order {
            id: 2,
            amount: 350,
            owner: [7u8; 32],
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
            memo: Some("thanks".to_string()),
        };
        assert!(settle(&order).matches_declared);
    }
}
