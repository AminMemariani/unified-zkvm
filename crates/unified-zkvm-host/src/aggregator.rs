//! Capability-gated proof aggregation.
//!
//! # What aggregation is, and what it is not
//!
//! These four words get used interchangeably and mean very different things:
//!
//! | Term | Meaning | Result |
//! |---|---|---|
//! | **Batching** | Proving several computations in one guest run | One proof, one program |
//! | **Compression** | Recursively shrinking one proof | One proof, constant size |
//! | **Recursion** | Verifying a proof inside a guest | Building block |
//! | **Aggregation** | One proof attesting to *N independent* proofs | One proof, N programs |
//!
//! Only the last is [`ProofAggregator`]. Putting several proofs in a `Vec` is
//! batching at best and is **not** implemented here under an aggregation name -
//! doing so would let a caller believe they had constant-size verification when
//! they had linear-size verification.
//!
//! # Why no backend implements this today
//!
//! Research against the pinned SDKs found that neither SP1 6.8.0 nor RISC Zero
//! 3.0.6 exposes a host-level `aggregate(&[proof]) -> proof`. Both provide the
//! *ingredients* - SP1's in-guest `verify_sp1_proof` plus
//! `SP1Stdin::write_proof`, RISC Zero's `add_assumption` plus `env::verify` -
//! but assembling them requires **a dedicated aggregation guest program
//! compiled for the specific set of proofs being folded**. That program is
//! application-specific, so a generic adapter cannot supply it.
//!
//! The honest result: [`CapabilitySet::AGGREGATION`] is unset on every shipped
//! backend, and calling [`ProofAggregator::aggregate`] returns
//! [`ZkVmError::UnsupportedCapability`]. See `docs/aggregation.md` for how to
//! build an aggregation guest yourself using the backend escape hatch.
//!
//! [`CapabilitySet::AGGREGATION`]: unified_zkvm_core::CapabilitySet::AGGREGATION

use unified_zkvm_core::{BackendAdapter, Capability, CapabilitySet, ZkProof, ZkVmError};

/// Folds several independent proofs into a single proof.
///
/// # Contract
///
/// An implementation must produce a proof whose verification genuinely implies
/// the validity of every input proof. Concatenation, wrapping in a container,
/// or any construction whose verification cost grows with `proofs.len()` does
/// not satisfy this and must not be offered here.
pub trait ProofAggregator {
    /// Aggregates `proofs` into one.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedCapability`] when the backend does not
    /// implement aggregation, [`ZkVmError::Configuration`] if `proofs` is empty
    /// or mixes backends, or [`ZkVmError::Backend`] on failure.
    fn aggregate(&self, proofs: &[ZkProof]) -> Result<ZkProof, ZkVmError>;

    /// Whether aggregation is available.
    fn supports_aggregation(&self) -> bool;
}

impl<T: BackendAdapter> ProofAggregator for T {
    fn aggregate(&self, proofs: &[ZkProof]) -> Result<ZkProof, ZkVmError> {
        if !self.capabilities().contains(CapabilitySet::AGGREGATION) {
            return Err(ZkVmError::UnsupportedCapability {
                backend: self.backend_id(),
                capability: Capability::Aggregation,
            });
        }
        if proofs.is_empty() {
            return Err(ZkVmError::Configuration {
                reason: "cannot aggregate an empty set of proofs".to_string(),
            });
        }
        // Mixing backends is meaningless: no verifier can check both halves.
        if let Some(bad) = proofs.iter().find(|p| p.backend() != self.backend_id()) {
            return Err(ZkVmError::BackendMismatch {
                proof_backend: bad.backend(),
                verifier_backend: self.backend_id(),
            });
        }
        BackendAdapter::aggregate(self, proofs)
    }

    fn supports_aggregation(&self) -> bool {
        self.capabilities().contains(CapabilitySet::AGGREGATION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unified_zkvm_mock::MockBackend;

    #[test]
    fn aggregation_is_refused_rather_than_faked() {
        let backend = MockBackend::new();
        assert!(!backend.supports_aggregation());
        assert!(matches!(
            ProofAggregator::aggregate(&backend, &[]),
            Err(ZkVmError::UnsupportedCapability { .. })
        ));
    }
}
