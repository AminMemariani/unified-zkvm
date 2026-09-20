//! The portable proof envelope.
//!
//! # What is and is not portable
//!
//! [`ZkProof`] makes proofs portable **at the API layer**: one type to store,
//! pass around, serialize and inspect regardless of backend. It does **not**
//! make them portable at the cryptographic layer. The bytes inside
//! [`ZkProof::proof_bytes`] are a backend-native artifact; an SP1 proof will
//! never verify under a RISC Zero verifier, and this module never pretends
//! otherwise — [`ZkProof::verify_binding`] rejects a cross-backend attempt
//! before any verifier is invoked.
//!
//! # Verification before trust
//!
//! The only way to obtain a [`VerifiedPublicValues`] is
//! [`ZkProof::into_verified`], which an adapter calls after its verifier has
//! accepted the proof. Application code that wants trustworthy output is
//! therefore pushed, by the type system, through verification first.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backend::BackendId;
use crate::error::ZkVmError;
use crate::program::{ProgramArtifact, ProgramId};
use crate::public_values::PublicValues;

/// Maximum accepted proof payload size, in bytes (512 MiB).
///
/// Uncompressed STARK proofs for large programs reach hundreds of megabytes,
/// so the ceiling is generous; its purpose is to bound allocation when parsing
/// an untrusted container, not to be a tight fit.
pub const MAX_PROOF_BYTES: usize = 512 * 1024 * 1024;

/// The category of proof an artifact contains.
///
/// These names describe *verification and size characteristics*, which is what
/// a consumer actually needs to choose between them. The mapping to each
/// vendor's terminology is documented in `docs/backend-compatibility.md` — this
/// enum deliberately does not adopt one vendor's vocabulary for all backends.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProofKind {
    /// The backend's default proof. Largest, cheapest to produce.
    ///
    /// SP1 calls this `Core`; RISC Zero calls it `Composite`.
    Native,
    /// A recursively compressed proof of constant size.
    ///
    /// SP1 `Compressed`; RISC Zero `Succinct`.
    Compressed,
    /// A SNARK-wrapped proof suitable for on-chain verification.
    ///
    /// SP1 `Groth16`/`Plonk`; RISC Zero `Groth16`.
    Onchain,
    /// A proof attesting to the validity of several other proofs.
    ///
    /// Genuine recursive aggregation only — never a concatenation. See
    /// `docs/aggregation.md`.
    Aggregated,
    /// **Not a proof.** Produced only by the development mock backend.
    ///
    /// # Security
    ///
    /// Carries no cryptographic guarantee. Real verifiers reject it.
    Mock,
    /// A backend-specific kind with no portable equivalent.
    BackendSpecific(String),
}

impl fmt::Display for ProofKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => f.write_str("native"),
            Self::Compressed => f.write_str("compressed"),
            Self::Onchain => f.write_str("onchain"),
            Self::Aggregated => f.write_str("aggregated"),
            Self::Mock => f.write_str("mock"),
            Self::BackendSpecific(s) => write!(f, "backend-specific({s})"),
        }
    }
}

/// What to do when the requested [`ProofKind`] is unavailable.
///
/// The default is [`Self::Deny`] because a silent downgrade changes proof size,
/// verification cost and on-chain compatibility — all things a caller chose
/// deliberately when they asked for a specific kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackPolicy {
    /// Fail with [`ZkVmError::UnsupportedProofKind`]. The default.
    #[default]
    Deny,
    /// Fall back to the backend's [`ProofKind::Native`] proof.
    ///
    /// Opt in only when the caller genuinely does not care about proof size or
    /// on-chain verifiability.
    AllowNative,
}

/// Options controlling proof generation.
///
/// Built with a small builder so that adding an option later is not a breaking
/// change for callers.
///
/// ```
/// use unified_zkvm_core::{ProofKind, ProvingOptions};
///
/// let opts = ProvingOptions::new(ProofKind::Compressed).with_cycle_limit(1 << 24);
///
/// assert_eq!(opts.kind, Some(ProofKind::Compressed));
/// // Downgrades are refused unless explicitly permitted.
/// assert_eq!(opts.fallback, unified_zkvm_core::FallbackPolicy::Deny);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProvingOptions {
    /// The proof kind to produce, or `None` for the backend's own default.
    ///
    /// `None` is the default and means *"whatever this backend produces most
    /// cheaply"*. That is not the same as [`ProofKind::Native`]: the mock
    /// backend's default is [`ProofKind::Mock`], and a backend added later may
    /// have a different one again. Asking for `Native` explicitly is a real
    /// request that an incompatible backend must refuse — so conflating the two
    /// would either break portable defaults or smuggle in a silent substitution.
    pub kind: Option<ProofKind>,
    /// What to do if `kind` is unsupported.
    pub fallback: FallbackPolicy,
    /// Abort if the guest exceeds this cycle count, when the backend supports it.
    pub cycle_limit: Option<u64>,
}

impl ProvingOptions {
    /// Requests a specific proof kind.
    #[must_use]
    pub fn new(kind: ProofKind) -> Self {
        Self {
            kind: Some(kind),
            ..Self::default()
        }
    }

    /// Requests whatever proof kind the backend produces by default.
    #[must_use]
    pub fn backend_default() -> Self {
        Self::default()
    }

    /// Permits a documented downgrade to [`ProofKind::Native`].
    #[must_use]
    pub fn with_fallback(mut self, policy: FallbackPolicy) -> Self {
        self.fallback = policy;
        self
    }

    /// Sets a guest cycle limit, where the backend honours one.
    #[must_use]
    pub fn with_cycle_limit(mut self, limit: u64) -> Self {
        self.cycle_limit = Some(limit);
        self
    }

    /// Resolves the effective proof kind for a backend, or fails.
    ///
    /// Adapters call this instead of hand-rolling the policy, which keeps
    /// "never downgrade silently" true across every backend by construction.
    ///
    /// `supported` must be ordered with the backend's preferred default first;
    /// that first entry is what an unset [`Self::kind`] resolves to.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedProofKind`] when the requested kind is
    /// unsupported and [`FallbackPolicy::Deny`] is in force, or when `supported`
    /// is empty.
    pub fn resolve_kind(
        &self,
        backend: BackendId,
        supported: &[ProofKind],
    ) -> Result<ProofKind, ZkVmError> {
        let Some(default_kind) = supported.first() else {
            return Err(ZkVmError::UnsupportedProofKind {
                backend,
                requested: self.kind.clone().unwrap_or(ProofKind::Native),
            });
        };

        let Some(requested) = self.kind.as_ref() else {
            return Ok(default_kind.clone());
        };

        if supported.contains(requested) {
            return Ok(requested.clone());
        }

        match self.fallback {
            FallbackPolicy::AllowNative if supported.contains(&ProofKind::Native) => {
                Ok(ProofKind::Native)
            }
            _ => Err(ZkVmError::UnsupportedProofKind {
                backend,
                requested: requested.clone(),
            }),
        }
    }
}

/// Metadata describing how a proof was produced.
///
/// Optional fields are `None` when a backend does not report them; see
/// [`crate::ResourceUsage`] for the same reasoning.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProofMetadata {
    /// Guest cycles executed.
    pub cycles: Option<u64>,
    /// Time spent proving.
    pub proving_time: Option<Duration>,
    /// Pinned upstream SDK version that produced this proof.
    pub backend_version: Option<String>,
    /// Free-form backend detail, as canonical-codec bytes.
    ///
    /// Bytes rather than a JSON value so that core stays `no_std` and free of a
    /// JSON dependency. Adapters document their own schema.
    pub backend_metadata: Option<Vec<u8>>,
}

impl ProofMetadata {
    /// Creates metadata with every field unset.
    ///
    /// The type is `#[non_exhaustive]`, so adapters in other crates build it
    /// through this constructor and the `with_*` methods rather than a struct
    /// literal. That lets new metadata fields be added without breaking every
    /// adapter in the ecosystem.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the guest cycle count.
    #[must_use]
    pub fn with_cycles(mut self, cycles: u64) -> Self {
        self.cycles = Some(cycles);
        self
    }

    /// Records how long proving took.
    #[must_use]
    pub fn with_proving_time(mut self, elapsed: Duration) -> Self {
        self.proving_time = Some(elapsed);
        self
    }

    /// Records the pinned upstream SDK version.
    #[must_use]
    pub fn with_backend_version(mut self, version: impl Into<String>) -> Self {
        self.backend_version = Some(version.into());
        self
    }

    /// Attaches adapter-defined metadata bytes.
    #[must_use]
    pub fn with_backend_metadata(mut self, bytes: Vec<u8>) -> Self {
        self.backend_metadata = Some(bytes);
        self
    }
}

/// A proof, its public values, and the identity of what it proves.
///
/// # Invariant
///
/// A `ZkProof` always carries the [`ProgramId`] it was generated for. There is
/// no constructor that omits it, which is what makes
/// [`Self::verify_binding`] possible at all — the common mistake of verifying a
/// proof against an implicit or attacker-supplied program cannot be expressed.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ZkProof {
    backend: BackendId,
    program_id: ProgramId,
    kind: ProofKind,
    public_values: PublicValues,
    proof_bytes: Vec<u8>,
    metadata: ProofMetadata,
}

impl ZkProof {
    /// Assembles a proof envelope around a backend-native artifact.
    ///
    /// Called by adapters; application code obtains proofs from a prover.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::SizeLimitExceeded`] if the payload exceeds
    /// [`MAX_PROOF_BYTES`], or [`ZkVmError::InvalidProof`] if `program_id`
    /// belongs to a different backend than `backend` — a mismatch that would
    /// otherwise produce an envelope that can never verify.
    pub fn new(
        backend: BackendId,
        program_id: ProgramId,
        kind: ProofKind,
        public_values: PublicValues,
        proof_bytes: Vec<u8>,
        metadata: ProofMetadata,
    ) -> Result<Self, ZkVmError> {
        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(ZkVmError::SizeLimitExceeded {
                context: "proof payload",
                claimed: proof_bytes.len(),
                limit: MAX_PROOF_BYTES,
            });
        }
        if program_id.backend() != backend {
            return Err(ZkVmError::InvalidProof {
                reason: alloc::format!(
                    "proof claims backend `{backend}` but its program identity belongs to `{}`",
                    program_id.backend()
                ),
            });
        }
        Ok(Self {
            backend,
            program_id,
            kind,
            public_values,
            proof_bytes,
            metadata,
        })
    }

    /// The backend that produced this proof.
    ///
    /// Part of the proof's domain: it selects which verifier is even applicable
    /// and must not be rewritten during serialization.
    #[must_use]
    pub const fn backend(&self) -> BackendId {
        self.backend
    }

    /// The identity of the program this proof attests to.
    #[must_use]
    pub const fn program_id(&self) -> &ProgramId {
        &self.program_id
    }

    /// The category of proof contained here.
    #[must_use]
    pub const fn kind(&self) -> &ProofKind {
        &self.kind
    }

    /// The public values, **unverified**.
    ///
    /// # Security
    ///
    /// Prefer [`Self::into_verified`]. This accessor exists for tooling that
    /// inspects proofs it has not checked.
    #[must_use]
    pub const fn public_values_unverified(&self) -> &PublicValues {
        &self.public_values
    }

    /// The backend-native proof bytes.
    ///
    /// Opaque at this layer. Only the originating backend's verifier can
    /// interpret them.
    #[must_use]
    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }

    /// Metadata reported by the backend.
    #[must_use]
    pub const fn metadata(&self) -> &ProofMetadata {
        &self.metadata
    }

    /// Size of the proof payload in bytes.
    ///
    /// Note this is the size of the native artifact, not of the serialized
    /// container, which adds a header and the public values.
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        self.proof_bytes.len()
    }

    /// Checks that this proof can even be verified against `program`.
    ///
    /// Performs the two cheap, non-cryptographic checks that must precede the
    /// expensive one:
    ///
    /// 1. the proof and the program belong to the same backend;
    /// 2. the proof's program identity equals the program's.
    ///
    /// # Security
    ///
    /// This is a **precondition**, not verification. A passing result means the
    /// proof is about the right program *if* its cryptography holds; the
    /// backend verifier still has to be run. Adapters call this at the top of
    /// [`crate::BackendAdapter::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::BackendMismatch`] or
    /// [`ZkVmError::ProgramIdMismatch`].
    pub fn verify_binding(&self, program: &ProgramArtifact) -> Result<(), ZkVmError> {
        if self.backend != program.id().backend() {
            return Err(ZkVmError::BackendMismatch {
                proof_backend: self.backend,
                verifier_backend: program.id().backend(),
            });
        }
        if &self.program_id != program.id() {
            return Err(ZkVmError::ProgramIdMismatch {
                expected: Box::new(self.program_id.clone()),
                actual: Box::new(program.id().clone()),
            });
        }
        Ok(())
    }

    /// Converts a verified proof into trustworthy public values.
    ///
    /// # Contract
    ///
    /// Call **only** after the backend verifier has accepted this proof. The
    /// type is the marker that verification happened; constructing one without
    /// verifying defeats the safeguard for every downstream consumer.
    #[must_use]
    pub fn into_verified(self) -> VerifiedPublicValues {
        VerifiedPublicValues {
            backend: self.backend,
            program_id: self.program_id,
            values: self.public_values,
        }
    }

    /// A domain-separated digest binding backend, program, kind and values.
    ///
    /// # Construction
    ///
    /// ```text
    /// SHA-256( "unified-zkvm:proof:v1"
    ///        || backend_u16_le
    ///        || len(program_id) || program_id
    ///        || len(kind_str)   || kind_str
    ///        || public_values_digest
    ///        || len(proof_bytes) || proof_bytes )
    /// ```
    ///
    /// Every variable-length field is length-prefixed so that no two distinct
    /// proofs can produce the same preimage by shifting a boundary.
    ///
    /// # Security
    ///
    /// An identifier for deduplication and logging — **not** a substitute for
    /// verification. Equal digests mean equal bytes, nothing more.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"unified-zkvm:proof:v1");
        h.update((self.backend as u16).to_le_bytes());

        let pid = self.program_id.as_bytes();
        h.update((pid.len() as u64).to_le_bytes());
        h.update(pid);

        let kind = self.kind.to_string();
        h.update((kind.len() as u64).to_le_bytes());
        h.update(kind.as_bytes());

        h.update(self.public_values.digest());

        h.update((self.proof_bytes.len() as u64).to_le_bytes());
        h.update(&self.proof_bytes);

        h.finalize().into()
    }
}

impl fmt::Debug for ZkProof {
    /// Summarises the proof without dumping its payload into logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZkProof")
            .field("backend", &self.backend)
            .field("program_id", &self.program_id)
            .field("kind", &self.kind)
            .field("public_values", &self.public_values)
            .field("proof_len", &self.proof_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Public values from a proof that has been cryptographically verified.
///
/// Obtainable only via [`ZkProof::into_verified`]. Holding one is evidence that
/// a backend verifier accepted the proof and that its program identity was
/// checked, so decoding from here is safe to act on.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedPublicValues {
    backend: BackendId,
    program_id: ProgramId,
    values: PublicValues,
}

impl VerifiedPublicValues {
    /// Decodes the verified output into an application type.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Serialization`] if the guest's committed bytes do
    /// not match `T` — typically a host/guest type mismatch, not an attack,
    /// since the bytes are already proven.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, ZkVmError> {
        self.values.decode_unverified()
    }

    /// The verified bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.values.as_bytes()
    }

    /// The program these values are proven to have come from.
    #[must_use]
    pub const fn program_id(&self) -> &ProgramId {
        &self.program_id
    }

    /// The backend whose verifier accepted the proof.
    #[must_use]
    pub const fn backend(&self) -> BackendId {
        self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn artifact(backend: BackendId, digest: [u8; 32]) -> ProgramArtifact {
        ProgramArtifact::new(ProgramId::from_digest(backend, digest), vec![1, 2, 3]).unwrap()
    }

    fn proof(backend: BackendId, digest: [u8; 32]) -> ZkProof {
        ZkProof::new(
            backend,
            ProgramId::from_digest(backend, digest),
            ProofKind::Native,
            PublicValues::new(vec![7]).unwrap(),
            vec![0xAB; 16],
            ProofMetadata::default(),
        )
        .unwrap()
    }

    #[test]
    fn envelope_rejects_a_program_id_from_another_backend() {
        let err = ZkProof::new(
            BackendId::Sp1,
            ProgramId::from_digest(BackendId::Risc0, [0u8; 32]),
            ProofKind::Native,
            PublicValues::empty(),
            vec![1],
            ProofMetadata::default(),
        );
        assert!(matches!(err, Err(ZkVmError::InvalidProof { .. })));
    }

    #[test]
    fn binding_rejects_a_proof_of_a_different_program() {
        let p = proof(BackendId::Mock, [1u8; 32]);
        let other = artifact(BackendId::Mock, [2u8; 32]);
        assert!(matches!(
            p.verify_binding(&other),
            Err(ZkVmError::ProgramIdMismatch { .. })
        ));
    }

    #[test]
    fn binding_rejects_a_cross_backend_verification_attempt() {
        let p = proof(BackendId::Sp1, [1u8; 32]);
        let other = artifact(BackendId::Risc0, [1u8; 32]);
        assert!(matches!(
            p.verify_binding(&other),
            Err(ZkVmError::BackendMismatch { .. })
        ));
    }

    #[test]
    fn binding_accepts_the_matching_program() {
        let p = proof(BackendId::Mock, [3u8; 32]);
        assert!(p
            .verify_binding(&artifact(BackendId::Mock, [3u8; 32]))
            .is_ok());
    }

    #[test]
    fn an_unset_kind_resolves_to_the_backends_own_default() {
        // Crucially NOT hardcoded to Native: the mock backend's default is
        // `Mock`, and a portable default must follow the backend.
        let opts = ProvingOptions::backend_default();
        assert_eq!(
            opts.resolve_kind(BackendId::Mock, &[ProofKind::Mock])
                .unwrap(),
            ProofKind::Mock
        );
    }

    #[test]
    fn an_empty_supported_list_fails_rather_than_panicking() {
        let opts = ProvingOptions::backend_default();
        assert!(opts.resolve_kind(BackendId::Mock, &[]).is_err());
    }

    #[test]
    fn unsupported_proof_kinds_are_not_silently_downgraded() {
        let opts = ProvingOptions::new(ProofKind::Onchain);
        let err = opts.resolve_kind(BackendId::Sp1, &[ProofKind::Native]);
        assert!(matches!(err, Err(ZkVmError::UnsupportedProofKind { .. })));
    }

    #[test]
    fn downgrade_happens_only_when_explicitly_permitted() {
        let opts =
            ProvingOptions::new(ProofKind::Onchain).with_fallback(FallbackPolicy::AllowNative);
        assert_eq!(
            opts.resolve_kind(BackendId::Sp1, &[ProofKind::Native])
                .unwrap(),
            ProofKind::Native
        );
    }

    #[test]
    fn digest_changes_when_any_bound_field_changes() {
        let base = proof(BackendId::Mock, [1u8; 32]);
        let other_program = proof(BackendId::Mock, [2u8; 32]);
        assert_ne!(base.digest(), other_program.digest());

        let mut tampered = base.clone();
        tampered.proof_bytes[0] ^= 0xFF;
        assert_ne!(base.digest(), tampered.digest());
    }

    #[test]
    fn verified_values_retain_their_program_binding() {
        let p = proof(BackendId::Mock, [5u8; 32]);
        let expected = p.program_id().clone();
        let verified = p.into_verified();
        assert_eq!(verified.program_id(), &expected);
    }

    #[test]
    fn debug_output_omits_the_proof_payload() {
        let p = proof(BackendId::Mock, [1u8; 32]);
        let s = alloc::format!("{p:?}");
        assert!(s.contains("proof_len: 16"));
        assert!(!s.contains("171"), "raw payload bytes leaked: {s}");
    }
}
