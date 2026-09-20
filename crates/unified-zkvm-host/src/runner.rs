//! [`ZkHostRunner`] — the primary host API.

use serde::Serialize;
use tracing::{debug, instrument};
use unified_zkvm_core::{
    BackendAdapter, BackendId, Capability, CapabilitySet, ExecutionResult, ProgramArtifact,
    ProvingOptions, VerifiedPublicValues, ZkMessage, ZkProof, ZkVmError,
};

use crate::config::RunnerConfig;

/// Orchestrates execution, proving and verification against one backend.
///
/// # Static dispatch
///
/// `B` is a concrete adapter by default, so `runner.prove(..)` is a direct
/// call. For runtime backend selection use `ZkHostRunner<Box<dyn
/// BackendAdapter>>`; the trait is object safe precisely so benchmark and CLI
/// tools can do that without the library forcing dynamic dispatch on everyone.
///
/// ```
/// # use unified_zkvm_host::ZkHostRunner;
/// # use unified_zkvm_mock::MockBackend;
/// # use unified_zkvm_core::{BackendAdapter, ProgramArtifact};
/// # fn demo(program: ProgramArtifact) -> Result<(), unified_zkvm_core::ZkVmError> {
/// // Static: zero-cost, compiler sees the concrete type.
/// let runner = ZkHostRunner::new(MockBackend::new());
///
/// // Dynamic: chosen at runtime, e.g. from a CLI flag.
/// let boxed: Box<dyn BackendAdapter> = Box::new(MockBackend::new());
/// let dynamic = ZkHostRunner::new(boxed);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ZkHostRunner<B> {
    backend: B,
    config: RunnerConfig,
    /// Cached so that tracing spans and capability checks do not call through
    /// the (possibly dynamically dispatched) adapter on every operation.
    /// The trait contract requires this value to be stable per instance.
    cached_backend_id: BackendId,
}

impl<B: BackendAdapter> ZkHostRunner<B> {
    /// Creates a runner with default, safe configuration.
    #[must_use]
    pub fn new(backend: B) -> Self {
        let cached_backend_id = backend.backend_id();
        Self {
            backend,
            config: RunnerConfig::default(),
            cached_backend_id,
        }
    }

    /// Starts a builder for a configured runner.
    #[must_use]
    pub fn builder() -> ZkHostRunnerBuilder<B> {
        ZkHostRunnerBuilder::default()
    }

    /// The backend this runner drives.
    #[must_use]
    pub const fn backend_id(&self) -> BackendId {
        self.cached_backend_id
    }

    /// The capabilities of the underlying backend.
    #[must_use]
    pub fn capabilities(&self) -> CapabilitySet {
        self.backend.capabilities()
    }

    /// The active configuration.
    #[must_use]
    pub const fn config(&self) -> &RunnerConfig {
        &self.config
    }

    /// Direct access to the backend adapter.
    ///
    /// # Portability
    ///
    /// This is the **escape hatch**. Backend adapters expose inherent methods
    /// for functionality that has no portable equivalent — SP1's network
    /// prover, RISC Zero's assumption composition — and this is how you reach
    /// them. Code that calls through here is no longer backend-portable, which
    /// is a fine trade when you need the feature; just make it a deliberate one
    /// rather than an accident. See `docs/host-guide.md`.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Runs the guest without proving, returning its unproven output.
    ///
    /// Use for fast iteration and to measure cycle counts before paying to
    /// prove.
    ///
    /// # Security
    ///
    /// The returned [`ExecutionResult::public_values`] are **not proven**. They
    /// are the output of a local, unattested run.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedCapability`] if the backend cannot
    /// execute without proving, [`ZkVmError::Serialization`] if `input` cannot
    /// be encoded, or [`ZkVmError::Backend`] if the guest fails.
    #[instrument(level = "info", skip_all, fields(backend = %self.cached_backend_id, program = %program.id()))]
    pub fn execute<I: Serialize + ?Sized>(
        &self,
        program: &ProgramArtifact,
        input: &I,
    ) -> Result<ExecutionResult, ZkVmError> {
        self.require(Capability::Execute)?;
        let encoded = ZkMessage::encode(input)?;
        debug!(input_bytes = encoded.len(), "executing guest");
        self.backend.execute(program, &encoded)
    }

    /// Generates a proof of the guest's execution on `input`.
    ///
    /// Uses the runner's configured [`ProvingOptions`]; for per-call control
    /// use [`Self::prove_with`].
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::UnsupportedCapability`] if the backend cannot
    /// prove, [`ZkVmError::UnsupportedProofKind`] if the configured kind is
    /// unavailable and downgrades are denied, or [`ZkVmError::Backend`] if
    /// proving fails.
    pub fn prove<I: Serialize + ?Sized>(
        &self,
        program: &ProgramArtifact,
        input: &I,
    ) -> Result<ZkProof, ZkVmError> {
        self.prove_with(program, input, &self.config.proving)
    }

    /// Generates a proof with explicit proving options.
    ///
    /// # Errors
    ///
    /// As [`Self::prove`].
    #[instrument(
        level = "info",
        skip_all,
        fields(backend = %self.cached_backend_id, program = %program.id(), kind = ?options.kind)
    )]
    pub fn prove_with<I: Serialize + ?Sized>(
        &self,
        program: &ProgramArtifact,
        input: &I,
        options: &ProvingOptions,
    ) -> Result<ZkProof, ZkVmError> {
        self.require(Capability::Prove)?;
        let encoded = ZkMessage::encode(input)?;

        if self.config.telemetry.log_guest_input {
            // Opt-in only: this is the private witness.
            debug!(input_hex = %hex_preview(&encoded), "guest input");
        }

        let proof = self.backend.prove(program, &encoded, options)?;
        debug!(
            proof_bytes = proof.size_bytes(),
            kind = %proof.kind(),
            "proof generated"
        );

        if self.config.verify_after_prove {
            self.backend.verify(&proof, program)?;
            debug!("post-prove verification passed");
        }

        Ok(proof)
    }

    /// Verifies a proof and returns its now-trustworthy public values.
    ///
    /// # Security
    ///
    /// This is the function that makes public values safe to act on. It checks,
    /// in order: backend match, program-identity match, then the backend's
    /// cryptographic verifier. Only on success does it hand back a
    /// [`VerifiedPublicValues`].
    ///
    /// Note the signature **requires** the program. There is deliberately no
    /// `verify(&proof)` overload that infers identity from the proof itself —
    /// that would check a proof against whatever program the proof claims,
    /// which is no check at all.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::BackendMismatch`], [`ZkVmError::ProgramIdMismatch`]
    /// or [`ZkVmError::VerificationFailed`].
    #[instrument(level = "info", skip_all, fields(backend = %self.cached_backend_id, program = %program.id()))]
    pub fn verify(
        &self,
        proof: &ZkProof,
        program: &ProgramArtifact,
    ) -> Result<VerifiedPublicValues, ZkVmError> {
        self.require(Capability::Verify)?;
        let witness = self.backend.verify(proof, program)?;
        debug!("verification passed");
        Ok(proof.clone().into_verified(witness))
    }

    /// Proves and then verifies in one call.
    ///
    /// The convenient path for tests and for applications that consume a proof
    /// locally.
    ///
    /// # Errors
    ///
    /// As [`Self::prove`] and [`Self::verify`].
    pub fn prove_and_verify<I: Serialize + ?Sized>(
        &self,
        program: &ProgramArtifact,
        input: &I,
    ) -> Result<(ZkProof, VerifiedPublicValues), ZkVmError> {
        let proof = self.prove(program, input)?;
        let verified = self.verify(&proof, program)?;
        Ok((proof, verified))
    }

    fn require(&self, capability: Capability) -> Result<(), ZkVmError> {
        unified_zkvm_core::backend::require_capability(
            self.cached_backend_id,
            self.backend.capabilities(),
            capability,
        )
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let take = bytes.len().min(32);
    let mut s = String::with_capacity(take * 2 + 3);
    for b in &bytes[..take] {
        let _ = write!(s, "{b:02x}");
    }
    if bytes.len() > take {
        s.push_str("..");
    }
    s
}

/// Builder for a configured [`ZkHostRunner`].
///
/// ```
/// # use unified_zkvm_host::{ZkHostRunner, RunnerConfig};
/// # use unified_zkvm_mock::MockBackend;
/// # fn demo() -> Result<(), unified_zkvm_core::ZkVmError> {
/// let runner = ZkHostRunner::builder()
///     .backend(MockBackend::new())
///     .verify_after_prove(true)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ZkHostRunnerBuilder<B> {
    backend: Option<B>,
    config: RunnerConfig,
}

impl<B> Default for ZkHostRunnerBuilder<B> {
    fn default() -> Self {
        Self {
            backend: None,
            config: RunnerConfig::default(),
        }
    }
}

impl<B: BackendAdapter> ZkHostRunnerBuilder<B> {
    /// Sets the backend adapter. Required.
    #[must_use]
    pub fn backend(mut self, backend: B) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Replaces the whole configuration.
    #[must_use]
    pub fn config(mut self, config: RunnerConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the proving options.
    #[must_use]
    pub fn proving_options(mut self, options: ProvingOptions) -> Self {
        self.config.proving = options;
        self
    }

    /// Verifies each proof immediately after generating it.
    #[must_use]
    pub fn verify_after_prove(mut self, enabled: bool) -> Self {
        self.config.verify_after_prove = enabled;
        self
    }

    /// Builds the runner.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Configuration`] if no backend was set, or if the
    /// backend cannot satisfy [`CapabilitySet::MINIMUM_VIABLE`] — catching a
    /// broken adapter at construction rather than at the first prove call.
    pub fn build(self) -> Result<ZkHostRunner<B>, ZkVmError> {
        let backend = self.backend.ok_or_else(|| ZkVmError::Configuration {
            reason: "no backend was set; call `.backend(..)` before `.build()`".to_string(),
        })?;

        let caps = backend.capabilities();
        let missing = caps.missing_from(CapabilitySet::MINIMUM_VIABLE);
        if !missing.is_empty() {
            return Err(ZkVmError::Configuration {
                reason: format!(
                    "backend `{}` is missing required capabilities: {missing:?}",
                    backend.backend_id()
                ),
            });
        }

        let cached_backend_id = backend.backend_id();
        Ok(ZkHostRunner {
            backend,
            config: self.config,
            cached_backend_id,
        })
    }
}
