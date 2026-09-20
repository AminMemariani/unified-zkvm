//! Host runner configuration.
//!
//! Every default here is the safe choice. In particular the runner never
//! enables a development mode, never downgrades a proof kind, and never logs
//! witness data unless explicitly told to.

use unified_zkvm_core::{FallbackPolicy, ProofKind, ProvingOptions};

/// What the runner does with proof artifacts it produces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ArtifactPolicy {
    /// Keep proofs in memory only. The default.
    #[default]
    InMemory,
    /// Also persist each proof to disk via the caller's own `save` call.
    ///
    /// The runner does not choose paths or write files on your behalf; this
    /// flag exists so tooling can record intent without the library guessing
    /// where your artifacts belong.
    PersistOnRequest,
}

/// Controls how much the runner reports through `tracing`.
///
/// # Security
///
/// The defaults never emit guest inputs, witness data, or proof bytes. Those
/// are either secret or large, and a library that logs them by default turns
/// every debug session into an accidental disclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelemetryConfig {
    /// Emit spans around execute, prove and verify. On by default; spans carry
    /// backend and program identity only.
    pub spans_enabled: bool,
    /// Include public values in span fields.
    ///
    /// Off by default. Public values are not secret, but they can be large and
    /// they bloat log volume.
    pub log_public_values: bool,
    /// Include guest **input** in span fields.
    ///
    /// # Security
    ///
    /// Off by default and should stay off. Guest input is the private witness:
    /// the data the proof exists to keep confidential. Enable only when
    /// debugging locally with non-sensitive input.
    pub log_guest_input: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            spans_enabled: true,
            log_public_values: false,
            log_guest_input: false,
        }
    }
}

/// Configuration for a [`crate::ZkHostRunner`].
///
/// ```
/// use unified_zkvm_host::RunnerConfig;
///
/// let cfg = RunnerConfig::default();
///
/// // Safe defaults: no silent downgrades, no witness logging.
/// assert!(!cfg.verify_after_prove);
/// assert!(!cfg.telemetry.log_guest_input);
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct RunnerConfig {
    /// Proving options applied when the caller does not supply their own.
    pub proving: ProvingOptions,
    /// Verify every proof immediately after generating it.
    ///
    /// Off by default: verification is not free, and a caller who proves in
    /// bulk and verifies elsewhere should not pay for it twice. Turn it on to
    /// catch adapter bugs early in development.
    pub verify_after_prove: bool,
    /// Artifact handling policy.
    pub artifacts: ArtifactPolicy,
    /// Telemetry policy.
    pub telemetry: TelemetryConfig,
}

impl RunnerConfig {
    /// Configuration tuned for development: verify after proving.
    ///
    /// # Security
    ///
    /// Despite the name this enables **no insecure mode**. It only turns on an
    /// extra check. There is no configuration in this library that weakens
    /// verification.
    #[must_use]
    pub fn development() -> Self {
        Self {
            verify_after_prove: true,
            ..Self::default()
        }
    }

    /// Requests a specific proof kind for proofs produced by this runner.
    #[must_use]
    pub fn with_proof_kind(mut self, kind: ProofKind) -> Self {
        self.proving.kind = Some(kind);
        self
    }

    /// Sets the downgrade policy when a proof kind is unsupported.
    #[must_use]
    pub fn with_fallback(mut self, policy: FallbackPolicy) -> Self {
        self.proving.fallback = policy;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_never_enable_a_downgrade_or_a_dev_mode() {
        let cfg = RunnerConfig::default();
        assert_eq!(cfg.proving.fallback, FallbackPolicy::Deny);
        assert_eq!(
            cfg.proving.kind, None,
            "the default must follow the backend, not impose a kind"
        );
        assert!(!cfg.verify_after_prove);
    }

    #[test]
    fn telemetry_defaults_do_not_leak_the_private_witness() {
        let t = TelemetryConfig::default();
        assert!(!t.log_guest_input, "guest input is the private witness");
        assert!(!t.log_public_values);
        assert!(t.spans_enabled, "observability should still be useful");
    }

    #[test]
    fn development_config_only_adds_checks() {
        let cfg = RunnerConfig::development();
        assert!(cfg.verify_after_prove);
        // Crucially, it does NOT relax the fallback policy.
        assert_eq!(cfg.proving.fallback, FallbackPolicy::Deny);
    }
}
