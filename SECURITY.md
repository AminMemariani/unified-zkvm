# Security policy

## Reporting a vulnerability

**Please report privately first. Do not open a public issue.**

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability), which creates a confidential advisory
visible only to maintainers.

Include what you have: affected crate and version, the component
(core / guest / host / mock / an adapter), a description of the issue, a
reproduction if you have one, and your assessment of the impact. A partial
report is welcome — do not wait until it is perfect.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 72 hours |
| Initial assessment | 7 days |
| Fix or mitigation plan | discussed with you, depending on severity |
| Coordinated disclosure | after a fix is available, with credit if you want it |

We will keep you informed, agree the disclosure timing with you, and credit you
unless you prefer otherwise. If we disagree about severity we will say so
plainly rather than quietly downgrading your report.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| < 0.1 | no |

Pre-1.0, security fixes land on the latest minor release. There is no long-term
support branch yet.

## What is in scope

Issues in **this project's code**:

- Verification that accepts what it should reject — a proof for a different
  program, from a different backend, or with altered public values.
- Any path that yields `VerifiedPublicValues` without the backend's
  cryptographic verifier having succeeded.
- Parsing flaws in the message frame or proof container: memory exhaustion via a
  length prefix, out-of-bounds reads, panics on hostile input.
- A capability bit claimed without an implementation, where that claim leads a
  caller into an unsafe assumption.
- A mock artifact reaching a real verifier, or any weakening of the three guards
  that isolate the mock backend.
- Silent proof-kind downgrades, or a configuration that weakens verification.
- Unintended disclosure of the private witness — for example telemetry logging
  guest input without being asked to.
- Supply-chain issues in this repository's own dependency declarations.

## Backend dependency vulnerabilities

If the issue is in `sp1-sdk`, `risc0-zkvm` or another upstream SDK, **report it
to that project first** — they own the fix and the disclosure timeline. Then let
us know privately so we can plan a version bump and, if needed, publish an
advisory pointing at theirs.

If the issue is in how *our adapter uses* an SDK — a missing verification step,
a misused API, a dangerous default feature — that is ours and is in scope.

## Proof soundness concerns

If you believe a backend's proof system is unsound, that is a finding about the
backend, and it belongs with the backend's maintainers first. We will act on it
here by adjusting or withdrawing our adapter, and we will document it — but
**unified-zkvm is an abstraction layer and does not independently make an
underlying zkVM cryptographically secure.** See
[docs/security-model.md](docs/security-model.md).

## Out of scope

- Correctness bugs in *your* guest program. A proof of a buggy program is a
  valid proof of a bug.
- The mock backend producing forgeable artifacts. That is its documented
  behaviour; it performs no cryptography and is development-only.
- Performance and resource use of proving.
- Side channels and timing analysis. Not currently analysed, and not claimed.
- Anything requiring an attacker to already control your build, your machine, or
  the `ProgramArtifact` you verify against.

For the full list of non-guarantees, see
[docs/security-model.md](docs/security-model.md#what-we-do-not-guarantee).

## Responsible disclosure

We ask that you give us a reasonable window to ship a fix before publishing, do
not access or modify data that is not yours while investigating, and avoid
testing against systems you do not own. In return we commit to responding
promptly, fixing real issues, crediting you, and never using legal threats
against good-faith research.

## Hardening checklist for users

- Pin your `ProgramArtifact` identity out of band. If an attacker chooses the
  program you verify against, they choose what "valid" means.
- Reject proofs where `BackendId::is_cryptographic()` is `false`.
- Keep `FallbackPolicy::Deny` unless you have a specific reason not to.
- Leave `telemetry.log_guest_input` off outside local debugging.
- Keep `risc0-zkvm`'s `default-features = false` so `bonsai` cannot route
  proving to a remote service from environment variables.
- Share the exact input/output types between host and guest — postcard is not
  self-describing, and the wrong type can decode successfully to a wrong value.
