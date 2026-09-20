# ADR-005: Capability system

## Status

Accepted.

## Context

Backends differ in what they can do, and the differences are not cosmetic: one
can produce an on-chain proof, another cannot; one has a Keccak precompile,
another does not. Application code needs to ask "can this backend do X?" before
committing to a design, and the abstraction needs to refuse unsupported
operations with a clear error rather than a confusing failure deep inside an
SDK.

The naive designs both fail:

- **A trait method per feature** (`fn supports_aggregation(&self) -> bool`)
  grows without bound, cannot be composed, and every new feature breaks every
  adapter.
- **A struct of bools** cannot express "the set of things I need", cannot
  compute what is missing, and serializes verbosely.

There is also a cultural problem to design against: it is tempting to advertise
a capability because the underlying SDK has it. That turns the capability system
into marketing and makes it worthless.

## Decision

A `bitflags` set:

```rust
pub struct CapabilitySet: u64 {
    const GUEST_IO              = 1 << 0;
    const PUBLIC_VALUES         = 1 << 1;
    const EXECUTE               = 1 << 2;
    const PROVE                 = 1 << 3;
    const VERIFY                = 1 << 4;
    const AGGREGATION           = 1 << 5;
    const RECURSION             = 1 << 6;
    const COMPRESSION           = 1 << 7;
    const ONCHAIN_PROOF         = 1 << 8;
    const SHA256_ACCEL          = 1 << 16;
    const KECCAK_ACCEL          = 1 << 17;
    const ELLIPTIC_CURVE_ACCEL  = 1 << 18;
    const CYCLE_METRICS         = 1 << 32;
    const REMOTE_PROVING        = 1 << 33;
}
```

With:

- `MINIMUM_VIABLE = GUEST_IO | PUBLIC_VALUES | EXECUTE | PROVE | VERIFY`
- `supports(Capability) -> bool`
- `satisfies(required) -> bool`
- `missing_from(required) -> CapabilitySet`
- `iter_capabilities()`
- a `Capability` enum for single-capability errors, with `as_flag()`

Bits are grouped by number with gaps: core operations low, crypto acceleration
at 16, operational concerns at 32. Room to grow per group without renumbering.

**The honesty rule, which is the actual point of this ADR: a bit is set only if
the adapter implements it and a test exercises it.** Not "the SDK supports it".
Both real adapters claim exactly `MINIMUM_VIABLE | CYCLE_METRICS | COMPRESSION`,
and each has a unit test asserting the *negative* claims - that `AGGREGATION`,
`RECURSION`, `ONCHAIN_PROOF` and the `*_ACCEL` bits are unset.

## Consequences

### Positive

- Requirements compose: `satisfies(MINIMUM_VIABLE | COMPRESSION)` is one call.
- `missing_from` produces an actionable error rather than "unsupported".
- `require_capability` gates every runner operation before any backend work, so
  failures are early and cheap.
- Adding a capability is additive; no adapter breaks.
- Compact and cheap - a `u64` copy, usable in a `no_std` guest.
- Negative-claim tests make dishonest capabilities a test failure rather than a
  review opinion.

### Negative

- **A bit is only as honest as the adapter author.** Nothing mechanical prevents
  setting `SHA256_ACCEL` without an implementation; the defence is the rule, the
  review checklist and the negative tests. This is a real limitation, not a
  solved problem.
- 64 bits is a ceiling. The grouped layout delays it, and crossing it would need
  a second word - a breaking change.
- Capabilities are per-adapter and static, so they cannot express "accelerated
  *if* the guest was built with the right patches". That is exactly why no
  `*_ACCEL` bit is set today: the host genuinely cannot know.
- A bitflags set is less self-documenting in a debugger than named booleans;
  mitigated by `iter_capabilities()` and `Display`.
- Capability granularity is a judgement call; too coarse hides differences, too
  fine becomes unusable.

## Alternatives considered

**Trait methods per feature.** Every new capability is a breaking trait change,
and requirements cannot be composed or diffed.

**A struct of bools.** Readable, but no set algebra, no `missing_from`, and a
verbose serialized form.

**Runtime probing** (try the operation, see if it fails). Honest by
construction, but proving is expensive, some probes have side effects, and
capability information is needed *before* the work starts.

**Version-based inference** ("SDK >= 6.0 means X"). Fragile, and it encodes
upstream's claims rather than this project's tested reality.
