# Governance

## Principles

1. **Accuracy outranks polish.** Documentation and capability claims must match
   what the code actually does and what tests actually exercise.
2. **Decisions get written down.** Anything architectural lands as an ADR in
   [docs/adr/](docs/adr/) with its *negative* consequences stated.
3. **No vendor preference.** This project is not affiliated with any zkVM
   project and does not rank them. Adapter status reflects our integration
   maturity only.
4. **Security review is not optional** for code that accepts proofs.

## Roles

**Contributors** open issues and PRs. No formal process to start.

**Maintainers** review and merge, triage issues and security reports, and cut
releases. Listed in `.github/CODEOWNERS`. Added by consensus of existing
maintainers after a sustained record of good contributions and review judgement;
may step down at any time, and inactive maintainers are moved to emeritus after
roughly a year of inactivity.

**Backend owners** may be named per adapter. They own their adapter's SDK
version bumps and capability claims, and must keep its documentation accurate.

## Decision making

Lazy consensus for ordinary changes: a PR with maintainer approval and no
unresolved objection merges.

An ADR is required for changes to the crate structure, the `BackendAdapter`
trait, the wire encoding or container format, verification semantics, the
capability model, or the addition of a core dependency. Open it as a PR, allow
at least 72 hours for comment, and merge on maintainer consensus. Unresolved
disagreement is settled by a simple majority of maintainers, with the dissent
recorded in the ADR.

## Security decisions

Security reports are handled privately per [SECURITY.md](SECURITY.md) by
maintainers only. A fix may be merged and released before public discussion. Any
change that weakens a verification guarantee requires unanimous maintainer
agreement and a documented rationale — this is the one place where speed does
not win.

## Capability claims

Setting a capability bit is a governance matter, not just a code change. A PR
that adds a bit must include the implementation, a test that exercises it, and
documentation. Maintainers will reject a bit justified only by upstream
capability. Removing an inaccurate bit is always accepted and released promptly.

## Adding a backend

Per [docs/adding-a-backend.md](docs/adding-a-backend.md). A new adapter needs at
least two maintainer approvals, with one reviewing the verification path
specifically. Status promotion (`Planned` → `Supported` → `Stable`) is a
maintainer decision based on evidence: `Stable` requires end-to-end proving in
scheduled CI plus a passing portability suite.

## Releases

Maintainers cut releases following the process in
[CONTRIBUTING.md](CONTRIBUTING.md). Versioning policy is
[docs/versioning.md](docs/versioning.md). Security releases may be cut at any
time; feature releases happen when there is something worth releasing.

## Communication

GitHub issues for bugs and features, PRs for changes and ADRs, private
advisories for security. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies
everywhere.

## Changing this document

Via PR, with maintainer consensus and a 72-hour comment window.
