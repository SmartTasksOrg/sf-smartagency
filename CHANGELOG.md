# Changelog

All notable changes to SmartAgency are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semantic.

## Unreleased

## 0.1.1

### Documentation
- The README's family section is the shared one now used in every Smart* repository: all 18 tools, the
  IAIso label each README states, and a diagram whose only arrow between packages is a real dependency
  (SmartAgency requires SmartFabric). The PyPI page shows it from this release on; the code is unchanged.

## 0.1.0 — first release as `sf-smartagency`

### Added
- Contract format `smartagency.contract/1` (JSON Schema draft-07 plus semantic rules): SmartFabric CIR verbs
  on resource paths with `*` / `**` wildcards, allow and deny grants, per-action limits, influence class,
  SmartFabric pressure configuration, composite deny sequences, validity window, supersession.
- Ed25519 signing (only Ed25519), key ids, signed envelopes, an issuer registry with validity windows and
  key revocation.
- Status ledger: signed, hash-chained, canonical lines; issue, suspend, resume, revoke single grants,
  revoke, supersede; a lock file for concurrent writers; status at any time.
- Monitor: decisions allow / deny / escalate with reason codes, deny-overrides across contracts, lowest
  limits, composite sequences per session, SmartFabric pressure with escalation, release and a lock until a
  person's reset; fail closed on an invalid ledger; `check_plan` without side effects.
- Hash-chained audit records, optionally signed by the monitor's key, and an RFC 5424 syslog formatter.
- Command line: demo, keygen, validate, sign, verify, ledger, status, check, vectors.
- Specification (spec/SPEC.md), 162 conformance checks and their generator, design decisions and threat model.

### Fixed before release (pre-release review; tests in tests/test_review_fixes.py)
- The monitor carries each agent's pressure by setting two private fields of SmartFabric 0.5.x's engine. A
  SmartFabric release that stored them elsewhere would have made every step start from zero, so pressure
  never escalated, with no error. The monitor now reads the state back and runs a self-test when it starts,
  and refuses with `PressureStateError` on a mismatch. The restart behaviour (pressure and locks are kept in
  memory) is now stated in the spec, the threat model and the README.
- A ledger file replaced by an older valid copy, or truncated, revived revoked contracts. A reader now refuses
  a ledger that no longer starts with what it read, and `anchor` (the head kept elsewhere) catches a rollback
  in a new process. A deleted ledger is never restarted by a write.
- Composite rules forgot actions more than 64 steps back. They now track each rule's progress per session,
  keyed by the rule's content and counted for every loaded contract, so supersession or a suspension does
  not reset it (second review round).
- `check_plan` could erase a real session; it now uses its own state.
- A malformed session, a time without a time zone or a huge usage figure raised after changing pressure and
  left no audit record. Such input is now `invalid-action`; the audit record is written before any state
  changes, and a decision that cannot be audited is denied (`audit-unavailable`).
- Deeply nested JSON raised RecursionError; ledgers, audit logs, registries and the command line now fail closed.
- Path and verb variants (`..`, `.`, `%2F`, upper-case or malformed extension verbs, Unicode, `;` and other
  punctuation) slipped past deny grants. Such actions are `invalid-action` and contracts cannot use them.
  Paths stay case-sensitive: hosts must pass the same normalised path they act on.
- `**` matching took exponential time; it is now linear, with at most four `**` per pattern.
- `check --session` did nothing and is removed; the README says `check` is one-shot.
- Concurrent audit writers broke the chain; appends now take a lock and catch up first.
- Decisions before the pressure step reported the zone from SmartFabric's defaults, not the contract's.
- Base64 strings with unused bits set, times without zero padding and ledger lines ending in `\r\n` were
  accepted; each value now has one spelling. A ledger whose last line has no newline is refused.
- `ledger verify` and `status` on a missing file reported success; they now fail.
- Audit records could be fabricated by anyone who rebuilt the hash chain. `AuditLog(path, signer=key)` now
  signs every record with the monitor's key, and `record_signed_by` checks one (found by the review of the
  private accounting layer). The monitor refuses an audit key that is also an issuer key.
- Second review round: a deleted audit file is not restarted mid-chain; audit records of invalid input
  carry a time; a non-string anchor is a `LedgerError`.
