# Design decisions: from the council to version 0.1.0

SmartAgency started from a SmartSignal design council ("Agency Contract v0", 2026-10-26: 120 stakeholder
views, 15 juror merges, every phase decided). `sf-smartsavant audit` reads that run as a real deliberation.
Its Frame and Concept phases define the product. From Design on, the council moved into performance tuning,
and the figures it set there were not measured. This page lists what was adopted, what was changed and why,
and what was left out.

## Adopted

| Council decision | In 0.1.0 |
|---|---|
| Canonical contract schema (JSON Schema draft-07) with version, roles, permissions, expiry, cryptographic fields | `spec/schema/contract.schema.json`: `version`, `roles`, `grants`, `limits`, `not_before`/`expires`; the signature lives in the envelope, not in the contract |
| Signed envelope, Ed25519, a provider key registry | `contract.sign` / `envelope_problems`; the issuer registry (SPEC.md section 5) with validity windows and key revocation |
| Local status ledger, append-only | `StatusLedger`: signed, hash-chained, one canonical line per entry, written under a lock with fsync |
| Enforcement monitor | `Monitor.check`, with SmartFabric pressure from the contract's limits |
| Composite-action checks | `composite` rules: forbidden sequences within a session; `check_plan` for a whole plan |
| Edge cases: partial revocation, cross-provider conflicts | `revoke_grants` ledger events; several contracts for one agent (next table) |
| Versioning: semantic versions, upgrade path | `version` in each contract; `supersedes` replaces a contract atomically in the ledger |
| Audit log: structured JSON with contract id, action, time, signature result, for a SIEM | `AuditLog` (hash-chained records) and `to_syslog` (RFC 5424 lines) |
| Conformance suite: schema, signatures, ledger, audit, monitor | `spec/conformance/` (162 checks) and `sf-smartagency vectors` |
| Threat model: tampering, downgrade | docs/threat-model.md |

## Changed

| Council decision | Changed to | Why |
|---|---|---|
| RSA-PSS as a fallback signature | Ed25519 only | The spec also said contracts that the primary scheme cannot verify are rejected; a fallback the verifier accepts is a downgrade path |
| Conflicts between providers: deterministic tie-break by provider id, compared lexicographically | Deny overrides allow across all active contracts; the lowest limit wins; the strictest pressure configuration applies | A lexicographic order is deterministic but arbitrary: whoever picks the lower id wins. Deny-overrides is deterministic and never grants more than every contract allows |
| JSON precedence rules as the policy language | Grants with `allow` / `deny` effects and path wildcards | Precedence lists made order significant and conflicted with "deny by default"; effects plus deny-overrides need no order |
| Ledger in a memory-mapped file for speed | A plain append-only file, fsync per entry | Nothing measured shows the simpler file is too slow; measure before optimising |
| Policy drift: alert when the policy's hash differs by more than 0.1 % | Any change is detected: the ledger binds each contract's digest | Two hashes are equal or not; a percentage difference between hashes has no meaning |
| Risk score (NIST SP 800-30, probability × impact, thresholds 0.3 / 0.6) | Not in the monitor; runtime risk is SmartFabric pressure | A risk assessment is a review process, not a per-action computation |

## Not in 0.1.0

- **Performance figures**: 0.2 ms ledger writes, 0.5 ms verification, 10,000 writes per second, garbage
  collector pauses under 0.05 ms, and the k6, Prometheus, network-emulation and GC-tuning steps around
  them. None was measured, and some contradicted each other (the council's own spec lists five different
  latency figures). They can return as measured results, not as promises.
- **OAuth2/OIDC mapping** of agents to contracts: the subject is an opaque id; mapping a token's `sub` to it
  belongs to the integration.
- **HSM key storage and rotation schedules**: `keygen` writes a PEM file readable only by its owner; where an
  operator keeps the key is theirs to decide. Rotation is a new registry key plus `supersedes`.
- **Automated rollback on an SLA breach**: there is no SLA in this version.
- **The training-dataset part of the council run** (500,000 contracts, annotation accuracy, deduplication):
  not part of the public package.

## Open questions

- Who authorises an `escalate` decision, and how the approval reaches the monitor (SmartGate is the
  family's tool for this).
- Ports to other languages: the vectors are written so that a port can be checked mechanically.
