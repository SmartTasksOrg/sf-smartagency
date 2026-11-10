# SmartAgency specification, version 1 (smartagency.contract/1)

This document is normative for every implementation. The Python package (`src/sf_smartagency`) is the
reference; the vectors in `spec/conformance/` test it. When this text and the vectors disagree, that is a
bug to report. "MUST", "MUST NOT" and "MAY" are used in their RFC 2119 sense.

## 1. Purpose and parts

A **contract** says what one AI agent (the *subject*) may do: which actions it may take, under which limits,
and for how long. An **issuer** signs it. A **status ledger** records when the issuer issues, suspends,
resumes, partly revokes, revokes or supersedes a contract. A **monitor** decides every action the agent asks
to take, from the contracts, the ledger and the agent's SmartFabric pressure, and writes an **audit record**
for each decision.

Actions are SmartFabric CIR verbs (`invoke`, `query`, `plan`, ...; see sf-smartfabric `CIR_VERBS`) or
namespaced extensions `x-<namespace>-<verb>`, applied to a **resource**, a `/`-separated path.

## 2. Canonical JSON and digests

Signed and hashed objects are serialised as canonical JSON: UTF-8, object keys sorted by code point, no
insignificant whitespace (`,` and `:` separators), the same rules as SmartFabric's wire format. Signed
objects MUST NOT contain floats (fractions are decimal strings), integers outside |n| < 2^53, unpaired
surrogates, or nesting deeper than 32. The digest of an object is `sha256:` plus the lowercase hex SHA-256
of its canonical bytes. Vectors: `canonical.json`.

## 3. Keys and signatures

Only Ed25519 (RFC 8032) is accepted. There is no fallback algorithm: a verifier that accepted a second
algorithm would let an attacker downgrade a contract to it.

- The key id of a public key is `ed25519:` plus the first 32 hex digits of SHA-256 of its 32 raw bytes.
- Signatures and public keys are written in URL-safe base64 without padding, in the one canonical
  spelling: a string that is not exactly what encoding its decoded bytes gives (padding, other characters,
  unused bits set in the last character) is invalid, as is a signature that is not 64 bytes.

Vectors: `keys.json`.

## 4. Contracts

### 4.1 Fields

A contract MUST validate against `spec/schema/contract.schema.json` (JSON Schema draft-07):

| Field | Meaning |
|---|---|
| `schema` | `smartagency.contract/1` |
| `id` | the issuer's identifier for this contract, `[A-Za-z0-9._:-]{1,128}` |
| `version` | `MAJOR.MINOR.PATCH` of this contract |
| `issuer` | the key id that signs it |
| `subject` | the agent, 1 to 256 printable ASCII characters (for example a SmartFabric `iaiso://` address) |
| `roles` | labels, informational only |
| `grants` | 1 to 256 `{verb, resource, effect}` with effect `allow` or `deny` |
| `limits` | `max_tokens`, `max_tool_calls`, `max_depth` per action; `max_influence` (a SmartFabric influence class); optional `pressure` |
| `composite` | optional rules `{name, deny_sequence}`: 2 to 8 action patterns that must not occur in order in one session |
| `not_before`, `expires` | exactly `YYYY-MM-DDTHH:MM:SSZ` (zero-padded, UTC); the contract applies when `not_before <= t < expires` |
| `supersedes` | optional id of an earlier contract of the same issuer that this one replaces |

`limits.pressure` holds SmartFabric `PressureConfig` fields as decimal strings: `escalation_threshold`,
`release_threshold`, `dissipation_per_step`, `token_coefficient`, `tool_coefficient`, `depth_coefficient`.
Absent fields take SmartFabric's defaults. The fabric-only warning band is the lower of SmartFabric's
default and the escalation threshold.

### 4.2 Semantic rules (beyond the schema)

- Every grant and composite verb is a CIR verb, an `x-` extension, or `*` (any verb).
- Resource patterns: `*` and `**` are wildcards only as a whole segment; at most four `**` segments; no
  empty, `.` or `..` segment; no `%` or backslash. Paths are compared literally, so they must be decoded and
  normalised before they reach a contract or the monitor.
- `expires` is later than `not_before`.
- The pressure configuration passes SmartFabric's validation (thresholds in [0, 1], release above
  escalation, coefficients not negative).
- Composite rule names are unique; a contract does not supersede itself.

### 4.3 Matching

A pattern's verb matches when it is `*` or equal. A resource pattern matches segment by segment: `*`
matches exactly one segment, `**` matches zero or more, any other segment matches only itself
(case-sensitive). Resources and patterns use only `A-Z a-z 0-9 . _ ~ : @ + = / -` (and `*` in patterns). An
action's own resource follows the same rules as a pattern and MUST NOT contain `*`. A verb matches
`[a-z]+(\.[a-z]+)?` or `x-<namespace>-<name>` with lowercase letters and digits and dot-separated name parts
(`x-[a-z0-9]+-[a-z0-9]+(\.[a-z0-9]+)*`). Paths are compared case-sensitively and literally: the host MUST
pass the monitor the same normalised path and verb it then acts on.

### 4.4 Signed envelope

    {"contract": {...}, "signature": {"alg": "ed25519", "kid": "<key id>", "sig": "<signature>"}}

The envelope has exactly these fields; `kid` equals `contract.issuer`; `sig` is over the canonical bytes of
`contract`; the contract is valid; and the issuer key is trusted at the time of the check (section 5).
Vectors: `contracts.json`.

## 5. Issuer registry

A registry lists trusted issuer keys: `kid`, `public_key`, `name`, `not_before`, and optionally `not_after`
and `revoked_at`. The `kid` MUST match the key. A key is trusted at time t when
`not_before <= t`, `t < not_after` and `t < revoked_at`. When a key is revoked, everything it signed stops
being trusted from `revoked_at`.

## 6. Status ledger

An append-only list of signed entries, one JSON object per line in its canonical form:

| Field | Meaning |
|---|---|
| `schema` | `smartagency.ledger/1` |
| `seq` | 0, 1, 2, ... |
| `prev` | digest of the previous entry, or `sha256:` and 64 zeros for the first |
| `at` | time of the event, never earlier than the previous entry |
| `event` | `issue` (optional `supersedes`), `suspend`, `resume`, `revoke_grants` (`grants`: distinct indexes 0 to 255), `revoke` |
| `contract_id`, `contract_digest` | the contract and the digest of its body |
| `reason` | optional, at most 500 characters |
| `kid`, `sig` | the signer and its signature over the entry without `sig` |

Rules, checked for every entry when it is appended or read:
- the signer's key is trusted at `at`;
- `issue` names a contract id that was never issued;
- every later event is signed by the issuer of the `issue` entry and carries the same digest;
- `suspend` needs an active contract, `resume` a suspended one;
- nothing follows `revoke`, or the supersession of a contract;
- `supersedes` names a live contract of the same issuer, which becomes `superseded`.

A file is invalid as a whole when an entry breaks any rule, or a line is not exactly the canonical form of its
entry followed by one `\n` (the last line included). A reader that has already read entries MUST refuse a
file that no longer starts with them (shrunk, rolled back or rewritten). To detect a rollback to an older
valid copy in a new process, keep the ledger's *head* (`<seq>:<digest of that entry>`) where the ledger's
writer cannot change it, and require that the ledger contains it (`anchor`). The status of a contract at time t replays the entries dated at or before t: `unknown`,
`active`, `suspended`, `revoked` or `superseded`, with the revoked grant indexes. Vectors: `ledger.json`.

## 7. Decisions

`check(subject, verb, resource, tokens, tool_calls, depth, influence, session, at)` returns
`{outcome, reasons, contract_ids, pressure, zone}`. The monitor applies these steps in order and stops at
the first that denies:

1. **invalid-action**: the subject is not 1 to 256 printable ASCII characters, the verb or resource is
   malformed (section 4.3), a usage figure is not an integer from 0 to 2^53, the influence class is
   unknown, the session is not absent or 1 to 256 printable ASCII characters, or the time has no time zone.
2. **ledger-invalid**: the ledger does not verify (for example its file was edited or removed). Fail closed.
3. **no-active-contract**: no loaded contract for the subject is *active* at t. Active means: a valid
   signed envelope; the issuer key trusted at t; ledger status `active`; the ledger digest equal to the
   contract's digest; `not_before <= t < expires`. Revoked grants are removed from an active contract.
4. **denied-by-grant**: a `deny` grant of any active contract matches. `contract_ids` lists those contracts.
5. **no-matching-grant**: no `allow` grant of an active contract matches (default deny).
6. **limit-tokens**, **limit-tool-calls**, **limit-depth**, **limit-influence**: the action exceeds the
   lowest limit among the contracts that allow it. Every exceeded limit is reported.
7. **composite:<name>**: the actions of this session that reached step 8, followed by this action, contain
   the rule's sequence in order (not necessarily adjacent, however far apart), and this action matches the
   last pattern. A rule fires when it belongs to an active contract. Progress is tracked per rule content
   (the digest of its `deny_sequence`) for the rules of every contract loaded for the subject, active or
   not, so a superseding contract with the same rule, or a suspended contract that resumes, sees actions
   taken before. Without a session, only this action counts.
8. **Pressure**, with SmartFabric's `PressureEngine` and the most restrictive configuration among all of
   the subject's active contracts (lowest thresholds and dissipation, highest coefficients):
   - if the subject is locked after a release: deny, **pressure-locked**;
   - otherwise one step with the action's tokens, tool calls and depth. If it releases: deny,
     **pressure-release** (the subject is now locked until a person resets it). If it ends in the
     escalation zone: **escalate**, **pressure-escalation** (a person must authorise the action before it
     runs). Otherwise: **allow**.

Pressure is per subject. Only actions that reach step 8 change it or the session. When an audit log is
configured, the decision's record is written first; if it cannot be written, the decision is **deny** with
**audit-unavailable**, and nothing changes. `contract_ids` is sorted.
`pressure` is a decimal string with at most 6 decimals and no trailing zeros (`"0"`, `"0.125"`); decisions
that stop before step 8 report the subject's current pressure and zone. A reset (a person's decision)
clears the subject's pressure and lock.

This version keeps pressure, locks and sessions in the monitor's memory. A new monitor starts every subject
at zero pressure and unlocked; restarting it therefore has the effect of a reset for every subject, without a
person's decision or an audit record. An implementation that keeps this state across restarts MUST NOT
restore a lower pressure, or an unlocked state, than the subject last had.

`check_plan(subject, steps, at)` decides a list of steps in order as one session, starting from the
subject's current pressure, and changes no state. Vectors: `decisions.json`.

## 8. Audit records

Every decision and reset appends a record `{schema: "smartagency.audit/1", seq, prev, at, subject, verb,
resource, session, outcome, reasons, contract_ids, pressure, zone, usage, influence}`. `prev` chains the
records as in the ledger. Writers append under a lock file and first catch up with records other writers
added. With a signer (the monitor's own Ed25519 key, which MUST NOT be an issuer key), each record also carries
`kid` and, last, `sig`: the signature over the record without `sig`. Verify records against a registry of
monitor keys only. Anyone who uses records as evidence (for example to pay for the
work they describe) MUST check those signatures against the monitor's key: a hash chain alone can be
rebuilt by anyone. Without a signer, protect the file like any audit log, or forward it.
`to_syslog` formats a record as an RFC 5424 line (facility 13, severity 6 for allow, 5 for deny, 4 for
escalate) whose message is the record's canonical JSON.

## 9. What this version does not define

- How a contract reaches the agent's host, and how the monitor is placed in front of the agent (sidecar,
  library, gateway).
- Who authorises an escalated action, and how. SmartGate can do this.
- Rate limits over time windows, and budgets across actions (pressure covers accumulation).
- Delegation from a person to an agent, or from one agent to another, field masking and money budgets:
  SmartDelegate does this. A host that uses both calls each one, and an action runs only if both allow it.
- Keeping pressure, locks and sessions across a restart of the monitor (section 7).
- Performance targets. The council proposed latency figures; none of them was measured, so none is part of
  this specification (docs/decisions.md).

## 10. Conformance

An implementation passes when, for every file in `spec/conformance/`, it reproduces every expected value.
`sf-smartagency vectors` runs the bundled copy and prints `python: N/N vectors passed`.

| File | Checks |
|---|---|
| `canonical.json` | canonical bytes and digests; refused inputs |
| `keys.json` | public key, key id and signature from each seed; verify cases |
| `contracts.json` | contract validity; envelope validity at `verify_at`; resource matching |
| `ledger.json` | a valid ledger and statuses at given times; invalid ledgers that must be refused |
| `decisions.json` | scenarios: registry, ledger, signed contracts, then steps with the expected decisions |
