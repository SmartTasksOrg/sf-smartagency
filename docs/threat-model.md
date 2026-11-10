# Threat model

## What SmartAgency protects

The decision whether an AI agent may take an action, and the record of that decision. The assets are the
issuer keys, the contracts, the status ledger and the audit log.

## Attacker capabilities considered, and the defence

| Attack | Defence | Test |
|---|---|---|
| Change a contract after signing (more grants, higher limits, later expiry) | Ed25519 over the canonical bytes of the whole contract | `test_every_field_change_breaks_the_signature`, `contracts.json` |
| Re-sign a changed contract with the issuer key, under the same id | The ledger binds each id to the digest of the issued body; a different body is not active | `test_a_contract_with_a_changed_body_is_not_the_issued_one` |
| Downgrade to a weaker algorithm | Only `ed25519` is accepted; no fallback | `contracts.json` "other algorithm" |
| Sign with an untrusted, expired or revoked key | Registry check at the time of use, for envelopes and every ledger entry | `decisions.json` "issuer key revoked", `test_expired_issuer_key_window` |
| Hide a revocation: delete, reorder or edit ledger entries | Hash chain, signatures, canonical lines; an invalid ledger denies everything | `ledger.json` invalid cases, `test_an_edited_ledger_file...`, `test_a_deleted_ledger_file...` |
| Roll the ledger file back to an older valid copy, or truncate it | A running monitor refuses a ledger that no longer starts with what it read; a new process refuses one without its anchor (the head kept elsewhere) | `test_rollback_is_detected...`, `test_a_truncated_ledger_file_is_detected` |
| Bypass a deny grant with `..`, `.`, `%2F`, case or Unicode variants of the path or verb | Such actions are invalid; paths and verbs are compared exactly and must arrive normalised | `test_ambiguous_actions_are_invalid` |
| Stall the monitor with wildcard patterns | Matching is linear in pattern × path length; at most four `**` per pattern | `test_wildcard_matching_is_fast` |
| Revoke or suspend someone else's contract | Only the issuer of the `issue` entry may sign later events | `test_only_the_issuer_can_change_a_contracts_status` |
| Obtain a grant through a second, more permissive contract | Deny overrides allow in any contract; the lowest limit and the strictest pressure apply | `decisions.json` "two contracts" |
| Split a forbidden operation into allowed steps (read a secret, then send it out) | Composite rules over the session; `check_plan` for whole plans | `decisions.json` "composite sequences" |
| Keep acting at high load | SmartFabric pressure: escalation needs a person; a release locks the agent until a person resets it | `decisions.json` "pressure" |
| Inject terminal escapes through contract fields | The command line JSON-escapes everything it repeats from a file | `test_cli_escapes_control_characters_in_problems` |
| Install a SmartFabric that stores pressure differently, so every step silently starts from zero | The monitor sets SmartFabric 0.5.x's state fields, reads them back, and runs a self-test when it starts; on a mismatch it refuses to start or to decide (`PressureStateError`). The dependency is pinned to `>=0.5.1,<0.6` | `test_an_incompatible_smartfabric_is_refused` |
| Crash the monitor with odd input | Malformed actions, sessions and times are denied with `invalid-action` before any state changes; deeply nested files fail closed | `test_non_string_and_odd_inputs_are_denied_not_raised`, `test_malformed_inputs_change_nothing_and_are_audited`, `test_deeply_nested_lines_fail_closed` |

## Out of scope

- **An agent that acts without asking the monitor.** SmartAgency decides; the host must route every action
  through it (a gateway, a SmartFabric node, or the agent framework's tool layer).
- **A stolen issuer key.** Revoke it in the registry (`revoked_at`); everything it signed stops being
  trusted from that time. Keeping the key safe (file permissions, an HSM) is the operator's job.
- **A rollback seen by nobody.** A process that starts fresh on a rolled-back ledger cannot tell without an
  anchor: keep the head that `sf-smartagency ledger verify` prints outside the ledger's reach and pass it.
- **Write access to the registry file.** Whoever can edit it decides which keys are trusted. Protect it like
  the keys.
- **The audit log's integrity against its writer.** Records are hash-chained, and signed when the monitor
  has a key (`AuditLog(path, signer=key)`); the monitor's host can still drop or rewrite unsigned files.
  Forward records to a SIEM to keep a copy the host cannot rewrite.
- **Whether a contract is wise.** The monitor enforces what the issuer signed.
- **Lock files.** Whoever can create `status.jsonl.lock` or `audit.jsonl.lock` stalls writers: each write
  waits five seconds, then fails closed (`audit-unavailable`, a refused ledger write). Protect the folder.
- **A restart of the monitor.** Pressure, release locks and sessions are kept in memory. A restarted
  monitor starts every agent at zero and unlocked: whoever can restart it can clear a lock without a
  person's reset. Restart it only when a person would also reset the agents, or suspend their contracts
  in the ledger first. The audit log still shows each agent's last pressure and zone.
- **Time.** Decisions use the host clock; an attacker who controls it can move inside or outside contract
  windows.
