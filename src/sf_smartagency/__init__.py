"""SmartAgency: signed contracts that say what an AI agent may do, a status ledger to suspend and revoke
them, and a monitor that enforces them on every action, with SmartFabric pressure limits.

Specification: spec/SPEC.md. Public API:
    keys                                  Ed25519 keys, key ids, signatures
    contract.validate / contract.sign     contract checks and signing
    Registry                              trusted issuer keys
    StatusLedger, LedgerError             signed, hash-chained contract status
    Monitor, Decision, PressureStateError the enforcement monitor
    AuditLog, to_syslog                   hash-chained decision records
"""
from ._version import __version__
from . import canonical, contract, keys
from .audit import AuditLog, record_signed_by, to_syslog, verify_records
from .ledger import LedgerError, StatusLedger
from .monitor import Decision, Monitor, PressureStateError
from .registry import Registry, RegistryError

__all__ = ["__version__", "canonical", "contract", "keys", "AuditLog", "record_signed_by", "to_syslog", "verify_records",
           "LedgerError", "StatusLedger", "Decision", "Monitor", "PressureStateError", "Registry", "RegistryError"]
