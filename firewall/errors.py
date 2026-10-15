"""Domain exception types (frozen contract). Messages must never contain argument values."""

from __future__ import annotations


class FirewallError(Exception):
    """Base class for errors raised by the firewall."""


class PolicyError(FirewallError):
    """The policy file is missing, unreadable or invalid. Callers must treat this as DENY."""


class AuditError(FirewallError):
    """The audit log could not be written or read."""
