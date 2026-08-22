"""Authorization policy enforcement.

This module is the single gate every plugin must call before it does
anything to a target. There is intentionally no override parameter, no
"skip check" flag, and no way to authorize a target from inside a request
body. Targets are only ever authorized by being listed, ahead of time, in
configs/*.yml (or the AEPTF__SAFETY__APPROVED_TARGETS environment
variable) by whoever operates the AEPTF instance.

AEPTF assumes the operator has independently confirmed they are legally
authorized (e.g. a signed scope document, bug-bounty program scope, or
ownership) to assess every host listed in approved_targets. AEPTF does not
and cannot verify legal authorization on its own; the allowlist is a
technical control, not a substitute for that authorization.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from aeptf.core.config import SafetyConfig


class AuthorizationError(PermissionError):
    """Raised when a target is not present in the approved-targets allowlist."""


@dataclass(frozen=True)
class AuthorizationDecision:
    target: str
    allowed: bool
    reason: str


def _normalize(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _resolve_candidates(target: str) -> set[str]:
    """Return the set of literal strings a target could match against.

    This resolves hostnames to IP addresses so that an approved IP also
    matches a hostname resolving to it, and vice versa, without ever
    expanding the match to a subnet, wildcard, or partial string.
    """
    candidates = {_normalize(target)}
    try:
        ipaddress.ip_address(target)
    except ValueError:
        try:
            resolved = socket.gethostbyname(target)
            candidates.add(_normalize(resolved))
        except (socket.gaierror, socket.timeout, OSError):
            pass
    return candidates


def check_authorization(target: str, safety: SafetyConfig) -> AuthorizationDecision:
    """Check whether `target` is present in the approved-targets allowlist.

    This performs an exact match only (after hostname resolution). No
    wildcards, no CIDR expansion, no prefix/substring matching -- an
    approved_targets entry authorizes exactly the host(s) it names.
    """
    if not safety.authorization_required:
        return AuthorizationDecision(target=target, allowed=True, reason="authorization_required is disabled")

    approved = {_normalize(t) for t in safety.approved_targets}
    candidates = _resolve_candidates(target)

    if candidates & approved:
        return AuthorizationDecision(target=target, allowed=True, reason="target present in approved_targets")

    return AuthorizationDecision(
        target=target,
        allowed=False,
        reason=(
            f"'{target}' is not present in safety.approved_targets. "
            "Add the exact hostname or IP to configs/default.yml before running any plugin against it."
        ),
    )


def enforce_authorization(target: str, safety: SafetyConfig) -> None:
    """Raise AuthorizationError if `target` is not explicitly approved."""
    decision = check_authorization(target, safety)
    if not decision.allowed:
        raise AuthorizationError(decision.reason)
