"""AEPTF: Automated End-to-End Penetration Testing Framework.

A Linux-first scaffold for organizing *authorized* security assessments.
Every assessment action must pass through aeptf.core.safety.enforce_authorization
before it touches a target. See README.md for the authorization model.
"""

__version__ = "0.1.0"
