from aeptf.core.config import SafetyConfig
from aeptf.core.safety import check_authorization, enforce_authorization, AuthorizationError
import pytest


def test_approved_target_allowed():
    safety = SafetyConfig(authorization_required=True, approved_targets=["127.0.0.1"])
    decision = check_authorization("127.0.0.1", safety)
    assert decision.allowed is True


def test_unapproved_target_denied():
    safety = SafetyConfig(authorization_required=True, approved_targets=["127.0.0.1"])
    decision = check_authorization("10.0.0.99", safety)
    assert decision.allowed is False


def test_enforce_raises_for_unapproved_target():
    safety = SafetyConfig(authorization_required=True, approved_targets=["127.0.0.1"])
    with pytest.raises(AuthorizationError):
        enforce_authorization("example.com", safety)


def test_authorization_disabled_allows_anything():
    safety = SafetyConfig(authorization_required=False, approved_targets=[])
    decision = check_authorization("anything.example", safety)
    assert decision.allowed is True


def test_no_substring_or_wildcard_matching():
    # "127.0.0.1" approved should NOT authorize "127.0.0.100" or similar.
    safety = SafetyConfig(authorization_required=True, approved_targets=["127.0.0.1"])
    decision = check_authorization("127.0.0.100", safety)
    assert decision.allowed is False
