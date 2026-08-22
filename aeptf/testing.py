"""Test helpers for people writing AEPTF plugins.

Not imported by the framework itself -- this is for *your* test suite,
so you don't have to hand-build a Settings object and a fake authorized
target every time. Example::

    from aeptf.testing import make_test_settings, assert_denied_for_unapproved_target
    from mypkg.my_plugin import MyPlugin

    def test_my_plugin_denies_unapproved_target():
        plugin = MyPlugin()
        settings = make_test_settings(approved_targets=["127.0.0.1"])
        assert_denied_for_unapproved_target(plugin, settings, "not-approved.example")

    def test_my_plugin_runs_against_approved_target():
        plugin = MyPlugin()
        settings = make_test_settings(approved_targets=["127.0.0.1"])
        result = plugin.run("127.0.0.1", settings)
        assert result.status in {"success", "error"}  # error is fine if e.g. nmap is absent in CI
"""
from __future__ import annotations

from aeptf.core.config import Settings, SafetyConfig
from aeptf.core.plugins import AssessmentPlugin
from aeptf.core.safety import AuthorizationError


def make_test_settings(
    approved_targets: list[str] | None = None,
    authorization_required: bool = True,
    max_scan_ports: int = 100,
    network_timeout_seconds: int = 5,
    nmap_timeout_seconds: int = 30,
) -> Settings:
    """Build a minimal Settings instance for plugin unit tests, without
    reading configs/default.yml or the environment."""
    return Settings(
        safety=SafetyConfig(
            authorization_required=authorization_required,
            approved_targets=approved_targets or [],
            max_scan_ports=max_scan_ports,
            network_timeout_seconds=network_timeout_seconds,
            nmap_timeout_seconds=nmap_timeout_seconds,
        )
    )


def assert_denied_for_unapproved_target(plugin: AssessmentPlugin, settings: Settings, target: str) -> None:
    """Assert that running `plugin` against `target` raises AuthorizationError.

    Use an obviously-unapproved target (not present in settings.safety.approved_targets).
    Requires pytest to be installed (it's expected to be, in your test environment).
    """
    import pytest  # local import: aeptf.testing shouldn't hard-require pytest at import time

    with pytest.raises(AuthorizationError):
        plugin.run(target, settings)
