from aeptf.core.config import Settings, PluginsConfig, SafetyConfig
from aeptf.core.plugins import PluginRegistry
from aeptf.core.safety import AuthorizationError
import pytest


def _settings(enabled: list[str], approved: list[str]) -> Settings:
    return Settings(
        plugins=PluginsConfig(enabled=enabled),
        safety=SafetyConfig(authorization_required=True, approved_targets=approved),
    )


def test_registry_loads_enabled_plugins():
    settings = _settings(
        enabled=["aeptf.modules.reconnaissance.discovery.HostDiscoveryPlugin"],
        approved=["127.0.0.1"],
    )
    registry = PluginRegistry(settings)
    assert "reconnaissance" in registry.names()


def test_registry_records_import_errors_without_raising():
    settings = _settings(enabled=["aeptf.modules.nonexistent.Nothing"], approved=[])
    registry = PluginRegistry(settings)
    entries = registry.list_plugins()
    assert any("FAILED TO LOAD" in e["description"] for e in entries)


def test_plugin_run_denies_unapproved_target():
    settings = _settings(
        enabled=["aeptf.modules.enumeration.http_metadata.HttpMetadataPlugin"],
        approved=["127.0.0.1"],
    )
    registry = PluginRegistry(settings)
    plugin = registry.get("enumeration")
    with pytest.raises(AuthorizationError):
        plugin.run("not-an-approved-host.example", settings)


def test_list_plugins_reports_meta_and_readiness():
    settings = _settings(
        enabled=["aeptf.modules.reconnaissance.discovery.HostDiscoveryPlugin"],
        approved=["127.0.0.1"],
    )
    registry = PluginRegistry(settings)
    entries = {e["name"]: e for e in registry.list_plugins()}
    entry = entries["reconnaissance"]
    assert entry["version"] == "1.0.0"
    assert "nmap" in entry["requires_binaries"]
    assert "ready" in entry and "ready_reasons" in entry


def test_plugin_run_emits_events():
    from aeptf.core.hooks import get_event_bus

    settings = _settings(
        enabled=["aeptf.modules.enumeration.http_metadata.HttpMetadataPlugin"],
        approved=["127.0.0.1"],
    )
    registry = PluginRegistry(settings)
    plugin = registry.get("enumeration")

    seen = []
    bus = get_event_bus()
    handler = lambda payload: seen.append(payload)
    bus.on("run.denied", handler)
    try:
        with pytest.raises(AuthorizationError):
            plugin.run("not-approved.example", settings)
        assert any(p["target"] == "not-approved.example" for p in seen)
    finally:
        bus.off("run.denied", handler)
