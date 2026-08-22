import pytest

from aeptf.core.config import Settings, PipelinesConfig
from aeptf.core.executor import resolve_pipeline_steps


def test_resolve_default_pipeline():
    settings = Settings(
        pipelines=PipelinesConfig(
            default="default",
            definitions={"default": ["reconnaissance", "scanning"]},
        )
    )
    name, steps = resolve_pipeline_steps(settings, None)
    assert name == "default"
    assert steps == ["reconnaissance", "scanning"]


def test_resolve_named_pipeline():
    settings = Settings(
        pipelines=PipelinesConfig(
            default="default",
            definitions={"default": ["reconnaissance"], "web-only": ["enumeration"]},
        )
    )
    name, steps = resolve_pipeline_steps(settings, "web-only")
    assert name == "web-only"
    assert steps == ["enumeration"]


def test_resolve_unknown_pipeline_raises():
    settings = Settings(pipelines=PipelinesConfig(default="default", definitions={"default": ["reconnaissance"]}))
    with pytest.raises(KeyError):
        resolve_pipeline_steps(settings, "does-not-exist")
