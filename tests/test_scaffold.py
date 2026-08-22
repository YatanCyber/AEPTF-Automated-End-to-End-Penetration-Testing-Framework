import importlib
import sys

from typer.testing import CliRunner

from aeptf.cli import app

runner = CliRunner()


def test_new_plugin_scaffolds_a_working_plugin(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "aeptf" / "modules").mkdir(parents=True)

    result = runner.invoke(
        app,
        ["new-plugin", "tls-inspect", "--category", "enumeration", "--description", "Checks TLS."],
    )
    assert result.exit_code == 0, result.output

    generated = tmp_path / "aeptf" / "modules" / "enumeration" / "tls_inspect.py"
    assert generated.exists()
    content = generated.read_text()
    assert "class TlsInspectPlugin(AssessmentPlugin):" in content
    assert 'name = "tls-inspect"' in content
    assert "self.authorize(target, settings)" in content


def test_new_plugin_refuses_to_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pkg_dir = tmp_path / "aeptf" / "modules" / "enumeration"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_text("")
    (pkg_dir / "dupe.py").write_text("# already here")

    result = runner.invoke(app, ["new-plugin", "dupe", "--category", "enumeration"])
    assert result.exit_code != 0
