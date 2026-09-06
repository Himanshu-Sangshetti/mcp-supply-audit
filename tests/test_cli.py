import json

import pytest

from mcp_supply_audit import __version__
from mcp_supply_audit.cli import main


def test_help_and_version_exit_clean(capsys):
    with pytest.raises(SystemExit) as hi:
        main(["-h"])
    assert hi.value.code == 0
    help_out = capsys.readouterr().out
    assert "examples:" in help_out
    assert "--explain" in help_out
    assert "--completions" in help_out
    with pytest.raises(SystemExit) as vi:
        main(["--tool-version"])
    assert vi.value.code == 0


def test_no_packages_is_usage_error():
    with pytest.raises(SystemExit) as err:
        main([])
    assert err.value.code == 2


def test_report_renders_and_exits_zero(tmp_path, capsys):
    doc = {
        "results": [{
            "package": "demo", "version": "1.0.0",
            "transitive_deps": 3, "floating_direct": 0,
            "capabilities": {},
            "provenance": True, "publisher_trusted": True,
            "install_scripts": [],
            "score_package": 90, "score_registry": 100,
            "score_sdk": 90, "score_overall": 93,
        }]
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(doc))
    assert main(["--report", str(path)]) == 0
    out = capsys.readouterr().out
    assert "Servers audited" in out
    assert "`demo`" in out


def test_tool_version_string():
    assert __version__
