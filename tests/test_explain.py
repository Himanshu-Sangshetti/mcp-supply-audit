import pytest

from mcp_supply_audit.cli import main
from mcp_supply_audit.explain import _EXPLAIN, explain, known_ids
from mcp_supply_audit.scoring import FINDINGS


def test_every_finding_has_an_explanation():
    assert set(_EXPLAIN) == set(FINDINGS)
    for fid in FINDINGS:
        text = explain(fid)
        assert text.startswith(fid)
        assert "why:" in text
        assert "do:" in text


def test_explain_unknown_is_keyerror():
    with pytest.raises(KeyError):
        explain("MSA-NOPE")


def test_cli_explain_one(capsys):
    assert main(["--explain", "MSA-P007"]) == 0
    out = capsys.readouterr().out
    assert "MSA-P007" in out
    assert "installing is enough" in out.lower() or "E10" in out


def test_cli_explain_all(capsys):
    assert main(["--explain"]) == 0
    out = capsys.readouterr().out
    for fid in known_ids():
        assert fid in out


def test_cli_explain_unknown():
    with pytest.raises(SystemExit) as err:
        main(["--explain", "MSA-NOPE"])
    assert err.value.code == 2
