import pytest

from mcp_supply_audit.cli import main
from mcp_supply_audit.completions import SHELLS, render


def test_each_shell_renders():
    bash = render("bash")
    assert "complete -F _mcp_supply_audit" in bash
    assert "--explain" in bash
    zsh = render("zsh")
    assert "#compdef" in zsh
    assert "--ecosystem" in zsh
    fish = render("fish")
    assert "complete -c mcp-supply-audit" in fish
    assert "npm pypi" in fish


def test_unknown_shell():
    with pytest.raises(KeyError):
        render("cmd")


def test_cli_completions_bash(capsys):
    assert main(["--completions", "bash"]) == 0
    assert "complete -F" in capsys.readouterr().out


def test_cli_completions_unknown():
    with pytest.raises(SystemExit) as err:
        main(["--completions", "cmd"])
    assert err.value.code == 2


def test_help_has_examples():
    with pytest.raises(SystemExit) as hi:
        main(["-h"])
    assert hi.value.code == 0
    # argparse writes help to stdout
    assert SHELLS
