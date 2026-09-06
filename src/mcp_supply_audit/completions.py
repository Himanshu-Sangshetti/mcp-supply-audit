"""Shell completion scripts. Stdlib only — no argcomplete."""

FLAGS = (
    "--corpus --version --diff --json --sarif --sbom --lock --check "
    "--report --explain --fail-under --no-cache --workers --ecosystem "
    "--completions --help --tool-version"
)
ECOSYSTEMS = "npm pypi"
SHELLS = ("bash", "zsh", "fish")


def render(shell: str) -> str:
    s = shell.strip().lower()
    if s == "bash":
        return (
            "# mcp-supply-audit bash completion — eval \"$(mcp-supply-audit --completions bash)\"\n"
            "_mcp_supply_audit() {\n"
            f"  local cur opts ecos\n"
            f"  COMPREPLY=()\n"
            f"  cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n"
            f"  opts=\"{FLAGS}\"\n"
            f"  ecos=\"{ECOSYSTEMS}\"\n"
            "  if [[ ${COMP_WORDS[COMP_CWORD-1]} == --ecosystem ]]; then\n"
            "    COMPREPLY=( $(compgen -W \"$ecos\" -- \"$cur\") )\n"
            "    return 0\n"
            "  fi\n"
            "  COMPREPLY=( $(compgen -W \"$opts\" -- \"$cur\") )\n"
            "}\n"
            "complete -F _mcp_supply_audit mcp-supply-audit\n"
        )
    if s == "zsh":
        return (
            "#compdef mcp-supply-audit\n"
            "# mcp-supply-audit zsh completion — eval \"$(mcp-supply-audit --completions zsh)\"\n"
            "_mcp_supply_audit() {\n"
            "  local -a opts\n"
            f"  opts=({' '.join(f'{f}' for f in FLAGS.split())})\n"
            "  if [[ $words[CURRENT-1] == --ecosystem ]]; then\n"
            "    _values ecosystem npm pypi && return\n"
            "  fi\n"
            "  _describe 'options' opts\n"
            "}\n"
            "compdef _mcp_supply_audit mcp-supply-audit\n"
        )
    if s == "fish":
        flags = "\n".join(
            f"complete -c mcp-supply-audit -l {f[2:]} -d '{f}'"
            for f in FLAGS.split()
            if f.startswith("--") and f != "--help"
        )
        return (
            "# mcp-supply-audit fish completion — mcp-supply-audit --completions fish | source\n"
            f"{flags}\n"
            "complete -c mcp-supply-audit -l ecosystem -xa 'npm pypi'\n"
            "complete -c mcp-supply-audit -s h -l help\n"
        )
    raise KeyError(shell)
