# Contributing

Thanks for helping make MCP supply-chain auditing better.

## Ground rules

- **Read-only, always.** The tool must never execute anything it fetches. PRs that
  introduce execution will be rejected on principle.
- **Zero runtime dependencies.** Stdlib only. Dev dependencies (pytest, ruff) are fine.
- **The rubric is public and debatable.** Scoring changes need a rationale in the PR
  description and a CHANGELOG entry — people cite these numbers.
- **Honesty over marketing.** Findings are heuristics. Wording matters: "signal", not
  "verdict".

## Dev setup

```bash
git clone <repo> && cd mcp-supply-audit
python3 -m pip install -e ".[dev]"
python3 -m pytest tests/ --cov=mcp_supply_audit
ruff check src tests
```

One logical change per commit. Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`.
Scoring or capability-pattern changes need a CHANGELOG entry — the talk cites corpus numbers.

## Good first contributions

- Corpus expansion (see `corpus/corpus.txt` — suggest widely-installed MCP servers)
- PyPI transitive resolver + PEP 740 (thin `--ecosystem pypi` slice already ships)
- Capability-pattern calibration (with false-positive analysis, please)
- Docs improvements and translations
