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
git clone https://github.com/Himanshu-Sangshetti/mcp-supply-audit && cd mcp-supply-audit
python3 -m pip install -e ".[dev]"
python3 -m pytest tests/ --cov=mcp_supply_audit
ruff check src tests
```

One logical change per commit. Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`.
Scoring or capability-pattern changes need a CHANGELOG entry — the talk cites corpus numbers.

## Good first contributions

Concrete starter tasks with scope and pitfalls: [`docs/ROADMAP.md`](docs/ROADMAP.md#good-first-issues) (GFI-1 … GFI-7).
