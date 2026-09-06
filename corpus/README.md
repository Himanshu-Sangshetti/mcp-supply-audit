# Corpus study — "State of the MCP Supply Chain"

Base-rate measurement of the MCP server supply chain, run with `mcp-supply-audit`
against the live npm registry.

- **Run date:** 2026-09-06
- **Sample:** 47 MCP servers that install today (90 candidate names probed; 47 exist and
  were audited). Official `@modelcontextprotocol/*` reference servers, popular
  community/vendor servers, and Chinese-ecosystem servers (Amap, AntV, Lark, Volcengine).
- **Method:** read-only. Registry metadata + published tarball source scan. Nothing executed.

## Headline numbers

| Metric | Value |
|---|---|
| Servers audited | 47 |
| Floating direct dependency ranges | 83% of servers |
| Transitive dependencies | median 95 · max 440 |
| Process-exec capability in source | 28% |
| Filesystem + outbound network (exfil shape) | 19% |
| STDIO transport | 85% |
| No provenance attestation | 70% |
| Overall score | median 72 · spread 57–82 |

## Files

- `results.json` — full per-server records (scores, capabilities, findings)
- `results.csv` — flat table for spreadsheets/charts

## Reproduce

```bash
pip install mcp-supply-audit
mcp-supply-audit --corpus corpus.txt --json > results.json
```

(`corpus.txt` — one package name per line — is the exact list audited in this run.)

## Caveats

- Scores are heuristics for triage, not verdicts — see "Sharp edges" in the main README.
- Base rates age fast; re-run before citing. Registry state changes daily.
- The sample is broad but not exhaustive; it is not a ranking of "worst servers" and
  should not be used to shame individual maintainers.
