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
| Published via OIDC trusted publishing | 28% |
| Install-time lifecycle scripts (`postinstall`) | 1 server (`@wonderwhy-er/desktop-commander`) |
| Overall score | median 72 · spread 57–88 |

## Re-run history

**2026-09-07 — re-run with lifecycle detection (tool v0.1.0+).** Two deliberate changes vs
the 2026-09-06 snapshot; same cached registry metadata, so deltas are tool changes, not
registry drift:

1. **Rubric addition:** `MSA-P007` — install-time lifecycle scripts dock the package score
   20 pts. Affected 1/47 servers (`@wonderwhy-er/desktop-commander`: package 20 → 0).
2. **Signal fix:** `_npmUser.trustedPublisher` (OIDC) was not extracted in the original run;
   it now is. 11 servers gained registry points they had earned (registry 80 → 100),
   lifting the overall spread's top end from 82 to 88. The original snapshot
   *under-reported* trusted publishing.

Base-rate metrics (floating ranges, dep counts, capability shapes, provenance) are
unchanged — they don't depend on either change.

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
