# mcp-supply-audit

**Audit an MCP server's supply chain before you trust it.**

Every MCP server you install is three supply chains at once — the **package** (its npm
dependency tree), the **registry** (where you fetched it), and the **SDK** it is built on —
and all three are trusted by default. `mcp-supply-audit` reads all three layers and scores
them. It is **read-only**: nothing is downloaded-and-run, nothing is executed, no API token
or cloud account is required.

```console
$ uvx mcp-supply-audit @modelcontextprotocol/server-filesystem

@modelcontextprotocol/server-filesystem@2025.x
  publisher: modelcontextprotocol (trusted publisher (OIDC)) · latest release: 2025-xx-xx
  package ######---- 64   registry ########## 100   sdk ########-- 82
  overall 76/100
  deps: 100 transitive (depth 2, 4/4 direct floating) · provenance: yes
  MED  [package] 100 transitive dependencies — a large unread attack surface  (MCP04, MSA-P001)
  LOW  [package] 4 floating direct dependency ranges (^/~/*) — reinstalls can silently move to new code  (MCP04, MSA-P002)
```

## Install & run

```bash
uvx mcp-supply-audit <npm-package>        # zero-install via uv
pipx run mcp-supply-audit <npm-package>   # or pipx
pip install mcp-supply-audit              # or into your env
```

```bash
mcp-supply-audit <pkg>                    # human report
mcp-supply-audit <pkg> --json             # machine-readable
mcp-supply-audit <pkg> --sarif > r.sarif  # GitHub code scanning
mcp-supply-audit <pkg> --fail-under 70    # CI gate: exit 1 below 70
mcp-supply-audit --corpus servers.txt     # audit a whole list
mcp-supply-audit <pkg> --diff 1.0.15 1.0.16   # rug-pull detector: what changed between versions
mcp-supply-audit <pkg> --sbom > bom.json      # CycloneDX 1.5 from the resolved tree
mcp-supply-audit <pkg> --lock                 # pin the resolved tree (writes <pkg>.msa.lock.json)
mcp-supply-audit <pkg> --check pkg.msa.lock.json   # CI: exit 1 if the tree drifted
mcp-supply-audit --report results.json            # markdown headline + score tables
mcp-supply-audit mcp --ecosystem pypi             # PyPI thin slice (direct deps + sdist scan)
```

**Diff mode** compares two releases of the same package — the postmark-mcp attack was
invisible to version-based scanning (clean tree in both v1.0.15 and v1.0.16), but a diff
sees what *changed*: new lifecycle scripts (`MSA-D001`, HIGH), publisher changes
(`MSA-D002`, HIGH), dropped provenance, newly-appeared exec/eval capabilities, a
newly-formed filesystem+network exfil shape, and dependency-tree growth.

Zero runtime dependencies. Python ≥ 3.9. Works offline once the registry cache is warm
(`~/.cache/mcp-supply-audit`, override with `MCP_SUPPLY_AUDIT_CACHE`).

## What it checks

| Layer | Signals | Source |
|---|---|---|
| **Package** | full transitive dependency count + depth, floating direct ranges (`^`/`~`/`*`), lifecycle scripts (`preinstall`/`install`/`postinstall` run on the consumer's machine; `prepare` runs for git-dep installs), capability surface of the published tarball (process exec, outbound network, filesystem, env reads, `eval`, STDIO transport) | live registry metadata + tarball source, read never executed |
| **Registry** | `dist.attestations.provenance`, `dist.signatures`, `_npmUser.trustedPublisher` (OIDC vs personal account), publish recency | live registry metadata |
| **SDK** | `@modelcontextprotocol/sdk` range vs the current release, floating SDK ranges, STDIO transport usage | registry + source |

## The rubric

Explicit points, no black box — the same philosophy as OpenSSF Scorecard.

| Package | | Registry | | SDK | |
|---|---|---|---|---|---|
| >200 transitive deps | −30 | provenance + OIDC publisher | 100 | current minor | 100 |
| >100 | −20 | one of the two | 80 | behind a minor | −15 |
| >50 | −10 | registry signature only | 60 | behind a major | −30 |
| floating direct ranges | −10 | none | 40 | floating SDK range | −10 |
| exec capability | −10 | | | STDIO transport | −10 |
| `eval` | −10 | | | no official SDK dep | −20 |
| fs + network (exfil shape) | −15 | | | | |
| env + network | −5 | | | | |

Overall = mean of the three layer scores. Every finding carries an ID (`MSA-*`), a severity,
a layer, and an **OWASP MCP Top 10** mapping (MCP01 secrets, MCP04 supply chain, MCP05
command execution). Note the OWASP MCP Top 10 is currently `v0.1` (Phase 3 beta) — we use it
as shared vocabulary, not as a ratified baseline, and will align when it finalizes.

## The corpus study

We ran this on **47 real MCP servers** you can install today (official reference servers,
popular community servers, and the Chinese ecosystem). Headline base rates:

| | |
|---|---|
| **83%** | ship floating dependency ranges |
| **95** | median transitive dependencies (max 440) |
| **28%** | can execute processes |
| **19%** | have the filesystem + network exfiltration shape |
| **85%** | use STDIO transport |
| **70%** | have no build provenance |
| **72** | median overall score (spread 57–88) |

Full data, method, and reproduction steps: [`corpus/`](corpus/README.md). One command
re-runs the entire study.

## How this fits with other tools

Different tools watch different boundaries — they complement each other:

- **Snyk Agent Scan** (ex-Invariant `mcp-scan`) — tool-description analysis: poisoning,
  rug-pulls, shadowing. Requires a Snyk token for analysis.
- **Cisco mcp-scanner** — multi-engine intent analysis (YARA, LLM-judge) + dependency CVEs.
- **MCTS** — broad local-first SAST + live probing + attack chains.
- **mcp-guard / AgentGate / ToolPin** — policy guardrails and tool-surface drift gates.
- **mcp-supply-audit** — the layer underneath all of that: the npm supply chain itself
  (tree, provenance, SDK currency) plus published base-rate data. Offline, no token.

## Sharp edges (read before citing scores)

- **Heuristic, not proof.** A capability regex flags surface, not behavior. A filesystem
  server *should* read files. Use scores for triage, not verdicts. `MSA-P009`
  (obfuscation) is a shape match — we do not decode or emulate the payload.
  `MSA-P010` / `MSA-P011` flag known sink hosts and install-time remote fetch;
  they do not change scores.
- **Signal, not verdict.** A personal publisher account lowers the registry score; plenty of
  excellent servers are personally published.
- **PyPI is a thin first slice.** `--ecosystem pypi` scans the published sdist and
  scores *direct* `requires_dist` only. There is no transitive resolver and no PEP 740
  provenance parse yet — registry score is a floor (40). Do not cite PyPI scores as
  equivalent to the npm corpus.
- **Mini-semver.** The range resolver handles the forms that appear in real MCP
  package.json files; it is not a complete node-semver.
- **Point-in-time.** A scan is a snapshot. Re-run it on every update — every update is a new
  supply-chain decision.

## Roadmap

Shipped vs next vs blocked: [`docs/ROADMAP.md`](docs/ROADMAP.md). Next up is
obfuscation-aware capability patterns and a real PyPI tree (today's `--ecosystem pypi`
is a thin slice — do not cite it as corpus-equivalent).

## GitHub Action

The action installs this repo checkout (not PyPI), so it works before a public
publish. Pin a tag once one exists.

```yaml
- uses: Himanshu-Sangshetti/mcp-supply-audit@v1
  with:
    package: "@modelcontextprotocol/server-filesystem"
    fail-under: 60
```

## Contributing

Issues and PRs welcome — especially corpus expansion, ecosystem support, and rubric
calibration. The rubric is deliberately explicit so it can be debated in public.

## License & citation

MIT. Built for the talk **"Auditing the MCP Supply Chain"** (AGNTcon China, 2026). If you
use the corpus data, cite the repo and the run date — base rates age.
