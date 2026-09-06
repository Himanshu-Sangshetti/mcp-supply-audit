# Methodology

How mcp-supply-audit reaches its numbers. This document is the audit trail for every
score the tool emits — if you cite a result, cite this alongside it.

## 0. Prime directive: read-only

The tool never executes, installs, or evaluates anything it fetches. Tarballs are read as
byte streams; `package.json` is parsed as data; lifecycle scripts are inspected, never run.
There is no code path from fetched content to the interpreter. (If you find one, that is a
priority-one security report — see SECURITY.md.)

## 1. Data sources

| Source | What we read | Why it's trustworthy enough |
|---|---|---|
| `registry.npmjs.org` metadata JSON | version list, `dependencies`, `dist` (tarball URL, attestations, signatures), `_npmUser`, `maintainers`, `time` | The registry is the source of truth for what `npm install` would fetch. We read the same document your package manager reads. |
| Published tarball (`.tgz`) | source files (`*.js/mjs/cjs/ts`), `package.json` | This is the exact artifact that lands on disk at install time — not a repository snapshot that may differ from what shipped. |
| Registry cache (`~/.cache/mcp-supply-audit`) | prior responses | Plain files; speeds up corpora, enables offline re-audits. Disable with `--no-cache`. |

We deliberately do **not** read: GitHub repo contents (may not match the published
artifact), download counts (popularity ≠ risk), or README claims (marketing, not evidence).

## 2. Transitive tree resolution

- Breadth-first traversal from the audited package's `dependencies`, depth-capped at 8.
- Each range is resolved with a **mini max-satisfying** semver resolver against the
  registry's full version list (prereleases excluded).
- We count **unique package names**, not total installed copies — npm dedupes, and
  "unique names" is the number that matters for "how many strangers' code am I running".

**Known limits:** the resolver handles the range forms seen in real MCP package.json files
(`^`, `~`, exact, comparators, x-ranges, `||`). It is not a complete node-semver; exotic
ranges (hyphen ranges with prereleases, complex unions) may resolve differently than npm.
Peer and optional dependencies are not traversed (npm would install peers; we undercount
slightly). Both limits err toward *understating* tree size.

## 3. Capability surface scan

Regex patterns over tarball source (tests and `.d.ts` excluded, 400-file / 2 MB-per-file
caps). Six signals:

| Signal | Pattern family | Why it matters |
|---|---|---|
| `exec` | `child_process`, `spawn`, `execSync` | process execution — MCP05 |
| `network_out` | `fetch`, `http.request`, `axios`, sockets | outbound data path |
| `filesystem` | `fs.readFile/writeFile/...` | local data access |
| `env_read` | `process.env` | credential access |
| `eval` | `eval(`, `new Function(` | dynamic code — MCP05 |
| `stdio` | `StdioServerTransport` | STDIO transport — launch-command exposure |

**This is a surface scan, not behavior analysis.** A filesystem server *should* contain
`fs.readFile`. The compound signals are where meaning lives: `filesystem + network_out` is
the exfiltration shape (read something, send it somewhere) regardless of intent.

**Known limits:** minified bundles can both hide and inflate signals; regexes don't follow
data flow; obfuscated code (base64 blobs, hex escapes) is not yet decoded (roadmap).
False positives are expected and acceptable — the tool is a triage aid.

## 4. Registry trust signals

| Signal | Field | Meaning |
|---|---|---|
| Provenance | `dist.attestations.provenance` | npm provenance attestation — the build is linked to a public CI run and repo commit (SLSA-style origin evidence) |
| Signatures | `dist.signatures` | registry artifact signatures |
| Trusted publisher | `_npmUser.trustedPublisher` | published via OIDC trusted publishing (e.g. GitHub Actions) rather than a long-lived personal token |
| Recency | `time[version]`, `time.created` | maintenance activity; a package unchanged for years inherits years of ecosystem drift |

Absence of these is **not an accusation** — most legitimate packages lack provenance today.
The score reflects *verifiability*, not *trustworthiness of the author*.

## 5. SDK layer

- We look up `@modelcontextprotocol/sdk` in direct dependencies, resolve its range, and
  compare against the registry's current `latest`.
- Behind a major: −30; behind a minor: −15; floating range: −10; STDIO transport: −10;
  no official SDK dependency detected: −20 (custom/other-language implementation — the
  SDK-currency question doesn't apply, so we mark it INFO and take a flat deduction for
  unaudited surface).

**Known limits:** only the TypeScript SDK is tracked. Python (`mcp` package) servers are
on the roadmap; until then they score the flat "no official SDK dep" deduction, which is
conservative but imprecise.

## 6. Scoring philosophy

- **Explicit over clever.** Every deduction is listed in the README rubric. No ML, no
  weights learned from data. If a score looks wrong, you can trace exactly why — and open
  an issue about a specific rule.
- **Triage, not verdict.** A 72 does not mean "malicious"; it means "this much unverified
  surface." The corpus median is 72 *because the ecosystem's defaults are loose*, not
  because the ecosystem is hostile.
- **Floors and ceilings are deliberate.** Nothing scores below 0; nothing is penalized
  twice for the same root cause within a layer.

## 7. Reproducibility

Every number in `corpus/` can be regenerated with:

```bash
mcp-supply-audit --corpus corpus/corpus.txt --json > results.json
```

Results drift with the live registry (new releases, new provenance). Corpus reports are
therefore always dated; the talk's numbers are the 2026-09-06 snapshot.
