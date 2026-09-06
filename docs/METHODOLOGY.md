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
| `pypi.org/pypi/<pkg>/json` | `info.requires_dist`, sdist URL, author | Same JSON API `pip` uses. Thin slice: direct deps only, no PEP 740. |
| Published tarball (npm `.tgz` or PyPI sdist) | source files (`*.js/mjs/cjs/ts/py`), `package.json` | This is the exact artifact that lands on disk at install time — not a repository snapshot that may differ from what shipped. |
| Registry cache (`~/.cache/mcp-supply-audit`) | prior responses | Plain files; speeds up corpora, enables offline re-audits. Disable with `--no-cache`. |

We deliberately do **not** read: GitHub repo contents (may not match the published
artifact), download counts (popularity ≠ risk), or README claims (marketing, not evidence).

## 2. Transitive tree resolution

- Breadth-first traversal from the audited package's `dependencies`, depth-capped at 8.
- Each range is resolved with a **mini max-satisfying** semver resolver against the
  registry's full version list (prereleases excluded).
- We count **unique package names**, not total installed copies — npm dedupes, and
  "unique names" is the number that matters for "how many strangers' code am I running".

**Known limits:** the resolver handles `^` `~` exact comparators x-ranges `||` and
hyphen ranges (`1.2.3 - 2.0.0`; partial upper bounds exclusive-next, like node-semver).
Prereleases are skipped unless the range itself mentions a prerelease. It is still
not a complete node-semver (build metadata, hyphen+prerelease unions). Peer and
optional dependencies are not traversed (npm would install peers; we undercount
slightly). Both limits err toward *understating* tree size.

**PyPI (`--ecosystem pypi`)** does not resolve a transitive tree. It scores the
package's own `requires_dist` (extras skipped) and scans the published sdist.
`transitive_deps` in the JSON is therefore *direct count*, not a tree. Registry
score is a floor of 40 — PEP 740 attestations are not parsed, and npm-shaped
findings `MSA-R001`–`R003` are suppressed so we do not pretend PyPI is npm.

## 3. Capability surface scan

Regex patterns over tarball source (tests and `.d.ts` excluded, 400-file / 2 MB-per-file
caps). Six signals. Python extras (`subprocess`, `httpx`, `os.environ`, …) apply
**only** to `*.py` so the npm corpus scores do not drift.

| Signal | Pattern family | Why it matters |
|---|---|---|
| `exec` | `child_process`, `spawn`, `execSync`; `subprocess`, `Popen` | process execution — MCP05 |
| `network_out` | `fetch`, `http.request`, `axios`; `httpx`, `urllib.request` | outbound data path |
| `filesystem` | `fs.readFile/writeFile/...`; `open(`, `pathlib` | local data access |
| `env_read` | `process.env`; `os.environ`, `os.getenv` | credential access |
| `eval` | `eval(`, `new Function(` | dynamic code — MCP05 |
| `stdio` | `StdioServerTransport`; `stdio_server` | STDIO transport — launch-command exposure |
| `obfuscation` | `atob` / `Buffer.from(...,'base64')` / `fromCharCode` / `b64decode`; ≥20 `\\xNN` escapes in one file | decode-then-run shape — MCP05. **Finding only (`MSA-P009`). Does not change scores.** |
| `exfil_host` | `giftshop.club`, webhook.site, requestbin, ngrok, pastebin, discord webhooks, telegram bots, interact.sh, oast, burpcollaborator | known sink / OOB host — MCP04. **`MSA-P010`. Score-neutral.** |

Install-time scripts whose *command* curls/wgets/pipes-to-shell, or whose
`postinstall.js` / `preinstall.js` / `install.js` contains outbound network, raise
`MSA-P011` (also score-neutral). A local `node postinstall.js` that only writes
files is P007 only.

**This is a surface scan, not behavior analysis.** A filesystem server *should* contain
`fs.readFile`. The compound signals are where meaning lives: `filesystem + network_out` is
the exfiltration shape (read something, send it somewhere) regardless of intent.

**Known limits:** minified bundles can both hide and inflate signals; regexes don't follow
data flow; we flag obfuscation *shapes* (`MSA-P009`) but do not decode or emulate them.
False positives are expected and acceptable — the tool is a triage aid.

### Lifecycle scripts (install-time execution)

The published `package.json` is also read from the tarball for npm lifecycle scripts:

| Script | When it runs | Signal |
|---|---|---|
| `preinstall` / `install` / `postinstall` | on the **consumer's** `npm install <pkg>` from the registry | `MSA-P007` HIGH, −20 package pts |
| `prepare` | on local dev install and **git-dependency** installs (not registry installs) | `MSA-P008` INFO |

This is the highest-signal check in the package layer: a malicious `postinstall` runs
arbitrary code before the MCP server is ever started — the package doesn't need to be
*run* to be dangerous, only *installed*.

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
