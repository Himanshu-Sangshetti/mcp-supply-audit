# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Obfuscation surface scan (`atob`, `Buffer.from(...,'base64')`, `fromCharCode`,
  `b64decode`, dense `\\xNN` escapes) → finding `MSA-P009` (MED, MCP05).
  **Does not change scores** — corpus numbers stay valid. SARIF rules 21 → 22.
- Known exfil/paste/tunnel hosts (`giftshop.club`, webhook.site, ngrok, …) →
  `MSA-P010`. Install-time remote fetch / hook-file network → `MSA-P011`.
  Both score-neutral. SARIF rules 22 → 24.
- Diff mode: `mcp-supply-audit <pkg> --diff <v1> <v2>` compares two releases of the same
  package — the rug-pull detector. New findings: `MSA-D001` lifecycle script added (HIGH),
  `MSA-D002` publisher changed (HIGH), `MSA-D003` provenance dropped, `MSA-D004` new
  exec/eval capability, `MSA-D005` fs+network exfil shape newly formed, `MSA-D006`
  dependency-tree growth. SARIF rule count: 15 → 21.
- SBOM output: `mcp-supply-audit <pkg> --sbom` emits CycloneDX 1.5 from the resolved
  transitive tree (`pkg:npm/...` PURLs). `resolve_tree` now also returns the named
  package/version list used for the BOM.
- Tree-hash locking: `--lock` writes a pin file (SHA-256 over package version +
  resolved tree + install scripts + publisher). `--check FILE` exits 1 on drift
  — the CI gate for silent floating-range moves.
- Corpus report: `--report results.json` prints markdown headline numbers and a
  score table from a prior `--json` run (regenerates the tables in `corpus/README.md`).
- PyPI thin slice: `--ecosystem pypi` fetches the PyPI JSON API, scans the published
  sdist for capabilities (Python patterns on `*.py` only — JS regexes unchanged),
  and scores direct `requires_dist` only. No transitive resolver and no PEP 740
  provenance yet — documented as a first slice.

### Fixed
- `resolve_tree` never advanced its BFS frontier, so any audit that reached a
  second hop hung forever. This was untested — corpus numbers came from a
  cached run. Tests now cover tree resolution, registry cache, SARIF, CLI, and
  the audit orchestrator.

### Changed
- Semver: hyphen ranges (`1.2.3 - 2.0.0`, partial exclusive-next), empty `||`
  alternatives ignored, prereleases only satisfy a range that mentions one.
  Scoring values unchanged.
- GitHub Action installs the action checkout instead of `pipx run` from PyPI (usable
  before a public publish). CI now has `contents: read`, a wheel-install job, and
  coverage on the test matrix. Dev extra: `pip install -e ".[dev]"`.

## [0.2.0] - 2026-09-07

### Added
- Lifecycle-script detection: `preinstall`/`install`/`postinstall` in the published
  `package.json` now raise `MSA-P007` (HIGH, MCP04) and dock the package score 20 pts —
  install-time code execution means installing is enough, the server never has to start.
  `prepare` raises `MSA-P008` (INFO) since it only runs for git-dependency installs.
  SARIF rule count: 13 → 15.

### Fixed
- `_npmUser.trustedPublisher` (OIDC trusted publishing) is now extracted from registry
  metadata. Previously all publishers read as personal accounts; the 47-server corpus
  under-reported trusted publishing (actual base rate: 28%).

### Changed
- Corpus re-run with both changes (`corpus/`): 1/47 servers ships an install-time script
  (`@wonderwhy-er/desktop-commander`, `postinstall`); overall spread now 57–88.
  Base rates unchanged: 83% floating ranges, median 95 transitive deps, 19% exfil shape,
  70% no provenance. See `corpus/README.md` "Re-run history".

## [0.1.0] - 2026-09-07

Initial scaffold. Read-only npm supply-chain auditor for MCP servers.

- Three-layer audit: package (transitive tree, floating ranges, capability surface),
  registry (provenance, signatures, trusted publisher), SDK (currency, STDIO transport)
- Structured findings with IDs (`MSA-*`), severities, and OWASP MCP Top 10 mapping
- Output: human report, `--json`, `--sarif` (13 rules), `--fail-under` CI gate
- Corpus study: 47 real MCP servers audited 2026-09-06 (`corpus/`)
- GitHub Action (`action.yml`)
- Zero runtime dependencies; Python ≥ 3.9
