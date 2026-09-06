# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Diff mode: `mcp-supply-audit <pkg> --diff <v1> <v2>` compares two releases of the same
  package — the rug-pull detector. New findings: `MSA-D001` lifecycle script added (HIGH),
  `MSA-D002` publisher changed (HIGH), `MSA-D003` provenance dropped, `MSA-D004` new
  exec/eval capability, `MSA-D005` fs+network exfil shape newly formed, `MSA-D006`
  dependency-tree growth. SARIF rule count: 15 → 21.

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
