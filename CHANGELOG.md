# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-07

Initial scaffold. Read-only npm supply-chain auditor for MCP servers.

- Three-layer audit: package (transitive tree, floating ranges, capability surface),
  registry (provenance, signatures, trusted publisher), SDK (currency, STDIO transport)
- Structured findings with IDs (`MSA-*`), severities, and OWASP MCP Top 10 mapping
- Output: human report, `--json`, `--sarif` (13 rules), `--fail-under` CI gate
- Corpus study: 47 real MCP servers audited 2026-09-06 (`corpus/`)
- GitHub Action (`action.yml`)
- Zero runtime dependencies; Python ≥ 3.9
