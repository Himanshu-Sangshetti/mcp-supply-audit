# Roadmap

Status of work that is shipped, next, or blocked on a public launch.

## Shipped (v0.2.x)

- Three-layer scoring (package / registry / SDK) with `MSA-*` findings mapped to OWASP MCP Top 10
- `--json`, `--sarif`, `--fail-under` for CI
- `--diff` rug-pull detector, `--sbom` CycloneDX 1.5, `--lock` / `--check` tree-hash pin
- `--report` corpus markdown from a prior JSON run
- `--ecosystem pypi` thin slice (direct `requires_dist` + sdist scan; no transitive tree, no PEP 740)
- 47-server npm corpus with published base rates

## Next

- Capability patterns v2: obfuscation signals (base64+eval, hex escapes), obvious exfil endpoints
- Semver edge cases (hyphen ranges, `||` + prerelease) to match node-semver more closely
- Score calibration note: what each band means against the corpus
- `--explain <finding-id>` — full rationale + remediation
- PyPI transitive resolver + PEP 740 provenance (do not cite today's PyPI scores as corpus-equivalent)
- Shell completions

## Blocked on public launch

Repo URLs, the GitHub Action marketplace listing, and `pip install mcp-supply-audit`
from PyPI all assume a GitHub + PyPI publish. That is a deliberate hold — local
commits only until the owner decides to launch.
