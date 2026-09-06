# Roadmap

Status of work that is shipped, next, or blocked on a public launch.

## Shipped (v0.2.x)

- Three-layer scoring (package / registry / SDK) with `MSA-*` findings mapped to OWASP MCP Top 10
- `--json`, `--sarif`, `--fail-under` for CI
- `--diff` rug-pull detector, `--sbom` CycloneDX 1.5, `--lock` / `--check` tree-hash pin
- `--report` corpus markdown from a prior JSON run
- `--ecosystem pypi` thin slice (direct `requires_dist` + sdist scan; no transitive tree, no PEP 740)
- 47-server npm corpus with published base rates
- Score-neutral pattern findings: `MSA-P009` obfuscation, `MSA-P010` known exfil hosts,
  `MSA-P011` install-time remote fetch
- Hyphen ranges + prerelease-aware max-satisfying (still not full node-semver)
- Score calibration note (`docs/CALIBRATION.md`) against the 47-server snapshot
- `--explain [ID]` rationale + remediation for every `MSA-*` finding
- `--completions bash|zsh|fish` and man-style `--help` examples

## Next

- PyPI transitive resolver + PEP 740 provenance (do not cite today's PyPI scores as corpus-equivalent)

## Good first issues

Each of these is one PR. Read CONTRIBUTING first (read-only, stdlib only, no
score changes without a CHANGELOG). Open an issue with the `corpus` / `feature`
template if you want to claim one.

| ID | Task | Why it's small | Watch out |
|---|---|---|---|
| GFI-1 | Add 3–5 widely-installed MCP servers to `corpus/corpus.txt` with a one-line why | Text file + a `--report` note | Inclusion is not an accusation. No drive-by "this one is malware" |
| GFI-2 | `--explain` translations or tighter wording for one finding | `src/mcp_supply_audit/explain.py` only | Keep "heuristic, not proof". Test `test_every_finding_has_an_explanation` must stay green |
| GFI-3 | Fish/zsh completion polish (file paths after `--corpus` / `--report` / `--check`) | `completions.py` + `tests/test_completions.py` | Do not add runtime deps (no argcomplete) |
| GFI-4 | CLI coverage: `--fail-under` / `--json` with a mocked `audit_package` | `tests/test_cli.py` — no network | Do not change scoring |
| GFI-5 | Document one `--fail-under` recommendation vs `docs/CALIBRATION.md` bands in the GitHub Action README snippet | Docs only | 70 fails the bottom third of the snapshot; say so |
| GFI-6 | False-positive note for `MSA-P009` on a real minified bundle (which file, which pattern) | Issue + optional skip-path tweak | Pattern changes need CHANGELOG + state note — corpus is cited in a talk |
| GFI-7 | `docs/COMPARISON.md` date-check: one row stale? update the date line | One file | Honesty over marketing |

Larger (not first issues): PyPI transitive tree, PEP 740, hyphen+prerelease unions.

## Blocked on public launch

Private GitHub repo exists (`Himanshu-Sangshetti/mcp-supply-audit`). Still held:
making it public, marketplace Action listing, and `pip install mcp-supply-audit`
from PyPI.
