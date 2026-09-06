# Score calibration

What the numbers mean against the **2026-09-06/07 corpus snapshot** (47 npm MCP
servers). Scoring values have not changed since that run. These bands are
descriptive of *this sample*, not a grading curve we fit to it.

Cite this file next to any score you quote. Heuristic, not verdict.

## Overall (mean of package / registry / SDK)

Corpus: median **72**, spread **57–88**. Quartiles 67 / 72 / 78.

| Band | Overall | Servers in corpus | How to read it |
|---|---:|---:|---|
| Tight | 85–100 | 4 (9%) | Small tree *and* provenance + OIDC. Still a snapshot, not a blessing. |
| Typical | 70–84 | 28 (60%) | The ecosystem default. Median 72 lives here — unverified surface, not malice. |
| Loose | 55–69 | 15 (32%) | Large unread tree and/or no registry verifiability. Triage first. |
| Weak | 0–54 | 0 (0%) | Stacked package deductions (install-time scripts + huge tree + eval). None in this sample. |

A `--fail-under 70` CI gate fails the bottom third of *this* corpus (15/47). That
is a posture choice, not a security proof. `--fail-under 60` fails 3/47.

## What a 72 actually is

Several servers sit on 72: package ~75, registry 60 (signatures, no provenance),
SDK ~80, ~90 transitive deps, floating ranges, no OIDC. That is the *normal*
MCP npm server in this sample — not an outlier.

The floor (57, `@pulumi/mcp-server`) is a 276-dep tree. The ceiling (88,
`@supabase/mcp-server-supabase`) is a 10-dep tree with provenance + OIDC.

## Layer notes (same snapshot)

| Layer | Observed | Meaning |
|---|---|---|
| Package | median 75; 11 servers ≤54 | Tree size and capability shape dominate. One server hit 0 after `MSA-P007` (`desktop-commander` postinstall). |
| Registry | 33 at 60, 1 at 80, 13 at 100 | Almost binary: signatures-only vs provenance+OIDC. 70% have no provenance. |
| SDK | median 80; 39 in 70–84 | STDIO (−10) and a floating SDK range (−10) are the usual deductions. |

## What we are *not* claiming

- Higher is not "safer to run." A filesystem server *should* read files.
- Lower is not "malicious." Large official trees score loose because they *are* large.
- Bands will move if we change the rubric — we will not do that without a
  CHANGELOG entry and a new dated corpus note.
- PyPI `--ecosystem pypi` scores are **not** calibrated here (thin slice, no tree).
