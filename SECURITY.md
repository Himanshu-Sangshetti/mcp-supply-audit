# Security Policy

## Reporting a vulnerability

If you find a security issue in mcp-supply-audit itself, please report it privately:

- Email: himanshu.sangshetti@mem0.ai
- Subject line: `[mcp-supply-audit security] ...`

Please do not open a public issue for vulnerabilities. We aim to acknowledge within
72 hours and to ship a fix or a documented mitigation within 90 days of a confirmed
report.

## Scope notes

- The tool is **read-only by design**: it fetches registry metadata and tarballs and
  scans them without execution. If you find a code path where fetched content could be
  executed (e.g. via tar extraction quirks), that is a priority-one issue — please report it.
- Audit results are heuristics about *other* packages. A false negative in detection is a
  normal bug report; a false negative that is systematically exploitable is a security report.

## Supported versions

Only the latest release receives security fixes.
