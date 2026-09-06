"""mcp-supply-audit CLI. See --help for the full command list."""
import argparse
import concurrent.futures as cf
import json
import sys
from typing import Optional

from . import __version__
from .audit import audit_package, audit_pypi_package, sdk_baseline
from .completions import SHELLS
from .completions import render as render_completions
from .diff import diff_audits
from .explain import explain, explain_all, known_ids
from .lock import check_lock, default_lock_path, read_lock, write_lock
from .registry import Registry
from .report import to_markdown
from .sarif import to_sarif
from .sbom import to_cyclonedx


def _bar(score: int, width: int = 10) -> str:
    filled = max(0, min(width, round(score / 100 * width)))
    return "#" * filled + "-" * (width - filled)


def _print_human(r: dict) -> None:
    if "error" in r:
        print(f"\n{r['package']}: ERROR {r['error']}")
        return
    if r.get("ecosystem") == "pypi":
        trusted = "PyPI; OIDC/PEP 740 not parsed"
    else:
        trusted = "trusted publisher (OIDC)" if r.get("publisher_trusted") else "personal account"
    print(f"\n{r['package']}@{r['version']}")
    print(f"  publisher: {r['publisher']} ({trusted}) · latest release: {(r.get('latest_release') or '?')[:10]}")
    print(
        f"  package {_bar(r['score_package'])} {r['score_package']:3d}   "
        f"registry {_bar(r['score_registry'])} {r['score_registry']:3d}   "
        f"sdk {_bar(r['score_sdk'])} {r['score_sdk']:3d}"
    )
    print(f"  overall {r['score_overall']}/100")
    if r.get("ecosystem") == "pypi":
        print(
            f"  deps: {r['transitive_deps']} unique (depth {r['tree_depth']}, "
            f"{r['floating_direct']}/{r['direct_deps']} direct floating; "
            f"latest-for-unpinned, no PEP 440) · "
            f"provenance: not parsed (PEP 740)"
        )
    else:
        print(
            f"  deps: {r['transitive_deps']} transitive (depth {r['tree_depth']}, "
            f"{r['floating_direct']}/{r['direct_deps']} direct floating) · "
            f"provenance: {'yes' if r['provenance'] else 'NO'}"
        )
    caps = {k: v for k, v in r["capabilities"].items() if v}
    if caps:
        print("  capabilities: " + ", ".join(f"{k} x{v}" for k, v in caps.items()))
    if r.get("sdk_range"):
        print(f"  sdk: {r['sdk_range']} → resolved {r.get('sdk_resolved')} (latest {r.get('sdk_latest')})")
    for f in r.get("findings", []):
        print(f"  {f['severity']:4s} [{f['layer']:7s}] {f['message']}  ({f['owasp']}, {f['id']})")


_EPILOG = """examples:
  mcp-supply-audit @modelcontextprotocol/server-filesystem
  mcp-supply-audit <pkg> --json --fail-under 70
  mcp-supply-audit <pkg> --diff 1.0.15 1.0.16
  mcp-supply-audit --explain MSA-P007
  eval "$(mcp-supply-audit --completions bash)"

Nothing fetched is executed. Scores are heuristics — see docs/CALIBRATION.md.
"""


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcp-supply-audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Read-only supply-chain auditor for MCP servers.\n"
            "Layers: package tree, registry provenance, SDK currency.\n"
            "Nothing is downloaded-and-run. No API token required."
        ),
        epilog=_EPILOG,
    )
    ap.add_argument("packages", nargs="*", help="npm package names to audit")
    ap.add_argument("--corpus", help="file with one package name per line")
    ap.add_argument("--version", help="package version to audit (default: latest)")
    ap.add_argument("--diff", nargs=2, metavar=("V1", "V2"),
                    help="diff two versions of one package (rug-pull detector)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0")
    ap.add_argument("--sbom", action="store_true", help="emit CycloneDX 1.5 SBOM (single package)")
    ap.add_argument("--lock", nargs="?", const="", metavar="FILE",
                    help="write a tree-hash pin file (default: <pkg>.msa.lock.json)")
    ap.add_argument("--check", metavar="FILE",
                    help="exit 1 if the live tree drifted from the pin file")
    ap.add_argument("--report", metavar="FILE",
                    help="render a markdown corpus report from a results.json")
    ap.add_argument("--explain", nargs="?", const="*", metavar="ID",
                    help="print rationale + remediation for a finding id (e.g. MSA-P007); "
                         "omit ID to list all")
    ap.add_argument("--fail-under", type=int, default=None,
                    help="exit 1 if any audited package scores below N")
    ap.add_argument("--no-cache", action="store_true", help="disable the on-disk registry cache")
    ap.add_argument("--workers", type=int, default=6, help="parallel audits for corpora")
    ap.add_argument("--ecosystem", choices=("npm", "pypi"), default="npm",
                    help="package ecosystem (default: npm). pypi: sdist scan + thin "
                         "requires_dist tree (latest for unpinned; no PEP 440 / PEP 740)")
    ap.add_argument("--completions", metavar="SHELL",
                    help=f"print a completion script ({', '.join(SHELLS)})")
    ap.add_argument("-V", "--tool-version", action="version", version=f"mcp-supply-audit {__version__}")
    args = ap.parse_args(argv)

    packages = list(args.packages)
    if args.corpus:
        with open(args.corpus) as f:
            packages += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if args.report:
        with open(args.report) as f:
            print(to_markdown(json.load(f)), end="")
        return 0
    if args.completions:
        try:
            print(render_completions(args.completions), end="")
        except KeyError:
            ap.error(f"unknown shell {args.completions!r} — known: {', '.join(SHELLS)}")
        return 0
    if args.explain is not None:
        if args.explain == "*":
            print(explain_all(), end="")
            return 0
        try:
            print(explain(args.explain), end="")
        except KeyError:
            ap.error(f"unknown finding id {args.explain!r} — known: {', '.join(known_ids())}")
        return 0
    if not packages:
        ap.error("give at least one package name, --corpus FILE, --report FILE, or --explain [ID]")

    registry = Registry(use_cache=not args.no_cache)
    if args.ecosystem == "pypi":
        results = []
        for p in packages:
            results.append(audit_pypi_package(p, version=args.version, registry=registry))
        if args.json:
            print(json.dumps({"tool": "mcp-supply-audit", "tool_version": __version__,
                              "ecosystem": "pypi", "results": results}, indent=2))
        else:
            for r in results:
                _print_human(r)
        if args.fail_under is not None:
            for r in results:
                if "error" not in r and r["score_overall"] < args.fail_under:
                    return 1
        return 0

    sdk_latest, sdk_meta = sdk_baseline(registry)

    if args.diff:
        if len(packages) != 1:
            ap.error("--diff takes exactly one package")
        v1, v2 = args.diff
        ra = audit_package(packages[0], version=v1, registry=registry,
                           sdk_latest=sdk_latest, _sdk_meta=sdk_meta)
        rb = audit_package(packages[0], version=v2, registry=registry,
                           sdk_latest=sdk_latest, _sdk_meta=sdk_meta)
        for r in (ra, rb):
            if "error" in r:
                print(f"\n{r['package']}: ERROR {r['error']}")
                return 1
        d = diff_audits(ra, rb)
        if args.json:
            print(json.dumps({"package": packages[0], "diff": d,
                              "v1": ra, "v2": rb}, indent=2))
            return 0
        sd = d["score_delta"]
        print(f"\n{packages[0]} {d['from']} → {d['to']}")
        print(
            f"  scores: package {ra['score_package']} → {rb['score_package']} ({sd['package']:+d}) · "
            f"registry {ra['score_registry']} → {rb['score_registry']} ({sd['registry']:+d}) · "
            f"sdk {ra['score_sdk']} → {rb['score_sdk']} ({sd['sdk']:+d})"
        )
        print(f"  overall {ra['score_overall']} → {rb['score_overall']} ({sd['overall']:+d})")
        if d["capability_delta"]:
            print("  capabilities: " + ", ".join(
                f"{k} {v:+d}" for k, v in d["capability_delta"].items()))
        if d["transitive_deps_delta"]:
            print(f"  deps: {ra['transitive_deps']} → {rb['transitive_deps']} transitive "
                  f"({d['transitive_deps_delta']:+d})")
        if d["findings"]:
            for f in d["findings"]:
                print(f"  {f['severity']:4s} [{f['layer']:7s}] {f['message']}  ({f['owasp']}, {f['id']})")
        else:
            print("  no new trust-relevant changes detected")
        if args.fail_under is not None and rb["score_overall"] < args.fail_under:
            return 1
        return 0

    results = []
    if len(packages) == 1:
        results.append(audit_package(packages[0], version=args.version,
                                     registry=registry, sdk_latest=sdk_latest, _sdk_meta=sdk_meta))
    else:
        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(audit_package, p, None, registry, sdk_latest, sdk_meta): p
                    for p in packages}
            for i, fut in enumerate(cf.as_completed(futs), 1):
                p = futs[fut]
                try:
                    r = fut.result()
                except Exception as e:
                    r = {"package": p, "error": str(e)}
                results.append(r)
                if not (args.json or args.sarif):
                    tag = "ERR " if "error" in r else f"{r['score_overall']:3d}"
                    print(f"[{i:2d}/{len(packages)}] {tag} {p}", file=sys.stderr)
        results.sort(key=lambda r: r.get("score_overall", -1))

    if args.lock is not None or args.check:
        if len(results) != 1 or "error" in results[0]:
            ap.error("--lock / --check take exactly one auditable package")
        r = results[0]
        if args.lock is not None:
            path = args.lock or default_lock_path(r["package"])
            lock = write_lock(path, r)
            print(f"wrote {path}  tree_hash={lock['tree_hash'][:12]}…  "
                  f"{lock['transitive_deps']} deps", file=sys.stderr)
        if args.check:
            pin = read_lock(args.check)
            drift = check_lock(pin, r)
            if drift:
                print(f"DRIFT {r['package']}@{r.get('version')}", file=sys.stderr)
                for reason in drift:
                    print(f"  {reason}", file=sys.stderr)
                return 1
            print(f"OK {r['package']}@{r.get('version')} matches {args.check}", file=sys.stderr)
            return 0

    if args.sbom:
        if len(results) != 1 or "error" in results[0]:
            ap.error("--sbom takes exactly one auditable package")
        print(json.dumps(to_cyclonedx(results[0]), indent=2))
    elif args.sarif:
        print(json.dumps(to_sarif(results), indent=2))
    elif args.json:
        print(json.dumps({"tool": "mcp-supply-audit", "tool_version": __version__,
                          "sdk_latest": sdk_latest, "results": results}, indent=2))
    else:
        for r in results:
            _print_human(r)

    if args.fail_under is not None:
        for r in results:
            if "error" not in r and r["score_overall"] < args.fail_under:
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
