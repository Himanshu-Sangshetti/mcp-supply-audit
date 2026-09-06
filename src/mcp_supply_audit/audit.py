"""Per-package audit orchestration. Read-only: nothing is ever executed."""
from typing import Optional

from .capabilities import scan_lifecycle_scripts, scan_tarball
from .pypi import is_unpinned, parse_requires, pypi_meta, sdist_url
from .registry import Registry
from .scoring import (
    build_findings,
    score_package,
    score_registry,
    score_sdk,
)
from .semver import is_floating, max_satisfying
from .tree import resolve_tree

SDK_PKG = "@modelcontextprotocol/sdk"


def sdk_baseline(registry: Registry) -> tuple[Optional[str], dict]:
    meta = registry.package_meta(SDK_PKG)
    if "__error__" in meta:
        return None, meta
    return meta.get("dist-tags", {}).get("latest"), meta


def audit_package(
    pkg: str,
    version: Optional[str] = None,
    registry: Optional[Registry] = None,
    sdk_latest: Optional[str] = None,
    _sdk_meta: Optional[dict] = None,
) -> dict:
    """Audit one npm package. Returns a result dict (or {'error': ...})."""
    registry = registry or Registry()
    meta = registry.package_meta(pkg)
    if "__error__" in meta:
        return {"package": pkg, "error": meta["__error__"]}

    tag = version or meta.get("dist-tags", {}).get("latest")
    vinfo = meta.get("versions", {}).get(tag)
    if not vinfo:
        return {"package": pkg, "error": f"version not found: {tag}"}

    dist = vinfo.get("dist", {})
    att = dist.get("attestations")
    provenance = bool(att.get("provenance")) if isinstance(att, dict) else bool(att)
    signatures = len(dist.get("signatures", []) or [])
    npm_user = (vinfo.get("_npmUser") or {}).get("name", "unknown")
    publisher_trusted = bool((vinfo.get("_npmUser") or {}).get("trustedPublisher"))
    maintainers = [m.get("name") if isinstance(m, dict) else str(m) for m in meta.get("maintainers", [])]
    time_map = meta.get("time", {})

    deps = vinfo.get("dependencies", {}) or {}
    floating = sum(1 for r in deps.values() if is_floating(r))

    # SDK layer
    sdk_range = deps.get(SDK_PKG)
    sdk_meta = _sdk_meta
    if sdk_meta is None:
        sdk_meta = registry.package_meta(SDK_PKG)
    if sdk_latest is None and "__error__" not in sdk_meta:
        sdk_latest = sdk_meta.get("dist-tags", {}).get("latest")
    sdk_resolved = None
    if sdk_range and "__error__" not in sdk_meta:
        sdk_resolved = max_satisfying(list(sdk_meta.get("versions", {}).keys()), sdk_range)

    # Capability surface (tarball read, never executed)
    tarball_url = dist.get("tarball")
    tgz = registry.tarball(tarball_url, pkg, tag) if tarball_url else None
    caps, files_scanned = scan_tarball(tgz)
    install_scripts, git_dep_scripts = scan_lifecycle_scripts(tgz)

    # Transitive tree
    meta_cache = {pkg: meta, SDK_PKG: sdk_meta}
    tree_n, depth, resolved = resolve_tree(pkg, tag, registry, meta_cache)

    result = {
        "package": pkg,
        "version": tag,
        "publisher": npm_user,
        "publisher_trusted": publisher_trusted,
        "maintainers": len(maintainers),
        "created": time_map.get("created"),
        "latest_release": time_map.get(tag),
        "provenance": provenance,
        "signatures": signatures,
        "direct_deps": len(deps),
        "floating_direct": floating,
        "transitive_deps": tree_n,
        "tree_depth": depth,
        "resolved_tree": [{"name": n, "version": v} for n, v in resolved],
        "capabilities": caps,
        "files_scanned": files_scanned,
        "install_scripts": install_scripts,
        "prepare_script": bool(git_dep_scripts),
        "sdk_range": sdk_range,
        "sdk_resolved": sdk_resolved,
        "sdk_latest": sdk_latest,
    }
    result["score_package"] = score_package(tree_n, floating, caps, len(install_scripts))
    result["score_registry"] = score_registry(provenance, signatures > 0, publisher_trusted)
    result["score_sdk"] = score_sdk(sdk_range, sdk_resolved, sdk_latest, caps.get("stdio", 0) > 0)
    result["score_overall"] = round(
        (result["score_package"] + result["score_registry"] + result["score_sdk"]) / 3
    )
    result["findings"] = build_findings(result)
    return result


def audit_pypi_package(
    pkg: str,
    version: Optional[str] = None,
    registry: Optional[Registry] = None,
) -> dict:
    """Thin PyPI slice: metadata + sdist scan. No transitive resolver yet."""
    registry = registry or Registry()
    meta = pypi_meta(registry, pkg, version)
    if "__error__" in meta:
        return {"package": pkg, "error": meta["__error__"], "ecosystem": "pypi"}
    info = meta.get("info") or {}
    tag = version or info.get("version")
    uploaded = next(
        (u.get("upload_time_iso_8601") or u.get("upload_time") for u in (meta.get("urls") or []) if u.get("url")),
        None,
    )
    reqs = parse_requires(info.get("requires_dist"))
    floating = sum(1 for _, spec in reqs if is_unpinned(spec))
    url = sdist_url(meta)
    tgz = registry.fetch_bytes(url, f"pypi_{pkg}-{tag}") if url else None
    caps, files_scanned = scan_tarball(tgz)
    sdk_hits = [n for n, _ in reqs if n.lower() in ("mcp", "fastmcp")]
    if not sdk_hits and pkg.lower() in ("mcp", "fastmcp"):
        sdk_hits = [pkg]  # the audited package *is* the SDK
    result = {
        "package": pkg,
        "ecosystem": "pypi",
        "version": tag,
        "publisher": info.get("author") or info.get("maintainer") or "unknown",
        "publisher_trusted": False,
        "maintainers": 1 if info.get("author") else 0,
        "created": None,
        "latest_release": uploaded,
        "provenance": False,  # PEP 740 not parsed in this slice
        "signatures": 0,
        "direct_deps": len(reqs),
        "floating_direct": floating,
        "transitive_deps": len(reqs),  # direct only — no resolver yet
        "tree_depth": 1,
        "resolved_tree": [{"name": n, "version": s} for n, s in reqs],
        "capabilities": caps,
        "files_scanned": files_scanned,
        "install_scripts": [],
        "prepare_script": False,
        "sdk_range": sdk_hits[0] if sdk_hits else None,
        "sdk_resolved": None,
        "sdk_latest": None,
    }
    result["score_package"] = score_package(len(reqs), floating, caps, 0)
    result["score_registry"] = score_registry(False, False, False)
    result["score_sdk"] = score_sdk(result["sdk_range"], None, None, caps.get("stdio", 0) > 0)
    result["score_overall"] = round(
        (result["score_package"] + result["score_registry"] + result["score_sdk"]) / 3
    )
    result["findings"] = build_findings(result)
    return result
