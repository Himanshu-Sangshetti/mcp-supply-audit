"""Per-package audit orchestration. Read-only: nothing is ever executed."""
from .capabilities import scan_tarball
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


def sdk_baseline(registry):
    meta = registry.package_meta(SDK_PKG)
    if "__error__" in meta:
        return None, meta
    return meta.get("dist-tags", {}).get("latest"), meta


def audit_package(pkg, version=None, registry=None, sdk_latest=None, _sdk_meta=None):
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

    # Transitive tree
    meta_cache = {pkg: meta, SDK_PKG: sdk_meta}
    tree_n, depth = resolve_tree(pkg, tag, registry, meta_cache)

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
        "capabilities": caps,
        "files_scanned": files_scanned,
        "sdk_range": sdk_range,
        "sdk_resolved": sdk_resolved,
        "sdk_latest": sdk_latest,
    }
    result["score_package"] = score_package(tree_n, floating, caps)
    result["score_registry"] = score_registry(provenance, signatures > 0, publisher_trusted)
    result["score_sdk"] = score_sdk(sdk_range, sdk_resolved, sdk_latest, caps.get("stdio", 0) > 0)
    result["score_overall"] = round(
        (result["score_package"] + result["score_registry"] + result["score_sdk"]) / 3
    )
    result["findings"] = build_findings(result)
    return result
