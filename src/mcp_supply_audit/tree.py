"""Transitive dependency tree resolution via live registry metadata."""
from .registry import ckey, REGISTRY
from .semver import max_satisfying


def resolve_tree(root_pkg, root_ver, registry, meta_cache=None, max_depth=8):
    """BFS over registry metadata. Returns (unique_dep_count, max_depth_reached)."""
    if meta_cache is None:
        meta_cache = {}
    seen = set()
    frontier = [(root_pkg, root_ver, 0)]
    depth_reached = 0
    while frontier:
        nxt = []
        for pkg, ver, depth in frontier:
            if depth > max_depth:
                continue
            depth_reached = max(depth_reached, depth)
            meta = meta_cache.get(pkg)
            if meta is None:
                meta = registry.fetch_json(f"{REGISTRY}/{pkg.replace('/', '%2f')}", ckey(pkg))
                meta_cache[pkg] = meta
            if "__error__" in meta:
                continue
            vinfo = meta.get("versions", {}).get(ver)
            if not vinfo:
                continue
            for d, rng in (vinfo.get("dependencies", {}) or {}).items():
                if d in seen or d == root_pkg:
                    continue
                seen.add(d)
                dmeta = meta_cache.get(d)
                if dmeta is None:
                    dmeta = registry.fetch_json(f"{REGISTRY}/{d.replace('/', '%2f')}", ckey(d))
                    meta_cache[d] = dmeta
                if "__error__" in dmeta:
                    continue
                dver = max_satisfying(list(dmeta.get("versions", {}).keys()), rng)
                if dver:
                    nxt.append((d, dver, depth + 1))
        frontier = nxt
    return len(seen), depth_reached
