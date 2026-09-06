"""PyPI JSON API (thin slice). Read-only, uses the shared Registry cache."""
import re
from typing import Optional

from .registry import Registry, ckey

PYPI = "https://pypi.org/pypi"
# "anyio>=4.9; python_version < \"3.14\"" → name=anyio, spec=>=4.9
_REQ = re.compile(r"^([A-Za-z0-9_.-]+)\s*([^;]*?)(?:;.*)?$")


def parse_requires(requires_dist: Optional[list]) -> list[tuple[str, str]]:
    out = []
    for raw in requires_dist or []:
        if not isinstance(raw, str):
            continue
        if "extra ==" in raw or 'extra==' in raw:
            continue  # optional extras
        m = _REQ.match(raw.strip())
        if not m:
            continue
        name, spec = m.group(1), (m.group(2) or "").strip()
        out.append((name, spec or "*"))
    return out


def is_unpinned(spec: str) -> bool:
    return not spec.startswith("==") and spec not in ("",)


def pypi_meta(registry: Registry, pkg: str, version: Optional[str] = None) -> dict:
    path = f"{pkg}/{version}/json" if version else f"{pkg}/json"
    return registry.fetch_json(f"{PYPI}/{path}", f"pypi_{ckey(pkg)}_{version or 'latest'}")


def sdist_url(meta: dict) -> Optional[str]:
    for u in meta.get("urls") or []:
        if u.get("packagetype") == "sdist" and u.get("url"):
            return u["url"]
    return None


def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


def resolve_pypi_tree(
    registry: Registry,
    root_pkg: str,
    root_requires: list[tuple[str, str]],
    max_depth: int = 6,
) -> tuple[int, int, list[tuple[str, str]]]:
    """BFS over PyPI requires_dist.

    Unpinned specs resolve to the registry *latest* (not a full PEP 440 solver).
    Extras skipped. Unique normalized names, depth-capped. Heuristic tree size.
    """
    root_key = _norm(root_pkg)
    seen: set[str] = set()
    resolved: dict[str, str] = {}
    frontier: list[tuple[str, str, int]] = []
    for name, spec in root_requires:
        key = _norm(name)
        if key == root_key or key in seen:
            continue
        seen.add(key)
        frontier.append((name, spec, 1))
    depth_reached = 1 if frontier else 0
    while frontier:
        nxt: list[tuple[str, str, int]] = []
        for name, spec, depth in frontier:
            if depth > max_depth:
                continue
            depth_reached = max(depth_reached, depth)
            pin = spec[2:].strip() if spec.startswith("==") else None
            meta = pypi_meta(registry, name, pin)
            if "__error__" in meta:
                resolved[name] = pin or spec
                continue
            info = meta.get("info") or {}
            tag = pin or info.get("version") or spec
            resolved[name] = tag
            if depth >= max_depth:
                continue
            for child, cspec in parse_requires(info.get("requires_dist")):
                ckey_ = _norm(child)
                if ckey_ == root_key or ckey_ in seen:
                    continue
                seen.add(ckey_)
                nxt.append((child, cspec, depth + 1))
        frontier = nxt
    return len(seen), depth_reached, sorted(resolved.items(), key=lambda x: _norm(x[0]))
