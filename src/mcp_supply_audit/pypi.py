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
