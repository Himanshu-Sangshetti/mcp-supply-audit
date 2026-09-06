"""Tree-hash lockfile: pin a resolved tree, fail CI when it drifts.

The pin is a SHA-256 over the sorted (name, version) list plus the
package version and install-time scripts. A floating range that silently
resolves to new code changes the hash — that's the whole point.
"""
import hashlib
import json
from typing import Optional

from . import __version__

LOCK_VERSION = 1


def tree_hash(result: dict) -> str:
    """Stable hash of the resolved supply-chain surface."""
    payload = {
        "package": result.get("package"),
        "version": result.get("version"),
        "resolved_tree": sorted(
            (d.get("name"), d.get("version")) for d in result.get("resolved_tree") or []
        ),
        "install_scripts": sorted(result.get("install_scripts") or []),
        "publisher": result.get("publisher"),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def make_lock(result: dict) -> dict:
    return {
        "lock_version": LOCK_VERSION,
        "tool": "mcp-supply-audit",
        "tool_version": __version__,
        "package": result["package"],
        "version": result.get("version"),
        "tree_hash": tree_hash(result),
        "transitive_deps": result.get("transitive_deps"),
        "resolved_tree": result.get("resolved_tree") or [],
        "install_scripts": result.get("install_scripts") or [],
        "publisher": result.get("publisher"),
    }


def check_lock(lock: dict, result: dict) -> list[str]:
    """Return a list of drift reasons (empty = match)."""
    reasons = []
    if lock.get("package") != result.get("package"):
        reasons.append(f"package {lock.get('package')} → {result.get('package')}")
    if lock.get("version") != result.get("version"):
        reasons.append(f"version {lock.get('version')} → {result.get('version')}")
    if lock.get("tree_hash") != tree_hash(result):
        reasons.append(f"tree_hash {lock.get('tree_hash')} → {tree_hash(result)}")
    locked = {(d.get("name"), d.get("version")) for d in lock.get("resolved_tree") or []}
    now = {(d.get("name"), d.get("version")) for d in result.get("resolved_tree") or []}
    added = sorted(now - locked)
    removed = sorted(locked - now)
    if added:
        reasons.append("added: " + ", ".join(f"{n}@{v}" for n, v in added[:8]))
    if removed:
        reasons.append("removed: " + ", ".join(f"{n}@{v}" for n, v in removed[:8]))
    return reasons


def default_lock_path(pkg: str) -> str:
    safe = pkg.replace("/", "__").replace("@", "")
    return f"{safe}.msa.lock.json"


def write_lock(path: str, result: dict) -> dict:
    lock = make_lock(result)
    with open(path, "w") as f:
        json.dump(lock, f, indent=2)
        f.write("\n")
    return lock


def read_lock(path: str) -> Optional[dict]:
    with open(path) as f:
        return json.load(f)
