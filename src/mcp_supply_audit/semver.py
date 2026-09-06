"""Minimal npm-style semver range resolution (max-satisfying).

Handles the forms that appear in MCP package.json files: ^ ~ exact
comparators x-ranges || hyphen ranges. Prereleases match a range only
when the range itself mentions a prerelease (node-semver default).
Not a complete node-semver — see README "Sharp edges".
"""
import re
from collections.abc import Iterable
from typing import Optional

Version = tuple[int, int, int]

_HYPHEN = re.compile(r"(\S+)\s+-\s+(\S+)")


def parse_ver(v: str) -> Optional[Version]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", v)
    return tuple(map(int, m.groups())) if m else None


def _is_prerelease(v: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+\-", v))


def _expand_hyphens(rng: str) -> str:
    """`1.2.3 - 2.0.0` → `>=1.2.3 <=2.0.0`. Partial right bound is exclusive next."""

    def _upper(raw: str) -> str:
        core = raw.split("-")[0]
        parts = [p for p in core.split(".") if p.isdigit()]
        if len(parts) == 1:
            return f"<{int(parts[0]) + 1}.0.0"
        if len(parts) == 2:
            return f"<{parts[0]}.{int(parts[1]) + 1}.0"
        return f"<={raw}"

    def _lower(raw: str) -> str:
        core = raw.split("-")[0]
        parts = [p for p in core.split(".") if p.isdigit()]
        while len(parts) < 3:
            parts.append("0")
        return ">=" + ".".join(parts[:3])

    return _HYPHEN.sub(lambda m: f"{_lower(m.group(1))} {_upper(m.group(2))}", rng)


def satisfies(ver: str, rng: str) -> bool:
    pv = parse_ver(ver)
    if pv is None:
        return False
    rng = _expand_hyphens((rng or "").strip())
    if rng in ("*", "", "latest", "x"):
        return True
    # node-semver: a prerelease only satisfies a range that mentions one
    if _is_prerelease(ver) and "-" not in rng:
        return False
    return any(_satisfies_and(pv, alt.strip()) for alt in rng.split("||") if alt.strip())


def _satisfies_and(pv: Version, alt: str) -> bool:
    if not alt:
        return False
    for tok in alt.split():
        if tok.startswith("^"):
            b = parse_ver(tok[1:])
            if b is None:
                return False
            ok = pv >= b and pv[0] == b[0] and (b[0] > 0 or pv[1] == b[1])
            if not ok and not (b[0] == 0 and b[1] == 0 and pv[1] == 0 and pv[2] >= b[2]):
                return False
        elif tok.startswith("~"):
            b = parse_ver(tok[1:])
            if b is None or not (pv >= b and pv[0] == b[0] and pv[1] == b[1]):
                return False
        elif tok.startswith(">="):
            b = parse_ver(tok[2:])
            if b is None or pv < b:
                return False
        elif tok.startswith("<="):
            b = parse_ver(tok[2:])
            if b is None or pv > b:
                return False
        elif tok.startswith(">"):
            b = parse_ver(tok[1:])
            if b is None or pv <= b:
                return False
        elif tok.startswith("<"):
            b = parse_ver(tok[1:])
            if b is None or pv >= b:
                return False
        elif tok.endswith((".x", ".*")) or re.match(r"^\d+\.\d+$", tok):
            parts = [p for p in re.split(r"[.*x]", tok)[0].split(".") if p.isdigit()]
            if len(parts) == 1 and pv[0] != int(parts[0]):
                return False
            if len(parts) == 2 and (pv[0], pv[1]) != (int(parts[0]), int(parts[1])):
                return False
        else:
            b = parse_ver(tok)
            if b is None:
                continue
            if pv != b:
                return False
    return True


def max_satisfying(versions: Iterable[str], rng: str) -> Optional[str]:
    allow_pre = "-" in (rng or "")
    cands = []
    for v in versions:
        pv = parse_ver(v)
        if pv is None:
            continue
        if "-" in v and not allow_pre:
            continue
        if satisfies(v, rng):
            # same X.Y.Z: release sorts above prerelease
            cands.append((pv, 0 if "-" in v else 1, v))
    return max(cands)[2] if cands else None


def is_floating(rng: object) -> bool:
    """A range that can silently move to new code on reinstall."""
    if not isinstance(rng, str):
        return False
    return rng.startswith(("^", "~")) or rng.strip() in ("*", "latest", "x", "")
