"""Minimal npm-style semver range resolution (max-satisfying).

Deliberately small: handles the range forms that actually appear in MCP
server package.json files (^, ~, exact, >=, <=, >, <, x-ranges, ||).
Not a full node-semver implementation — see README "Sharp edges".
"""
import re


def parse_ver(v):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", v)
    return tuple(map(int, m.groups())) if m else None


def satisfies(ver, rng):
    pv = parse_ver(ver)
    if pv is None:
        return False
    rng = (rng or "").strip()
    if rng in ("*", "", "latest", "x"):
        return True
    for alt in rng.split("||"):
        if _satisfies_and(pv, alt.strip()):
            return True
    return False


def _satisfies_and(pv, alt):
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


def max_satisfying(versions, rng):
    cands = []
    for v in versions:
        pv = parse_ver(v)
        if pv is None or "-" in v:  # skip prereleases
            continue
        if satisfies(v, rng):
            cands.append((pv, v))
    return max(cands)[1] if cands else None


def is_floating(rng):
    """A range that can silently move to new code on reinstall."""
    if not isinstance(rng, str):
        return False
    return rng.startswith(("^", "~")) or rng.strip() in ("*", "latest", "x", "")
