"""Version-diff mode: compare two releases of the same package.

The rug-pull detector. The postmark-mcp attack was v1.0.15 → v1.0.16:
same tree, same publisher, one extra line. Version-based scanners see a
clean tree in both; a diff sees what *changed*.
"""

from .scoring import make_finding


def diff_audits(a: dict, b: dict) -> dict:
    """Diff two audit results (a = older, b = newer). Returns a delta dict
    with structured findings (MSA-D*)."""
    caps_a, caps_b = a.get("capabilities", {}), b.get("capabilities", {})
    keys = sorted(set(caps_a) | set(caps_b))
    cap_delta = {k: caps_b.get(k, 0) - caps_a.get(k, 0) for k in keys}
    new_caps = [k for k in keys if caps_b.get(k, 0) > 0 and not caps_a.get(k, 0)]

    scripts_a = set(a.get("install_scripts") or [])
    scripts_b = set(b.get("install_scripts") or [])
    scripts_added = sorted(scripts_b - scripts_a)

    deps_a = a.get("transitive_deps", 0)
    deps_b = b.get("transitive_deps", 0)

    findings = []
    if scripts_added:
        findings.append(make_finding("MSA-D001", v=b.get("version"), scripts=", ".join(scripts_added)))
    if a.get("publisher") != b.get("publisher"):
        findings.append(make_finding("MSA-D002", a=a.get("publisher"), b=b.get("publisher")))
    if a.get("provenance") and not b.get("provenance"):
        findings.append(make_finding("MSA-D003", v=b.get("version")))
    risky_new = [c for c in new_caps if c in ("exec", "eval")]
    if risky_new:
        findings.append(make_finding("MSA-D004", v=b.get("version"), caps=", ".join(risky_new)))
    exfil_a = caps_a.get("filesystem") and caps_a.get("network_out")
    exfil_b = caps_b.get("filesystem") and caps_b.get("network_out")
    if exfil_b and not exfil_a:
        findings.append(make_finding("MSA-D005", v=b.get("version")))
    if deps_a and deps_b > deps_a * 1.5 and deps_b - deps_a >= 20:
        findings.append(make_finding("MSA-D006", a=deps_a, b=deps_b))

    return {
        "from": a.get("version"),
        "to": b.get("version"),
        "score_delta": {
            "package": b.get("score_package", 0) - a.get("score_package", 0),
            "registry": b.get("score_registry", 0) - a.get("score_registry", 0),
            "sdk": b.get("score_sdk", 0) - a.get("score_sdk", 0),
            "overall": b.get("score_overall", 0) - a.get("score_overall", 0),
        },
        "capability_delta": {k: v for k, v in cap_delta.items() if v},
        "new_capabilities": new_caps,
        "install_scripts_added": scripts_added,
        "transitive_deps_delta": deps_b - deps_a,
        "publisher_changed": a.get("publisher") != b.get("publisher"),
        "provenance_dropped": bool(a.get("provenance") and not b.get("provenance")),
        "findings": findings,
    }
