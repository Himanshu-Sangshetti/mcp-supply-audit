"""Three-layer scoring rubric + findings with OWASP MCP Top 10 mapping.

The rubric is explicit on purpose — same model as OpenSSF Scorecard:
visible signals, visible points, no black box. Scores are heuristics for
triage, not verdicts (see README "Sharp edges").

Layers: PACKAGE (dependency tree + capability surface), REGISTRY
(provenance / signatures / publisher), SDK (currency + transport).
"""
from typing import Optional

from .semver import parse_ver

# Finding catalogue: id -> (severity, layer, OWASP MCP category, template)
FINDINGS = {
    "MSA-P001": ("MED", "package", "MCP04", "{n} transitive dependencies — a large unread attack surface"),
    "MSA-P002": ("LOW", "package", "MCP04", "{n} floating direct dependency ranges (^/~/*) — reinstalls can silently move to new code"),
    "MSA-P003": ("MED", "package", "MCP05", "process execution capability in published source"),
    "MSA-P004": ("MED", "package", "MCP04", "combines filesystem read + outbound network — the postmark-mcp exfiltration shape"),
    "MSA-P005": ("LOW", "package", "MCP01", "reads environment variables and has outbound network — env exfiltration shape"),
    "MSA-P006": ("HIGH", "package", "MCP05", "eval / new Function in published source"),
    "MSA-P007": ("HIGH", "package", "MCP04", "lifecycle scripts run arbitrary code on install: {scripts} — installing is enough, the server never has to start"),
    "MSA-P008": ("INFO", "package", "MCP04", "prepare script — executes if installed as a git dependency"),
    "MSA-P009": ("MED", "package", "MCP05", "obfuscation signals in published source (base64 decode, fromCharCode, or dense hex escapes) — heuristic, not proof"),
    "MSA-P010": ("MED", "package", "MCP04", "published source references a known exfil/paste/tunnel host ({hosts}) — heuristic, not proof"),
    "MSA-P011": ("MED", "package", "MCP04", "install-time script fetches remote or phones home: {scripts} — installing is enough"),
    "MSA-R001": ("MED", "registry", "MCP04", "no provenance attestation — build origin unverifiable"),
    "MSA-R002": ("LOW", "registry", "MCP04", "no registry signatures on the published artifact"),
    "MSA-R003": ("LOW", "registry", "MCP04", "published from a personal account without trusted publishing (OIDC)"),
    "MSA-S001": ("MED", "sdk", "MCP05", "STDIO transport — untrusted input must never reach the launch command"),
    "MSA-S002": ("MED", "sdk", "MCP04", "MCP SDK is behind the current {baseline} baseline (resolved {resolved})"),
    "MSA-S003": ("LOW", "sdk", "MCP04", "floating SDK range — SDK upgrades arrive unreviewed"),
    "MSA-S004": ("INFO", "sdk", "MCP04", "no @modelcontextprotocol/sdk dependency detected (custom or non-TS implementation)"),
    "MSA-D001": ("HIGH", "diff", "MCP04", "lifecycle script added in {v}: {scripts} — install-time execution appeared between versions"),
    "MSA-D002": ("HIGH", "diff", "MCP04", "publisher changed between versions ({a} → {b}) — account-takeover / rug-pull signal"),
    "MSA-D003": ("MED", "diff", "MCP04", "provenance attestation dropped in {v} — build origin no longer verifiable"),
    "MSA-D004": ("MED", "diff", "MCP05", "new capability appeared in {v}: {caps}"),
    "MSA-D005": ("MED", "diff", "MCP04", "filesystem + network newly combined in {v} — the exfil shape appeared between versions"),
    "MSA-D006": ("LOW", "diff", "MCP04", "dependency tree grew {a} → {b} packages — new unread code"),
}

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MED": 2, "HIGH": 3}


def make_finding(fid: str, **fmt: object) -> dict:
    sev, layer, owasp, template = FINDINGS[fid]
    return {
        "id": fid,
        "severity": sev,
        "layer": layer,
        "owasp": owasp,
        "message": template.format(**fmt) if fmt else template,
    }


def score_package(
    tree_n: int, floating_direct: int, caps: dict[str, int], install_scripts: int = 0
) -> int:
    s = 100
    if tree_n > 200:
        s -= 30
    elif tree_n > 100:
        s -= 20
    elif tree_n > 50:
        s -= 10
    if floating_direct > 0:
        s -= 10
    if install_scripts:
        s -= 20  # arbitrary code runs at install time (the E10 attack)
    if caps.get("exec"):
        s -= 10
    if caps.get("eval"):
        s -= 10
    if caps.get("filesystem") and caps.get("network_out"):
        s -= 15  # exfil shape
    if caps.get("env_read") and caps.get("network_out"):
        s -= 5
    return max(0, s)


def score_registry(provenance: bool, signatures: bool, publisher_trusted: bool) -> int:
    if provenance and publisher_trusted:
        return 100
    if provenance or publisher_trusted:
        return 80
    if signatures:
        return 60
    return 40


def score_sdk(
    sdk_range: Optional[str], sdk_resolved: Optional[str], sdk_latest: Optional[str], stdio: bool
) -> int:
    s = 100
    if sdk_range is None:
        s -= 20  # not clearly on the official TS SDK
    else:
        if sdk_resolved and sdk_latest:
            rv, lv = parse_ver(sdk_resolved), parse_ver(sdk_latest)
            if rv and lv:
                if rv[0] < lv[0]:
                    s -= 30
                elif rv[1] < lv[1]:
                    s -= 15
        if sdk_range.startswith(("^", "~")) or sdk_range in ("*", "latest"):
            s -= 10  # floating SDK range
    if stdio:
        s -= 10
    return max(0, s)


def build_findings(r: dict) -> list[dict]:
    """Structured findings from a raw audit record."""
    out = []
    caps = r["capabilities"]
    if r["transitive_deps"] > 100:
        out.append(make_finding("MSA-P001", n=r["transitive_deps"]))
    if r["floating_direct"]:
        out.append(make_finding("MSA-P002", n=r["floating_direct"]))
    if caps.get("exec"):
        out.append(make_finding("MSA-P003"))
    if caps.get("filesystem") and caps.get("network_out"):
        out.append(make_finding("MSA-P004"))
    if caps.get("env_read") and caps.get("network_out"):
        out.append(make_finding("MSA-P005"))
    if caps.get("eval"):
        out.append(make_finding("MSA-P006"))
    if r.get("install_scripts"):
        out.append(make_finding("MSA-P007", scripts=", ".join(r["install_scripts"])))
    if r.get("prepare_script"):
        out.append(make_finding("MSA-P008"))
    if caps.get("obfuscation"):
        out.append(make_finding("MSA-P009"))
    if r.get("exfil_hosts") or caps.get("exfil_host"):
        hosts = ", ".join(r.get("exfil_hosts") or []) or "known host"
        out.append(make_finding("MSA-P010", hosts=hosts))
    if r.get("lifecycle_chain"):
        out.append(make_finding("MSA-P011", scripts=", ".join(r["lifecycle_chain"])))
    # npm-shaped registry findings; PyPI slice does not parse PEP 740 yet
    if r.get("ecosystem") != "pypi":
        if not r["provenance"]:
            out.append(make_finding("MSA-R001"))
        if not r["signatures"]:
            out.append(make_finding("MSA-R002"))
        if not r.get("publisher_trusted"):
            out.append(make_finding("MSA-R003"))
    if caps.get("stdio"):
        out.append(make_finding("MSA-S001"))
    if r.get("sdk_range") is None:
        out.append(make_finding("MSA-S004"))
    else:
        rv = parse_ver(r["sdk_resolved"]) if r.get("sdk_resolved") else None
        lv = parse_ver(r["sdk_latest"]) if r.get("sdk_latest") else None
        if rv and lv and (rv[0] < lv[0] or rv[1] < lv[1]):
            out.append(make_finding("MSA-S002", baseline=r["sdk_latest"], resolved=r["sdk_resolved"]))
        if r["sdk_range"].startswith(("^", "~")) or r["sdk_range"] in ("*", "latest"):
            out.append(make_finding("MSA-S003"))
    out.sort(key=lambda f: -SEVERITY_ORDER[f["severity"]])
    return out
