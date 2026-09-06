"""SARIF 2.1.0 output for CI integration (GitHub code scanning, etc.)."""
from . import __version__
from .scoring import FINDINGS, SEVERITY_ORDER

_SARIF_LEVEL = {"HIGH": "error", "MED": "warning", "LOW": "note", "INFO": "note"}
INFORMATION_URI = "https://github.com/Himanshu-Sangshetti/mcp-supply-audit"


def to_sarif(results):
    """results: list of audit result dicts."""
    rules = []
    for fid, (sev, layer, owasp, template) in sorted(FINDINGS.items()):
        rules.append({
            "id": fid,
            "name": fid.replace("MSA-", "McpSupply"),
            "shortDescription": {"text": f"[{layer}] {template.split('—')[0].strip()}"},
            "fullDescription": {"text": f"{template} (OWASP MCP Top 10: {owasp})"},
            "defaultConfiguration": {"level": _SARIF_LEVEL[sev]},
            "properties": {"layer": layer, "owasp": owasp, "severity": sev},
        })

    sarif_results = []
    for r in results:
        if "error" in r:
            continue
        for f in r.get("findings", []):
            sarif_results.append({
                "ruleId": f["id"],
                "level": _SARIF_LEVEL.get(f["severity"], "warning"),
                "message": {"text": f"{r['package']}@{r.get('version')}: {f['message']}"},
                "properties": {
                    "package": r["package"],
                    "version": r.get("version"),
                    "layer": f["layer"],
                    "owasp": f["owasp"],
                    "score_overall": r.get("score_overall"),
                },
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-supply-audit",
                    "version": __version__,
                    "informationUri": INFORMATION_URI,
                    "rules": rules,
                }
            },
            "results": sarif_results,
        }],
    }
