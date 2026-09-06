"""CycloneDX 1.5 SBOM output from the resolved dependency tree."""
import datetime
import urllib.parse

from . import __version__


def _purl(name: str, version: str) -> str:
    # pkg:npm/%40scope/name@version — scope must be URL-encoded
    return f"pkg:npm/{urllib.parse.quote(name, safe='')}@{version}"


def to_cyclonedx(result: dict) -> dict:
    """One audit result -> a CycloneDX 1.5 BOM (dict)."""
    root = {
        "type": "library",
        "bom-ref": _purl(result["package"], result.get("version", "")),
        "name": result["package"],
        "version": result.get("version"),
    }
    components = [
        {
            "type": "library",
            "bom-ref": _purl(d["name"], d["version"]),
            "name": d["name"],
            "version": d["version"],
        }
        for d in result.get("resolved_tree", [])
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tools": [{"name": "mcp-supply-audit", "version": __version__}],
            "component": root,
        },
        "components": components,
        "dependencies": [
            {"ref": root["bom-ref"], "dependsOn": [c["bom-ref"] for c in components]}
        ],
    }
