from mcp_supply_audit.sarif import to_sarif
from mcp_supply_audit.scoring import FINDINGS


def test_sarif_envelope_and_rule_catalog():
    doc = to_sarif([])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == set(FINDINGS)
    assert all("{" not in r["shortDescription"]["text"] for r in rules)


def test_sarif_skips_errors_and_maps_findings():
    doc = to_sarif([
        {"package": "gone", "error": "404"},
        {
            "package": "pkg",
            "version": "1.0.0",
            "score_overall": 50,
            "findings": [{
                "id": "MSA-P003",
                "severity": "MED",
                "layer": "package",
                "owasp": "MCP05",
                "message": "process execution capability in published source",
            }],
        },
    ])
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "MSA-P003"
    assert results[0]["level"] == "warning"
    assert results[0]["message"]["text"].startswith("pkg@1.0.0:")
