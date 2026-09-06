from mcp_supply_audit.sbom import to_cyclonedx

RESULT = {
    "package": "@modelcontextprotocol/server-filesystem",
    "version": "2026.8.31",
    "resolved_tree": [
        {"name": "@modelcontextprotocol/sdk", "version": "1.30.0"},
        {"name": "zod", "version": "3.25.76"},
    ],
}


def test_cyclonedx_shape():
    bom = to_cyclonedx(RESULT)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["metadata"]["component"]["name"] == "@modelcontextprotocol/server-filesystem"
    assert len(bom["components"]) == 2
    refs = {c["bom-ref"] for c in bom["components"]}
    assert "pkg:npm/%40modelcontextprotocol%2Fsdk@1.30.0" in refs
    assert "pkg:npm/zod@3.25.76" in refs
    # root depends on all components
    dep = bom["dependencies"][0]
    assert dep["ref"] == bom["metadata"]["component"]["bom-ref"]
    assert set(dep["dependsOn"]) == refs


def test_empty_tree_is_valid():
    bom = to_cyclonedx({"package": "solo", "version": "1.0.0", "resolved_tree": []})
    assert bom["components"] == []
    assert bom["dependencies"][0]["dependsOn"] == []
