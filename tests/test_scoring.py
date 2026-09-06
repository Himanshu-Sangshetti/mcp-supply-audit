from mcp_supply_audit.scoring import (
    build_findings,
    score_package,
    score_registry,
    score_sdk,
)

NO_CAPS = {"exec": 0, "network_out": 0, "filesystem": 0, "env_read": 0, "eval": 0, "stdio": 0}


def test_package_tree_bands():
    assert score_package(10, 0, NO_CAPS) == 100
    assert score_package(51, 0, NO_CAPS) == 90
    assert score_package(101, 0, NO_CAPS) == 80
    assert score_package(201, 0, NO_CAPS) == 70


def test_package_deductions_stack():
    caps = dict(NO_CAPS, exec=1, eval=1, filesystem=1, network_out=1, env_read=1)
    # 100 - 10 (exec) - 10 (eval) - 15 (exfil shape) - 5 (env+net) = 60
    assert score_package(10, 0, caps) == 60
    # floating ranges cost another 10
    assert score_package(10, 2, caps) == 50


def test_registry_ladder():
    assert score_registry(True, True, True) == 100
    assert score_registry(True, False, False) == 80
    assert score_registry(False, True, True) == 80
    assert score_registry(False, True, False) == 60
    assert score_registry(False, False, False) == 40


def test_sdk_scoring():
    assert score_sdk(None, None, "1.9.0", False) == 80
    assert score_sdk("1.9.0", "1.9.0", "1.9.0", False) == 100
    assert score_sdk("^1.9.0", "1.9.0", "1.9.0", False) == 90   # floating
    assert score_sdk("1.8.0", "1.8.0", "1.9.0", False) == 85   # minor behind
    assert score_sdk("0.9.0", "0.9.0", "1.9.0", False) == 70   # major behind
    assert score_sdk("1.9.0", "1.9.0", "1.9.0", True) == 90    # stdio


def test_findings_map_to_owasp():
    r = {
        "transitive_deps": 150,
        "floating_direct": 3,
        "capabilities": {"exec": 1, "network_out": 1, "filesystem": 1, "env_read": 1, "eval": 0, "stdio": 1},
        "provenance": False,
        "signatures": 0,
        "publisher_trusted": False,
        "sdk_range": "^1.0.0",
        "sdk_resolved": "1.0.0",
        "sdk_latest": "1.2.0",
    }
    findings = build_findings(r)
    ids = {f["id"] for f in findings}
    assert {"MSA-P001", "MSA-P002", "MSA-P003", "MSA-P004", "MSA-P005",
            "MSA-R001", "MSA-R002", "MSA-R003", "MSA-S001", "MSA-S002", "MSA-S003"} <= ids
    assert all(f["owasp"].startswith("MCP") for f in findings)
    # sorted by severity, HIGH/MED first
    assert findings[0]["severity"] == "MED"
