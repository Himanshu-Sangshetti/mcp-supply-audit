from mcp_supply_audit.diff import diff_audits

BASE = {
    "package": "pkg", "version": "1.0.0",
    "publisher": "alice", "provenance": True,
    "capabilities": {"exec": 0, "network_out": 0, "filesystem": 1, "env_read": 1, "eval": 0, "stdio": 1},
    "install_scripts": [], "transitive_deps": 50,
    "score_package": 90, "score_registry": 100, "score_sdk": 80, "score_overall": 90,
}


def v2(**kw):
    r = dict(BASE)
    r["version"] = "1.0.1"
    r.update(kw)
    return r


def test_clean_diff_has_no_findings():
    d = diff_audits(BASE, v2())
    assert d["findings"] == []
    assert d["score_delta"]["overall"] == 0
    assert d["from"] == "1.0.0" and d["to"] == "1.0.1"


def test_postinstall_added_is_high():
    d = diff_audits(BASE, v2(install_scripts=["postinstall"]))
    f = d["findings"][0]
    assert f["id"] == "MSA-D001" and f["severity"] == "HIGH"
    assert "postinstall" in f["message"]


def test_publisher_change_is_high():
    d = diff_audits(BASE, v2(publisher="mallory"))
    assert any(f["id"] == "MSA-D002" and f["severity"] == "HIGH" for f in d["findings"])
    assert d["publisher_changed"]


def test_provenance_drop_and_exfil_shape():
    caps = {"exec": 0, "network_out": 2, "filesystem": 1, "env_read": 1, "eval": 0, "stdio": 1}
    d = diff_audits(BASE, v2(provenance=False, capabilities=caps))
    ids = {f["id"] for f in d["findings"]}
    assert "MSA-D003" in ids  # provenance dropped
    assert "MSA-D005" in ids  # fs+network newly combined
    assert d["provenance_dropped"]


def test_new_exec_capability_and_dep_growth():
    caps = dict(BASE["capabilities"], exec=3)
    d = diff_audits(BASE, v2(capabilities=caps, transitive_deps=140))
    ids = {f["id"] for f in d["findings"]}
    assert "MSA-D004" in ids  # exec appeared
    assert "MSA-D006" in ids  # 50 → 140 is >1.5x and +90
    assert d["capability_delta"]["exec"] == 3
    assert d["transitive_deps_delta"] == 90


def test_existing_capability_not_flagged_as_new():
    # stdio present in both versions → not "new"
    d = diff_audits(BASE, v2(capabilities=dict(BASE["capabilities"], stdio=5)))
    assert "MSA-D004" not in {f["id"] for f in d["findings"]}
    assert d["capability_delta"]["stdio"] == 4
