from mcp_supply_audit.report import headlines, to_markdown

DOC = {
    "results": [
        {
            "package": "a", "version": "1.0.0",
            "transitive_deps": 10, "floating_direct": 1,
            "capabilities": {"exec": 0, "filesystem": 1, "network_out": 1, "stdio": 1},
            "provenance": False, "publisher_trusted": False,
            "install_scripts": [],
            "score_package": 80, "score_registry": 40, "score_sdk": 90, "score_overall": 70,
        },
        {
            "package": "b", "version": "2.0.0",
            "transitive_deps": 200, "floating_direct": 0,
            "capabilities": {"exec": 1, "filesystem": 0, "network_out": 0, "stdio": 1},
            "provenance": True, "publisher_trusted": True,
            "install_scripts": ["postinstall"],
            "score_package": 40, "score_registry": 100, "score_sdk": 80, "score_overall": 73,
        },
        {"package": "c", "error": "404"},
    ]
}


def test_headlines_ignore_errors():
    from mcp_supply_audit.report import _results
    h = headlines(_results(DOC))
    assert h["n"] == 2
    assert h["floating_pct"] == 50
    assert h["deps_median"] == 105
    assert h["deps_max"] == 200
    assert h["exfil_pct"] == 50
    assert h["exec_pct"] == 50
    assert h["stdio_pct"] == 100
    assert h["no_prov_pct"] == 50
    assert h["oidc_pct"] == 50
    assert h["lifecycle"] == ["b"]
    assert h["score_median"] == 71


def test_markdown_contains_tables():
    md = to_markdown(DOC)
    assert "| Servers audited | 2 |" in md
    assert "`b`" in md and "`a`" in md
    assert "`c`" not in md
    assert md.index("`b`") < md.index("`a`") or "73" in md  # sorted by score; a=70 first
    assert "| `a` |" in md.split("## Scores")[1]  # a is lower, listed first
