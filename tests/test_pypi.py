from mcp_supply_audit.pypi import is_unpinned, parse_requires, sdist_url
from mcp_supply_audit.scoring import build_findings


def test_parse_requires_strips_markers_and_extras():
    reqs = parse_requires([
        'anyio>=4.9; python_version < "3.14"',
        "mcp-types==2.1.1",
        'httpx>=0.27; extra == "cli"',
        "pydantic>=2.12.0",
    ])
    names = [n for n, _ in reqs]
    assert names == ["anyio", "mcp-types", "pydantic"]
    assert dict(reqs)["mcp-types"] == "==2.1.1"
    assert is_unpinned(">=4.9")
    assert not is_unpinned("==2.1.1")


def test_sdist_url_picks_sdist():
    meta = {"urls": [
        {"packagetype": "bdist_wheel", "url": "http://w.whl"},
        {"packagetype": "sdist", "url": "http://s.tar.gz"},
    ]}
    assert sdist_url(meta) == "http://s.tar.gz"


def test_pypi_skips_npm_registry_findings():
    r = {
        "ecosystem": "pypi",
        "transitive_deps": 4,
        "floating_direct": 0,
        "capabilities": {
            "exec": 0, "network_out": 0, "filesystem": 0,
            "env_read": 0, "eval": 0, "stdio": 0,
        },
        "provenance": False,
        "signatures": 0,
        "publisher_trusted": False,
        "sdk_range": None,
        "install_scripts": [],
        "prepare_script": False,
    }
    ids = {f["id"] for f in build_findings(r)}
    assert "MSA-R001" not in ids
    assert "MSA-R002" not in ids
    assert "MSA-R003" not in ids
    assert "MSA-S004" in ids
