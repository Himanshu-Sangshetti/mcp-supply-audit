from mcp_supply_audit.pypi import is_unpinned, parse_requires, resolve_pypi_tree, sdist_url
from mcp_supply_audit.scoring import build_findings


class _Reg:
    def __init__(self, catalog: dict) -> None:
        self.catalog = catalog

    def fetch_json(self, url: str, cache_key=None) -> dict:
        rest = url.split("/pypi/", 1)[-1]
        return self.catalog.get(rest, {"__error__": 404})


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


def test_resolve_pypi_tree_walks_latest_and_pins():
    cat = {
        "a/json": {"info": {"version": "2.0.0", "requires_dist": ["b==1.0.0", "c>=1"]}},
        "b/1.0.0/json": {"info": {"version": "1.0.0", "requires_dist": ["d>=0"]}},
        "c/json": {"info": {"version": "9.9.9", "requires_dist": []}},
        "d/json": {"info": {"version": "0.1.0", "requires_dist": []}},
    }
    n, depth, resolved = resolve_pypi_tree(_Reg(cat), "root", [("a", ">=1")])
    assert n == 4
    assert depth >= 2
    assert dict(resolved)["b"] == "1.0.0"
    assert dict(resolved)["c"] == "9.9.9"
    assert dict(resolved)["d"] == "0.1.0"


def test_resolve_pypi_tree_skips_cycle_and_extras():
    cat = {
        "a/json": {"info": {"version": "1.0.0", "requires_dist": [
            "root>=1",
            'bonus>=1; extra == "dev"',
        ]}},
    }
    n, _, resolved = resolve_pypi_tree(_Reg(cat), "root", [("a", "*")])
    assert n == 1
    assert dict(resolved)["a"] == "1.0.0"
