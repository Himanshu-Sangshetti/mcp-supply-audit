from mcp_supply_audit.tree import resolve_tree


class _Mem:
    def __init__(self, packages: dict) -> None:
        self.packages = packages

    def fetch_json(self, url: str, cache_key=None) -> dict:
        name = url.rsplit("/", 1)[-1].replace("%2f", "/")
        return self.packages.get(name, {"__error__": 404})


def test_resolves_direct_and_transitive():
    reg = _Mem({
        "root": {"versions": {"1.0.0": {"dependencies": {"a": "^1.0.0", "b": "1.0.0"}}}},
        "a": {"versions": {"1.0.0": {"dependencies": {}}, "1.2.0": {"dependencies": {"c": "^2.0.0"}}}},
        "b": {"versions": {"1.0.0": {"dependencies": {}}}},
        "c": {"versions": {"2.0.0": {"dependencies": {}}, "2.1.0": {"dependencies": {}}}},
    })
    n, depth, resolved = resolve_tree("root", "1.0.0", reg)
    assert n == 3
    assert depth >= 1
    assert dict(resolved) == {"a": "1.2.0", "b": "1.0.0", "c": "2.1.0"}


def test_skips_cycle_back_to_root():
    reg = _Mem({
        "root": {"versions": {"1.0.0": {"dependencies": {"a": "1.0.0"}}}},
        "a": {"versions": {"1.0.0": {"dependencies": {"root": "1.0.0"}}}},
    })
    n, _, resolved = resolve_tree("root", "1.0.0", reg)
    assert n == 1
    assert resolved == [("a", "1.0.0")]


def test_missing_package_is_counted_but_not_resolved():
    reg = _Mem({
        "root": {"versions": {"1.0.0": {"dependencies": {"ghost": "1.0.0"}}}},
    })
    n, _, resolved = resolve_tree("root", "1.0.0", reg)
    assert n == 1
    assert resolved == []
