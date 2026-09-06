from mcp_supply_audit.lock import check_lock, make_lock, tree_hash

BASE = {
    "package": "pkg",
    "version": "1.0.0",
    "publisher": "alice",
    "transitive_deps": 2,
    "install_scripts": [],
    "resolved_tree": [
        {"name": "zod", "version": "3.0.0"},
        {"name": "left-pad", "version": "1.3.0"},
    ],
}


def test_hash_is_stable_and_order_independent():
    flipped = dict(BASE, resolved_tree=list(reversed(BASE["resolved_tree"])))
    assert tree_hash(BASE) == tree_hash(flipped)
    assert len(tree_hash(BASE)) == 64


def test_version_or_dep_change_moves_hash():
    bumped = dict(BASE, version="1.0.1")
    newdep = dict(BASE, resolved_tree=BASE["resolved_tree"] + [{"name": "evil", "version": "9.9.9"}])
    assert tree_hash(bumped) != tree_hash(BASE)
    assert tree_hash(newdep) != tree_hash(BASE)


def test_check_lock_clean_and_drift():
    lock = make_lock(BASE)
    assert check_lock(lock, BASE) == []
    drifted = dict(BASE, version="2.0.0", resolved_tree=[{"name": "zod", "version": "4.0.0"}])
    reasons = check_lock(lock, drifted)
    assert any("version" in r for r in reasons)
    assert any("tree_hash" in r for r in reasons)
    assert any("removed" in r or "added" in r for r in reasons)
