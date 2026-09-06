from mcp_supply_audit.semver import is_floating, max_satisfying, parse_ver, satisfies


def test_parse_ver():
    assert parse_ver("1.2.3") == (1, 2, 3)
    assert parse_ver("1.2.3-beta.1") == (1, 2, 3)
    assert parse_ver("not-a-version") is None


def test_caret():
    assert satisfies("1.4.0", "^1.2.0")
    assert not satisfies("2.0.0", "^1.2.0")
    assert not satisfies("1.1.9", "^1.2.0")
    # 0.x caret pins the minor
    assert satisfies("0.3.5", "^0.3.0")
    assert not satisfies("0.4.0", "^0.3.0")


def test_tilde_and_exact():
    assert satisfies("1.2.9", "~1.2.3")
    assert not satisfies("1.3.0", "~1.2.3")
    assert satisfies("1.2.3", "1.2.3")
    assert not satisfies("1.2.4", "1.2.3")


def test_ranges_and_union():
    assert satisfies("1.5.0", ">=1.2.0 <2.0.0")
    assert not satisfies("2.0.0", ">=1.2.0 <2.0.0")
    assert satisfies("3.0.0", "^1.0.0 || >=3.0.0")
    assert satisfies("9.9.9", "*")
    assert satisfies("9.9.9", "latest")


def test_x_ranges():
    assert satisfies("1.7.0", "1.x")
    assert not satisfies("2.0.0", "1.x")
    assert satisfies("1.2.9", "1.2.x")


def test_max_satisfying_skips_prerelease():
    versions = ["1.0.0", "1.1.0", "1.2.0-rc.1", "0.9.9"]
    assert max_satisfying(versions, "^1.0.0") == "1.1.0"
    assert max_satisfying(versions, "^0.9.0") == "0.9.9"
    assert max_satisfying(versions, "^5.0.0") is None


def test_hyphen_range_inclusive():
    assert satisfies("1.2.3", "1.2.3 - 2.0.0")
    assert satisfies("1.9.0", "1.2.3 - 2.0.0")
    assert satisfies("2.0.0", "1.2.3 - 2.0.0")
    assert not satisfies("2.0.1", "1.2.3 - 2.0.0")
    assert not satisfies("1.2.2", "1.2.3 - 2.0.0")


def test_hyphen_partial_upper_is_exclusive_next():
    # node-semver: `1.2 - 2` ⇒ >=1.2.0 <3.0.0
    assert satisfies("1.2.0", "1.2 - 2")
    assert satisfies("2.9.9", "1.2 - 2")
    assert not satisfies("3.0.0", "1.2 - 2")
    assert not satisfies("1.1.9", "1.2 - 2")


def test_union_ignores_empty_alt():
    assert satisfies("1.4.0", "^1.0.0 ||")
    assert not satisfies("2.0.0", "^1.0.0 ||")


def test_prerelease_does_not_satisfy_stable_range():
    assert not satisfies("1.2.3-beta.1", "^1.0.0")
    assert not satisfies("1.2.3-beta.1", "1.2.3")
    assert satisfies("1.2.3-beta.1", ">=1.2.3-0")


def test_max_satisfying_includes_prerelease_only_when_asked():
    versions = ["1.0.0", "1.1.0-rc.1", "1.1.0"]
    assert max_satisfying(versions, "^1.0.0") == "1.1.0"
    assert max_satisfying(versions, "^1.1.0-rc") == "1.1.0"


def test_is_floating():
    assert is_floating("^1.0.0")
    assert is_floating("~1.0.0")
    assert is_floating("*")
    assert is_floating("latest")
    assert not is_floating("1.2.3")
    assert not is_floating(None)
