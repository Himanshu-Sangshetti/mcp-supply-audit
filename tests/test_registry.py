import json
from unittest.mock import MagicMock, patch

from mcp_supply_audit.registry import Registry, ckey


def test_ckey_scoped_names():
    assert ckey("@scope/pkg") == "_scope__pkg"
    assert ckey("plain") == "plain"


def test_fetch_json_reads_and_writes_cache(tmp_path):
    cached = tmp_path / "foo.json"
    cached.write_text(json.dumps({"from": "disk"}))
    reg = Registry(cache_dir=str(tmp_path), use_cache=True)
    assert reg.fetch_json("https://example.invalid/foo", "foo") == {"from": "disk"}

    with patch("mcp_supply_audit.registry.urllib.request.urlopen") as urlopen:
        body = MagicMock()
        body.read.return_value = b'{"from": "net"}'
        body.__enter__.return_value = body
        body.__exit__.return_value = False
        urlopen.return_value = body
        fresh = Registry(cache_dir=str(tmp_path / "empty"), use_cache=True)
        assert fresh.fetch_json("https://example.invalid/bar", "bar") == {"from": "net"}
        assert json.loads((tmp_path / "empty" / "bar.json").read_text()) == {"from": "net"}


def test_fetch_json_http_error_is_data():
    from urllib.error import HTTPError

    reg = Registry(use_cache=False)
    err = HTTPError("https://x", 404, "no", hdrs=None, fp=None)
    with patch("mcp_supply_audit.registry.urllib.request.urlopen", side_effect=err):
        assert reg.fetch_json("https://x") == {"__error__": 404}


def test_fetch_bytes_cache_roundtrip(tmp_path):
    (tmp_path / "p.tgz").write_bytes(b"tarball")
    reg = Registry(cache_dir=str(tmp_path), use_cache=True)
    assert reg.fetch_bytes("https://example.invalid/p.tgz", "p") == b"tarball"
