import io
import tarfile

from mcp_supply_audit.audit import audit_package, audit_pypi_package, sdk_baseline


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()

SDK = "@modelcontextprotocol/sdk"


class _Reg:
    def __init__(self, packages, tarballs=None) -> None:
        self.packages = packages
        self.tarballs = tarballs or {}

    def package_meta(self, pkg: str) -> dict:
        return self.packages.get(pkg, {"__error__": 404})

    def fetch_json(self, url: str, cache_key=None) -> dict:
        name = url.split("registry.npmjs.org/", 1)[-1].replace("%2f", "/")
        if name.startswith("pypi.org/pypi/"):
            return self.packages.get(name, {"__error__": 404})
        return self.packages.get(name, {"__error__": 404})

    def tarball(self, url, pkg, version):
        return self.tarballs.get((pkg, version))

    def fetch_bytes(self, url, cache_key=None):
        return self.tarballs.get(url)


def _npm(name="demo", ver="1.0.0", deps=None, trusted=False, provenance=True):
    deps = deps or {SDK: "^1.2.0", "left-pad": "^1.0.0"}
    return {
        "dist-tags": {"latest": ver},
        "time": {"created": "2024-01-01T00:00:00.000Z", ver: "2026-01-01T00:00:00.000Z"},
        "maintainers": [{"name": "alice"}],
        "versions": {
            ver: {
                "dependencies": deps,
                "_npmUser": {"name": "alice", "trustedPublisher": {"id": "gha"} if trusted else None},
                "dist": {
                    "tarball": f"https://example.invalid/{name}-{ver}.tgz",
                    "attestations": {"provenance": provenance},
                    "signatures": [{"sig": "x"}] if provenance else [],
                },
            }
        },
    }


def test_audit_package_error_paths():
    assert audit_package("gone", registry=_Reg({}))["error"] == 404
    meta = _npm()
    meta["versions"] = {}
    assert "version not found" in audit_package("demo", registry=_Reg({"demo": meta}))["error"]


def test_sdk_baseline_ok_and_error():
    assert sdk_baseline(_Reg({})) == (None, {"__error__": 404})
    latest, meta = sdk_baseline(_Reg({SDK: {"dist-tags": {"latest": "1.9.0"}}}))
    assert latest == "1.9.0"
    assert meta["dist-tags"]["latest"] == "1.9.0"


def test_audit_package_scores_a_clean_tree():
    tgz = _tgz({"package/index.js": "export const ok = true;\n"})
    sdk_meta = {
        "dist-tags": {"latest": "1.2.0"},
        "versions": {"1.2.0": {"dependencies": {}}},
    }
    left = {"versions": {"1.3.0": {"dependencies": {}}}}
    reg = _Reg(
        {"demo": _npm(trusted=True), SDK: sdk_meta, "left-pad": left},
        tarballs={("demo", "1.0.0"): tgz},
    )
    r = audit_package("demo", registry=reg, sdk_latest="1.2.0", _sdk_meta=sdk_meta)
    assert r["version"] == "1.0.0"
    assert r["publisher_trusted"] is True
    assert r["provenance"] is True
    assert r["transitive_deps"] == 2
    assert r["sdk_resolved"] == "1.2.0"
    assert r["score_registry"] == 100
    assert isinstance(r["score_overall"], int)
    assert r["files_scanned"] == 1


def test_audit_pypi_package_thin_slice():
    tgz = _tgz({"pkg/server.py": "print('hi')\n"})
    meta = {
        "info": {
            "version": "0.1.0",
            "author": "Ada",
            "requires_dist": ["anyio>=4.0", 'httpx>=0.27; extra == "cli"'],
        },
        "urls": [{"packagetype": "sdist", "url": "https://files.example/p.tgz",
                  "upload_time_iso_8601": "2026-02-01T00:00:00.000Z"}],
    }
    # pypi_meta builds https://pypi.org/pypi/{pkg}/json
    class _P(_Reg):
        def fetch_json(self, url, cache_key=None):
            if url.endswith("/demo/json"):
                return meta
            return {"__error__": 404}

    r = audit_pypi_package("demo", registry=_P({}, tarballs={"https://files.example/p.tgz": tgz}))
    assert r["ecosystem"] == "pypi"
    assert r["version"] == "0.1.0"
    assert r["direct_deps"] == 1  # extra skipped
    assert r["latest_release"].startswith("2026-02-01")
    assert r["score_registry"] == 40
    assert all(f["id"] not in {"MSA-R001", "MSA-R002", "MSA-R003"} for f in r["findings"])


def test_audit_pypi_error():
    class _P(_Reg):
        def fetch_json(self, url, cache_key=None):
            return {"__error__": 404}

    assert audit_pypi_package("nope", registry=_P({}))["error"] == 404
