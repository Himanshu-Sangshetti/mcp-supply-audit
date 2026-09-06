"""npm registry access. Read-only, cacheable, stdlib-only."""
import json
import os
import urllib.error
import urllib.request

REGISTRY = "https://registry.npmjs.org"
UA = {"User-Agent": "mcp-supply-audit/0.1 (read-only audit; https://github.com/Himanshu-Sangshetti/mcp-supply-audit)"}


def default_cache_dir():
    return os.environ.get(
        "MCP_SUPPLY_AUDIT_CACHE",
        os.path.join(os.path.expanduser("~"), ".cache", "mcp-supply-audit"),
    )


def ckey(pkg):
    """Filesystem-safe cache key for a package name."""
    return pkg.replace("@", "_").replace("/", "__")


class Registry:
    """Fetches package metadata and tarballs from the npm registry.

    Nothing fetched here is ever executed. Cache is plain files on disk so
    repeated audits (and the corpus study) don't hammer the registry.
    """

    def __init__(self, cache_dir=None, use_cache=True):
        self.cache_dir = cache_dir or default_cache_dir()
        self.use_cache = use_cache
        if use_cache:
            os.makedirs(self.cache_dir, exist_ok=True)

    def fetch_json(self, url, cache_key=None):
        p = None
        if self.use_cache and cache_key:
            p = os.path.join(self.cache_dir, cache_key + ".json")
            if os.path.exists(p):
                try:
                    with open(p) as f:
                        return json.load(f)
                except Exception:
                    pass
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read().decode())
            if p:
                with open(p, "w") as f:
                    json.dump(data, f)
            return data
        except urllib.error.HTTPError as e:
            return {"__error__": e.code}
        except Exception as e:
            return {"__error__": str(e)}

    def fetch_bytes(self, url, cache_key=None):
        p = None
        if self.use_cache and cache_key:
            p = os.path.join(self.cache_dir, cache_key + ".tgz")
            if os.path.exists(p):
                with open(p, "rb") as f:
                    return f.read()
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
            if p and len(data) < 40_000_000:
                with open(p, "wb") as f:
                    f.write(data)
            return data
        except Exception:
            return None

    def package_meta(self, pkg):
        return self.fetch_json(f"{REGISTRY}/{pkg.replace('/', '%2f')}", ckey(pkg))

    def tarball(self, url, pkg, version):
        return self.fetch_bytes(url, f"{ckey(pkg)}-{version}")
