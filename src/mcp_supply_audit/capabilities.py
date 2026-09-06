"""Capability surface scan of a published npm tarball.

Reads source files and counts capability signals. The code is never
executed — this is a regex surface scan, not a proof of behavior
(see README "Sharp edges").
"""
import io
import re
import tarfile

CAP_PATTERNS = {
    "exec": re.compile(r"child_process|execSync|spawnSync|\bspawn\(|\bexec\(", re.I),
    "network_out": re.compile(r"\bfetch\(|https?\.request|axios|net\.connect|new WebSocket|got\(", re.I),
    "filesystem": re.compile(r"fs\.(readFile|writeFile|createReadStream|createWriteStream|readdir|rm\(|unlink)", re.I),
    "env_read": re.compile(r"process\.env"),
    "eval": re.compile(r"\beval\(|new Function\(", re.I),
    "stdio": re.compile(r"StdioServerTransport"),
}

SOURCE_EXT = re.compile(r"\.(js|mjs|cjs|ts)$")
SKIP_PATHS = ("/test", "__tests__", ".test.", ".d.ts")


def scan_tarball(tgz_bytes, max_files=400, max_file_size=2_000_000):
    """Return (capabilities dict, files_scanned)."""
    caps = {k: 0 for k in CAP_PATTERNS}
    if not tgz_bytes:
        return caps, 0
    n = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz")
        for m in tf.getmembers():
            if n >= max_files:
                break
            if not m.isfile() or m.size > max_file_size:
                continue
            if not SOURCE_EXT.search(m.name):
                continue
            if any(s in m.name for s in SKIP_PATHS):
                continue
            f = tf.extractfile(m)
            if not f:
                continue
            try:
                src = f.read().decode("utf-8", errors="ignore")
            except Exception:
                continue
            n += 1
            for k, pat in CAP_PATTERNS.items():
                caps[k] += len(pat.findall(src))
    except Exception:
        pass
    return caps, n
