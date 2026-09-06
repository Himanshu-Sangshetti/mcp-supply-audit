"""Capability surface scan of a published tarball (npm .tgz or PyPI sdist).

Reads source files and counts capability signals. The code is never
executed — this is a regex surface scan, not a proof of behavior
(see README "Sharp edges").
"""
import io
import json
import re
import tarfile
from typing import Optional

# JS/TS patterns — keep stable; corpus scores are cited in the talk
CAP_PATTERNS = {
    "exec": re.compile(r"child_process|execSync|spawnSync|\bspawn\(|\bexec\(", re.I),
    "network_out": re.compile(r"\bfetch\(|https?\.request|axios|net\.connect|new WebSocket|got\(", re.I),
    "filesystem": re.compile(
        r"fs\.(readFile|writeFile|createReadStream|createWriteStream|readdir|rm\(|unlink)",
        re.I,
    ),
    "env_read": re.compile(r"process\.env"),
    "eval": re.compile(r"\beval\(|new Function\(", re.I),
    "stdio": re.compile(r"StdioServerTransport"),
}

# Applied only to *.py so npm corpus numbers do not drift
PY_CAP_PATTERNS = {
    "exec": re.compile(r"subprocess|os\.system|Popen\(", re.I),
    "network_out": re.compile(r"urllib\.request|urlopen|httpx|requests\.|aiohttp", re.I),
    "filesystem": re.compile(r"\bopen\(|pathlib\.Path", re.I),
    "env_read": re.compile(r"os\.environ|os\.getenv"),
    "eval": re.compile(r"\beval\(|\bexec\("),
    "stdio": re.compile(r"stdio_server|StdioServerParameters"),
}

SOURCE_EXT = re.compile(r"\.(js|mjs|cjs|ts|py)$")
SKIP_PATHS = ("/test", "/tests", "__tests__", ".test.", ".d.ts")


def scan_tarball(
    tgz_bytes: Optional[bytes], max_files: int = 400, max_file_size: int = 2_000_000
) -> tuple[dict[str, int], int]:
    """Return (capabilities dict, files_scanned)."""
    caps = {k: 0 for k in CAP_PATTERNS}
    if not tgz_bytes:
        return caps, 0
    n = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tf:
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
                patterns = PY_CAP_PATTERNS if m.name.endswith(".py") else CAP_PATTERNS
                for k, pat in patterns.items():
                    caps[k] += len(pat.findall(src))
    except Exception:
        pass
    return caps, n


# Scripts that execute on the CONSUMER's machine during `npm install <pkg>`
# from the registry. This is the E10 attack: install-time code execution.
INSTALL_TIME_SCRIPTS = ("preinstall", "install", "postinstall")
# `prepare` does NOT run for registry installs — but it DOES run when the
# package is installed as a git dependency (and in local dev). Lower signal.
GIT_DEP_SCRIPTS = ("prepare",)


def scan_lifecycle_scripts(tgz_bytes: Optional[bytes]) -> tuple[list[str], list[str]]:
    """Read package.json from the tarball; return (install_time, git_dep) scripts.

    install_time: scripts that run on a consumer's `npm install` (HIGH signal).
    git_dep: scripts that run only for git-dependency installs (INFO signal).
    """
    install_time: list[str] = []
    git_dep: list[str] = []
    if not tgz_bytes:
        return install_time, git_dep
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tf:
            member = next(
                (m for m in tf.getmembers() if m.isfile() and m.name.endswith("package/package.json")),
                None,
            )
            if member is None:
                return install_time, git_dep
            f = tf.extractfile(member)
            if not f:
                return install_time, git_dep
            pkg_json = json.loads(f.read().decode("utf-8", errors="ignore"))
    except Exception:
        return install_time, git_dep
    scripts = pkg_json.get("scripts", {})
    if not isinstance(scripts, dict):
        return install_time, git_dep
    install_time = [s for s in INSTALL_TIME_SCRIPTS if scripts.get(s)]
    git_dep = [s for s in GIT_DEP_SCRIPTS if scripts.get(s)]
    return install_time, git_dep
