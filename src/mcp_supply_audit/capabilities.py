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

# Informational only — does NOT feed score_package (corpus scores stay put)
OBFUSCATION_PATTERNS = (
    re.compile(r"\batob\(", re.I),
    re.compile(r"Buffer\.from\([^;]{0,120}['\"]base64", re.I),
    re.compile(r"String\.fromCharCode\(", re.I),
    re.compile(r"base64\.b64decode|base64\.b64encode", re.I),
    re.compile(r"(?:eval|Function|exec)\([^)]{0,80}(?:atob|fromCharCode|b64decode)", re.I),
)
HEX_ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}")
HEX_ESCAPE_FLOOR = 20

# High-signal hosts — pastebins, tunnels, OOB collaborators, the postmark sink.
# Score-neutral. Do not add generic CDNs or github.com.
EXFIL_HOSTS = (
    ("webhook.site", re.compile(r"webhook\.site", re.I)),
    ("requestbin", re.compile(r"requestbin(?:\.com|\.net)?", re.I)),
    ("pipedream.net", re.compile(r"pipedream\.net", re.I)),
    ("interact.sh", re.compile(r"interact\.sh", re.I)),
    ("ngrok", re.compile(r"ngrok(?:-free)?\.(?:io|app|dev)", re.I)),
    ("pastebin.com", re.compile(r"pastebin\.com", re.I)),
    ("discord-webhook", re.compile(r"discord(?:app)?\.com/api/webhooks", re.I)),
    ("telegram-bot", re.compile(r"api\.telegram\.org/bot", re.I)),
    ("giftshop.club", re.compile(r"giftshop\.club", re.I)),
    ("burpcollaborator", re.compile(r"burpcollaborator\.net", re.I)),
    ("oast", re.compile(r"oast(?:ify)?\.(?:com|fun|pro)", re.I)),
)

# Install-script *command* that fetches remote or pipes to a shell.
REMOTE_INSTALL = re.compile(
    r"https?://|\bcurl\b|\bwget\b|\|\s*(?:ba)?sh\b|powershell\s+-(?:enc|e\b)|Invoke-WebRequest",
    re.I,
)
HOOK_BASENAME = re.compile(r"^(preinstall|install|postinstall)\.[cm]?[jt]s$")

SOURCE_EXT = re.compile(r"\.(js|mjs|cjs|ts|py)$")
SKIP_PATHS = ("/test", "/tests", "__tests__", ".test.", ".d.ts")


def obfuscation_hits(src: str) -> int:
    """Count decode-then-run / dense-escape shapes. Heuristic, not proof."""
    n = sum(len(p.findall(src)) for p in OBFUSCATION_PATTERNS)
    if len(HEX_ESCAPES.findall(src)) >= HEX_ESCAPE_FLOOR:
        n += 1
    return n


def exfil_host_hits(src: str) -> list[str]:
    """Known exfil / paste / tunnel hosts in source. Heuristic, not proof."""
    return [name for name, pat in EXFIL_HOSTS if pat.search(src)]


def scan_tarball(
    tgz_bytes: Optional[bytes], max_files: int = 400, max_file_size: int = 2_000_000
) -> tuple[dict[str, int], int]:
    """Return (capabilities dict, files_scanned, unique exfil-host labels)."""
    caps = {k: 0 for k in CAP_PATTERNS}
    caps["obfuscation"] = 0
    caps["exfil_host"] = 0
    hosts: list[str] = []
    if not tgz_bytes:
        return caps, 0, []
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
                caps["obfuscation"] += obfuscation_hits(src)
                found = exfil_host_hits(src)
                if found:
                    caps["exfil_host"] += len(found)
                    hosts.extend(found)
    except Exception:
        pass
    return caps, n, sorted(set(hosts))


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


def scan_lifecycle_chain(tgz_bytes: Optional[bytes]) -> list[str]:
    """Install-time scripts that fetch remote or whose hook file has network_out.

    Score-neutral. `npx` alone is not enough — too common in real packages.
    """
    flagged: list[str] = []
    if not tgz_bytes:
        return flagged
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tf:
            member = next(
                (m for m in tf.getmembers() if m.isfile() and m.name.endswith("package/package.json")),
                None,
            )
            scripts: dict = {}
            if member is not None:
                f = tf.extractfile(member)
                if f:
                    pkg_json = json.loads(f.read().decode("utf-8", errors="ignore"))
                    raw = pkg_json.get("scripts", {})
                    if isinstance(raw, dict):
                        scripts = raw
            for s in INSTALL_TIME_SCRIPTS:
                cmd = scripts.get(s)
                if isinstance(cmd, str) and REMOTE_INSTALL.search(cmd) and s not in flagged:
                    flagged.append(s)
            if any(scripts.get(s) for s in INSTALL_TIME_SCRIPTS):
                for m in tf.getmembers():
                    if not m.isfile():
                        continue
                    base = m.name.rsplit("/", 1)[-1]
                    hit = HOOK_BASENAME.match(base)
                    if not hit:
                        continue
                    name = hit.group(1)
                    fh = tf.extractfile(m)
                    if not fh:
                        continue
                    src = fh.read().decode("utf-8", errors="ignore")
                    if name not in flagged and (
                        CAP_PATTERNS["network_out"].search(src) or exfil_host_hits(src)
                    ):
                        flagged.append(name)
    except Exception:
        return flagged
    return flagged
