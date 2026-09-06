import io
import tarfile

from mcp_supply_audit.capabilities import scan_tarball


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
    caps, n = scan_tarball(tgz)
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
    caps, n = scan_tarball(tgz)
    assert n == 1
    assert caps["eval"] == 0


def test_clean_package_scores_zero():
    tgz = make_tgz({"package/index.js": "export const ok = true;"})
    caps, n = scan_tarball(tgz)
    assert n == 1
    assert all(v == 0 for v in caps.values())


def test_empty_tarball_is_safe():
    caps, n = scan_tarball(None)
    assert n == 0
    assert all(v == 0 for v in caps.values())
