"""Markdown corpus report from an audit results.json."""
import statistics
from typing import Union


def _results(doc: Union[dict, list]) -> list[dict]:
    if isinstance(doc, list):
        return [r for r in doc if "error" not in r]
    return [r for r in doc.get("results", []) if "error" not in r]


def headlines(results: list[dict]) -> dict:
    n = len(results)
    if n == 0:
        return {"n": 0}
    deps = [r.get("transitive_deps") or 0 for r in results]
    scores = [r.get("score_overall") or 0 for r in results]
    def cap_count(k: str) -> int:
        return sum(1 for r in results if (r.get("capabilities") or {}).get(k))

    return {
        "n": n,
        "floating_pct": round(100 * sum(1 for r in results if r.get("floating_direct")) / n),
        "deps_median": int(statistics.median(deps)),
        "deps_max": max(deps),
        "exec_pct": round(100 * cap_count("exec") / n),
        "exfil_pct": round(
            100 * sum(
                1
                for r in results
                if (r.get("capabilities") or {}).get("filesystem")
                and (r.get("capabilities") or {}).get("network_out")
            )
            / n
        ),
        "stdio_pct": round(100 * cap_count("stdio") / n),
        "no_prov_pct": round(100 * sum(1 for r in results if not r.get("provenance")) / n),
        "oidc_pct": round(100 * sum(1 for r in results if r.get("publisher_trusted")) / n),
        "lifecycle": [
            r["package"] for r in results if r.get("install_scripts")
        ],
        "score_median": int(statistics.median(scores)),
        "score_min": min(scores),
        "score_max": max(scores),
    }


def to_markdown(doc: Union[dict, list]) -> str:
    rs = _results(doc)
    h = headlines(rs)
    if h["n"] == 0:
        return "# Corpus report\n\nNo successful audits in this file.\n"
    life = h["lifecycle"]
    life_cell = (
        f"{len(life)} server" + ("s" if len(life) != 1 else "")
        + (f" (`{life[0]}`)" if len(life) == 1 else "")
    )
    lines = [
        "# Corpus report",
        "",
        f"Generated from {h['n']} successful audits.",
        "",
        "## Headline numbers",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Servers audited | {h['n']} |",
        f"| Floating direct dependency ranges | {h['floating_pct']}% of servers |",
        f"| Transitive dependencies | median {h['deps_median']} · max {h['deps_max']} |",
        f"| Process-exec capability in source | {h['exec_pct']}% |",
        f"| Filesystem + outbound network (exfil shape) | {h['exfil_pct']}% |",
        f"| STDIO transport | {h['stdio_pct']}% |",
        f"| No provenance attestation | {h['no_prov_pct']}% |",
        f"| Published via OIDC trusted publishing | {h['oidc_pct']}% |",
        f"| Install-time lifecycle scripts | {life_cell} |",
        f"| Overall score | median {h['score_median']} · spread {h['score_min']}–{h['score_max']} |",
        "",
        "## Scores (low to high)",
        "",
        "| Package | Version | Pkg | Reg | SDK | Overall |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in sorted(rs, key=lambda x: x.get("score_overall", 0)):
        lines.append(
            f"| `{r.get('package')}` | {r.get('version', '')} | "
            f"{r.get('score_package', '')} | {r.get('score_registry', '')} | "
            f"{r.get('score_sdk', '')} | {r.get('score_overall', '')} |"
        )
    lines.append("")
    return "\n".join(lines)
