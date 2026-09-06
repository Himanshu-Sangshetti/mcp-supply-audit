"""Rationale + remediation for each MSA-* finding. Offline, no network."""
from .scoring import FINDINGS, SEVERITY_ORDER

# id -> (why, what to do). Keep honest: heuristic, not proof.
_EXPLAIN: dict[str, tuple[str, str]] = {
    "MSA-P001": (
        "Each unique transitive package is code you did not write and likely did not read. "
        "The corpus median is 95; >100 is the upper half of that sample.",
        "Pin direct ranges, drop unused deps, prefer smaller trees. Re-audit after each add.",
    ),
    "MSA-P002": (
        "^ / ~ / * re-resolves on the next install. A maintainer (or a hijack) can ship new code "
        "without your lockfile noticing if you do not have one.",
        "Pin exact versions or use --lock / --check so silent moves fail CI.",
    ),
    "MSA-P003": (
        "Published source contains process-execution APIs (child_process, spawn, subprocess). "
        "A filesystem server may need this; it is still an execution surface (MCP05).",
        "Confirm the server must exec. Do not pass untrusted strings into the launch command.",
    ),
    "MSA-P004": (
        "Filesystem read plus outbound network is the postmark-mcp shape: read something, send it. "
        "Intent is not proven — many legitimate servers do both.",
        "Restrict network egress; treat tool output as untrusted; prefer servers that do one or the other.",
    ),
    "MSA-P005": (
        "Env reads plus outbound network can leak tokens. Same caveat: signal, not proof of theft.",
        "Run with a minimal env. Do not put long-lived secrets in the process environment.",
    ),
    "MSA-P006": (
        "eval / new Function in published source is dynamic code execution (MCP05). "
        "Minifiers can inflate this; still worth a look.",
        "Prefer packages without runtime eval. If it is a parser, isolate it.",
    ),
    "MSA-P007": (
        "preinstall / install / postinstall run on the consumer machine during npm install. "
        "The server never has to start — installing is enough (the E10 attack).",
        "Do not install packages with unexpected lifecycle scripts. Use --ignore-scripts only as a temporary brake.",
    ),
    "MSA-P008": (
        "prepare runs for git-dependency and local installs, not for a normal registry install.",
        "Treat git-url dependencies as higher risk; prefer registry tarballs.",
    ),
    "MSA-P009": (
        "atob / base64 Buffer / fromCharCode / dense hex escapes look like decode-then-run. "
        "We do not decode or emulate. Score-neutral.",
        "Read the flagged file. If it is a packed vendor bundle, expect noise.",
    ),
    "MSA-P010": (
        "Source mentions a known paste/tunnel/OOB/sink host (webhook.site, giftshop.club, …). "
        "Heuristic host list. Score-neutral.",
        "If the host is not a documented integration, do not install. Diff versions with --diff.",
    ),
    "MSA-P011": (
        "An install-time script curls/wgets/pipes to a shell, or postinstall.js has outbound network. "
        "Installing is enough. Score-neutral on top of P007.",
        "Do not install. Inspect the hook file. Prefer packages with empty scripts.",
    ),
    "MSA-R001": (
        "No npm provenance attestation — the tarball is not linked to a public CI run and commit. "
        "70% of the corpus looks like this. Absence is not an accusation.",
        "Prefer packages that publish with npm provenance. You cannot add this as a consumer.",
    ),
    "MSA-R002": (
        "No registry signatures on the artifact. Lower signal than missing provenance.",
        "Same as R001 — a publisher-side control.",
    ),
    "MSA-R003": (
        "Published from a personal account, not OIDC trusted publishing. Plenty of good servers are.",
        "A publisher-side control. Do not treat a personal account as malice.",
    ),
    "MSA-S001": (
        "STDIO transport: the agent launches a process and speaks on stdin/stdout. "
        "Untrusted input must never reach the launch command (OX / STDIO foot-gun).",
        "Pin the command and args. Never interpolate user or tool text into the spawn line.",
    ),
    "MSA-S002": (
        "Resolved @modelcontextprotocol/sdk is behind the registry latest (major or minor).",
        "Bump the SDK range and re-audit. Check the SDK changelog for transport/auth fixes.",
    ),
    "MSA-S003": (
        "The SDK dependency is a floating range, so the next install can move it.",
        "Pin the SDK or --lock the tree.",
    ),
    "MSA-S004": (
        "No @modelcontextprotocol/sdk dependency — custom, Python, or other implementation. "
        "SDK-currency checks do not apply; we mark it INFO.",
        "Audit that implementation on its own terms. For PyPI use --ecosystem pypi (thin slice).",
    ),
    "MSA-D001": (
        "A lifecycle script appeared between the two versions you diffed. Rug-pull / E10 shape.",
        "Do not upgrade. Diff the tarball. This is the highest-signal version change we flag.",
    ),
    "MSA-D002": (
        "The npm publisher account changed between versions. Account-takeover or ownership transfer.",
        "Confirm the transfer on the registry/GitHub before installing the new version.",
    ),
    "MSA-D003": (
        "Provenance was present and then dropped. Build origin is no longer verifiable.",
        "Ask why. Prefer the last attested version until it returns.",
    ),
    "MSA-D004": (
        "exec or eval capability newly appeared in published source between versions.",
        "Read the new files. --diff is the postmark-shaped detector for capability adds.",
    ),
    "MSA-D005": (
        "Filesystem + network newly combined between versions — the exfil shape appeared.",
        "Same as P004, but it is new. Treat as a breaking trust change.",
    ),
    "MSA-D006": (
        "The resolved unique-package tree grew. New unread code arrived with the bump.",
        "Inspect the added names. Pin if the growth is a surprise.",
    ),
}


def explain(fid: str) -> str:
    """Human text for one finding id. Raises KeyError if unknown."""
    key = fid.strip().upper()
    if key not in FINDINGS:
        raise KeyError(key)
    sev, layer, owasp, template = FINDINGS[key]
    why, fix = _EXPLAIN[key]
    return (
        f"{key}  {sev}  [{layer}]  {owasp}\n"
        f"  signal: {template}\n"
        f"  why:    {why}\n"
        f"  do:     {fix}\n"
    )


def explain_all() -> str:
    keys = sorted(FINDINGS, key=lambda k: (-SEVERITY_ORDER[FINDINGS[k][0]], k))
    return "".join(explain(k) + "\n" for k in keys)


def known_ids() -> list[str]:
    return sorted(FINDINGS)
