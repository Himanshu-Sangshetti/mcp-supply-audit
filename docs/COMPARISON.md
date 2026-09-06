# How mcp-supply-audit compares

The MCP security tooling landscape (checked September 2026) is real but young. Different
tools watch different boundaries — most of these complement each other, and this document
says so honestly, because overclaiming is how security tools lose trust.

## The short version

| Tool | Watches | Model | Offline? | Supply-chain depth |
|---|---|---|---|---|
| **mcp-supply-audit** | npm package tree, registry provenance, SDK currency | Open source (MIT) | ✅ fully | ✅ transitive tree + provenance + SDK |
| Snyk Agent Scan (ex-Invariant mcp-scan) | tool descriptions: poisoning, rug-pulls, shadowing | Open source, analysis via Snyk API token | ⚠️ token required | ❌ |
| Cisco mcp-scanner | tool + code intent (YARA, LLM-judge), dep CVEs | Open source (Apache-2.0) | ⚠️ LLM features need keys | ⚠️ CVE-based only |
| MCTS | broad boundary SAST, live probing, attack chains | Open source | ✅ | ⚠️ package vetting, no tree/provenance base rates |
| mcp-guard | capability-gap policy linting | Open source | ✅ | ❌ |
| AgentGate / ToolPin / mcp-lock | tool-surface drift (lockfiles for tools) | Open source | ✅ | ❌ (drift, not posture) |
| Akto MCP Security | runtime discovery + continuous testing | Commercial | — | ❌ |

## What each one taught us

- **Snyk Agent Scan** — description analysis and tool-hash pinning are table stakes now.
  Its move behind an API token is the friction we deliberately avoid: this tool never
  phones home.
- **Cisco mcp-scanner** — multi-engine analysis (static + LLM judge) is where description
  scanning is heading. Their dependency check is CVE-based: it answers "is a known-bad
  version pinned?" — not "how much unverified surface does this tree have?" postmark-mcp
  had no CVEs. That gap is why this tool exists.
- **MCTS** — the most comprehensive scanner; proves practitioners want local-first,
  CI-ready, SARIF-emitting tools. We match that bar and stay in our lane: depth on the
  supply chain instead of breadth across every surface.
- **mcp-guard / windshock's eval lab** — they benchmarked scanners against a capability
  lab and found single-digit-to-teen recall for the big names. Lesson: detection claims
  need published benchmarks. We publish ours (`corpus/`) and its method
  (`docs/METHODOLOGY.md`).
- **Drift gates (AgentGate, ToolPin, mcp-lock)** — pinning a server's tool surface and
  failing CI on change is a control, not a scan. Our tree-hash locking roadmap item is
  the same idea applied to the dependency tree.

## Where we deliberately don't compete

- **Tool-description / prompt-injection analysis** — use Snyk Agent Scan or Cisco
  mcp-scanner. We flag *capability surface*; they flag *manipulative prose*. Both matter;
  they're different layers of the OWASP map (MCP03 vs MCP04).
- **Runtime monitoring** — use a gateway/proxy (Akto, invariant guardrails). We are a
  pre-install / CI-time control.
- **General SAST/SCA** — Semgrep, Trivy, npm-audit answer different questions. Pipe us
  alongside them.

## The honest one-liner

> They ask "is this server trying to trick the model?" We ask "what are you actually
> installing, and can anyone verify where it came from?" You should be asking both.
