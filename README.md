# MCP / Agent Security Toolkit

Runtime-verified **detection tools** for auditing MCP (Model Context Protocol) and AI-agent ecosystem repositories. Each tool encodes a specific, proven vulnerability pattern and a grading scheme that separates *sloppy* (vulnerable) from *hardened* (safe) implementations.

All patterns below were discovered and **runtime-confirmed** against real, isolated server instances (loopback, 127.0.0.1, no credentials, no real assets). See the companion research repo [mcp-agent-security-papers](https://github.com/shunfeng8421/mcp-agent-security-papers) for the papers (#24/#25/#26) and the four confirmed disclosures.

---

## Scanners (GitHub batch auditing)

| Tool | Pattern | Description |
|---|---|---|
| `bulk_readonly_gate_scan.py` | CWE-281 (read-only gate bypass) | Detects SQL/DB MCP servers whose "read-only" gate relies on `startswith` / first-word classification (letting `SELECT INTO`, `WITH ... INSERT` slip through), with no AST parse and no connection-level `mode=ro`. Proven against `db-connector`. |
| `bulk_ssrf_scan.py` | CWE-918 (SSRF) | Scans for URL-accepting tools that `httpx.get(url)` / `requests.get(url)` without allowlist/domain constraint. |
| `bulk_subprocess_scan.py` / `bulk_subprocess_scan2.py` | CWE-78 (command injection) | Detects `shell=True` subprocess calls where the command is an f-string built from request parameters with no escaping/allowlist. Proven against `kali-mcp` (remote RCE) and `py-mcps`. |
| `bulk_expand_scan.py` | candidate discovery | Broad GitHub query expansion (fresh-band starvation escape): keyword variants, `pushed>` recency, tool names, TS/JS surfaces. |

## Supply-chain probes

| Tool | Pattern | Description |
|---|---|---|
| `scan_pypi.py` | typosquat / poison | Enumerates PyPI MCP packages, checks names against known official packages, flags suspicious. |
| `scan_npm.py` | typosquat / poison | Same for npm; also detects the npm `security-hold` mechanism (official lock on easily-impersonated `mcp-server-*` names). |
| `typosquat_probe.py` | typosquat | Probes near-miss names of known packages. |

## Runtime verification

| Tool | Pattern | Description |
|---|---|---|
| `mcp_readonly_trust_test.py` | MCP trust-label spoof | Black-box proof that a malicious MCP server can declare a destructive tool `readOnlyHint=true`/`destructiveHint=false` + benign description, and the official Python SDK forwards it verbatim (no safety interception). Core evidence for paper #25. |

---

## Grading philosophy (honest, reproducible)
1. **Do not** report a finding without runtime confirmation on an isolated loopback instance.
2. **Separate** *vulnerable* (sloppy gate / no auth / no escaping) from *hardened* (AST parse / connection read-only / allowlist / token gate / fail-closed).
3. **Flag** deployment-dependent impact explicitly (`0.0.0.0` bind vs `127.0.0.1`); never exaggerate remoteness or RCE.
4. Each tool is small, single-file, stdlib-only (some use `gh` CLI for discovery).

## Environment
- Python 3.10+, no heavy deps (stdlib + optionally `sqlparse`/`sqlglot` for the strong-gate detector).
- `gh` CLI authenticated for GitHub discovery.
- Audit output goes to an isolated directory (default `I:/audit/...`); never touches real assets.

## Cite
See `CITATION.cff` in the companion papers repo. License: CC-BY-4.0. Contributions welcome via issues/PRs.
