#!/usr/bin/env python3
"""vgate bridge: turn a scanner's candidate list into fillable vgate spec skeletons.

Scanner output (bulk_*.py) is human text: "候选 N / 疑似命令注入 M / repo: [file:line sig]".
This bridge:
  1. reads a structured candidates.json produced by the scanner (name/signal),
  2. emits one vgate spec skeleton per candidate, tuned to its signal family
     (command-injection -> http_simple exec template, read-only-gate -> http_simple
     SQL template, etc), with the oracle left as a declared step for a human/compiler
     to fill in against the repo's actual endpoint.

This is the seam that connects "finding candidates" (scanners) to "confirming them"
(vgate). It does NOT auto-confirm — it scaffolds the confirmation.
"""
import json
import os
import sys

# signal family -> spec skeleton (oracle is a declared intent to be filled per-repo)
TEMPLATES = {
    "command-injection": {
        "family": "http_simple",
        "claim": "REPLACE: asserts <repo> executes attacker-influenced command without sanitization",
        "soundness": "sound",
        "ceiling": "Loopback-only; does not establish remote exploitability unless service is on 0.0.0.0.",
        "base": "http://127.0.0.1:PORT",
        "oracle": {
            "mode": "request",
            "request": {"method": "POST", "path": "REPLACE /endpoint",
                        "body": {"cmd": "__MARKER__"}, "expect": "200"},
            "evidence": "__MARKER__ in {body.stdout}",
        },
        "pass": {"mode": "assert"},
    },
    "no-auth-gateway": {
        "family": "http_chain",
        "claim": "REPLACE: asserts unauthenticated access to control surface of <repo>",
        "soundness": "sound",
        "ceiling": "Loopback-only; remote if bound 0.0.0.0.",
        "base": "http://127.0.0.1:PORT",
        "oracle": {
            "mode": "steps",
            "steps": [
                {"request": {"method": "GET", "path": "REPLACE /api/..."}, "expect": "200", "save": "s1", "name": "unauth_read"},
                {"request": {"method": "POST", "path": "REPLACE /api/...", "body": {}}, "expect": "2xx", "save": "s2", "name": "unauth_write"},
            ],
            "evidence": "REPLACE predicate",
        },
        "pass": {"mode": "chain"},
    },
    "read-only-gate-bypass": {
        "family": "http_simple",
        "claim": "REPLACE: asserts <repo> read-only gate lets a write SQL through",
        "soundness": "sound",
        "ceiling": "DB-dependent.",
        "base": "http://127.0.0.1:PORT",
        "oracle": {
            "mode": "request",
            "request": {"method": "POST", "path": "REPLACE /query",
                        "body": {"sql": "WITH c AS (...) INSERT INTO t ..."}, "expect": "200"},
            "evidence": "REPLACE effect predicate",
        },
        "pass": {"mode": "assert"},
    },
}


def scaffold(candidates_path, out_dir):
    cands = json.load(open(candidates_path, encoding="utf-8"))
    items = cands if isinstance(cands, list) else cands.get("candidates", cands.get("items", []))
    os.makedirs(out_dir, exist_ok=True)
    specs = []
    for i, c in enumerate(items):
        sig = c.get("signal") or c.get("pattern") or c.get("type") or "command-injection"
        fam = sig.split("_")[0].lower()
        if "injection" in sig or "rce" in sig or "shell" in sig:
            fam = "command-injection"
        elif "read.only" in sig or "gate" in sig or "sql" in sig:
            fam = "read-only-gate-bypass"
        else:
            fam = "no-auth-gateway"
        tpl = json.loads(json.dumps(TEMPLATES.get(fam, TEMPLATES["no-auth-gateway"])))  # deep copy
        name = c.get("name") or c.get("repo") or f"cand{i}"
        clean = "".join(ch for ch in name.lower() if ch.isalnum() or ch == "-")
        spec = {
            "schemaVersion": "1.0.0",
            "id": f"v-{clean[:40]}-scaffold",
            "title": f"scaffold: {c.get('title', c.get('name', name))} ({sig})",
            "family": tpl["family"],
            **{k: v for k, v in tpl.items() if k in ("soundness", "ceiling", "base", "oracle", "claim", "pass")},
            "provenance": {"from": c.get("signature") or c.get("path"), "scanner_seed": True},
        }
        out = os.path.join(out_dir, f"{clean[:40]}.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(spec, f, ensure_ascii=False, indent=2)
        specs.append(out)
    print(f"scaffolded {len(specs)} vgate spec skeletons -> {out_dir}/")
    for s in specs:
        print("  ", os.path.basename(s))
    return specs


def main(argv):
    if len(argv) < 3:
        print("usage: bridge.py <candidates.json> <out_dir>", file=sys.stderr); return 2
    scaffold(argv[1], argv[2])
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))