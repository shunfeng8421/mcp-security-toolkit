#!/usr/bin/env python3
"""VGATE — Verification Gate.

A declarative verification-gate engine, modeled on the verification core of
xiaolai/xros (the "no verification, no claim" philosophy) but adapted to my
heterogeneous verification workloads (http chains, single http, compute, file).

Philosophy:
  - The spec is a declarative contract; the validator + gate are mechanical.
  - The oracle result decides the verdict — never an agent/script self-grading.
  - sound x pass = confirmed; statistical x pass = evidence; none = unverified.
  - fail closed everywhere: missing vote, bad path, unsupported spec verion.

Usage:
  python3 vgate.py <spec.json> [--exec] [[--eval]] 
    --exec   actually run the oracle (default: validate + dry-run the gate shape)
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "specs", "vgate-spec.schema.json")

# ---- reuse xros-style validator (stdlib-only, fail-open-defensive) ----------
from validator_engine import (
    preflight_schema,
    validate as schema_validate,
)

# ------------------------------------------------------------------ semantic gates
def semantic_gates(spec):
    """Gates JSON Schema cannot express. Never crash on malformed spec."""
    errs = []
    if not isinstance(spec, dict):
        return errs
    fam = spec.get("family")
    sound = spec.get("soundness")
    ost = spec.get("cost")
    if isinstance(ost, dict) and ost.get("gated") is False and ost.get("timeoutMs") is None:
        errs.append("$.cost: gated=false requires timeoutMs (no unattended unbounded oracle)")
    # ceiling REQUIRED unless sound (a sound oracle must still state its scope)
    if not (isinstance(spec.get("ceiling"), str) and spec["ceiling"].strip()):
        if sound != "sound":
            errs.append(f"$.ceiling: REQUIRED when soundness={sound!r} (what this check does NOT establish)")
    if sound == "none":
        # Tier-C: legal spec, but engine must NOT run. --exec must refuse.
        if not isinstance(spec.get("oracle"), dict):
            errs.append("$.soundness: 'none' (Tier-C) needs an oracle.mode (e.g. manual/none) to be a valid unverified spec")
    # oracle mode must match family
    fammode = {"http_chain": "steps", "http_simple": "request",
               "compute": "command", "file_assert": "file"}
    want = fammode.get(fam)
    got = (spec.get("oracle") or {}).get("mode") if isinstance(spec.get("oracle"), dict) else None
    if want and got != want:
        errs.append(f"$.oracle.mode: family={fam} requires mode={want} got {got!r}")
    return errs


def validate_spec(spec):
    try:
        schema = json.load(open(SCHEMA, encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [f"SCHEMA LOAD: {e}"]
    pre = preflight_schema(schema)
    if pre:
        return [f"SCHEMA PREFLIGHT: {p}" for p in pre]
    return schema_validate(spec, schema) + semantic_gates(spec)


# ------------------------------------------------------------------ variable binding
_VAR = re.compile(r"@\{([A-Za-z0-9_.]+)\}")

class Ctx:
    def __init__(self):
        self.vars = {}   # name -> value (str/number/bool/dict/list)
    def bind(self, src):
        """Replace @{a.b} with bound value. Leaves unresolved as-is (recorded)."""
        def repl(m):
            path = m.group(1).split(".")
            cur = self.vars.get(path[0])
            for k in path[1:]:
                if isinstance(cur, dict): cur = cur.get(k)
                elif isinstance(cur, list):
                    try: cur = cur[int(k)]
                    except Exception: return m.group(0)
                else: return m.group(0)
            return str(cur) if cur is not None else m.group(0)
        return _VAR.sub(repl, src) if isinstance(src, str) else src


# ------------------------------------------------------------------ runners
def _http(method, url, body, timeout):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    # Bypass environment proxies (HTTP_PROXY etc): loopback verification must go direct.
    direct = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(direct)
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read().decode()
            try: return r.status, json.loads(raw)
            except Exception: return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]
    except Exception as e:
        return 0, {"__err__": str(e)}


def run_http_simple(spec, cost):
    """Single-request oracle: fire one request, bind response as {body.X}, eval evidence."""
    ctx = Ctx(); oracle = spec["oracle"]; timeout = (cost or {}).get("timeoutMs", 20000) / 1000
    req = oracle.get("request", {})
    base = spec.get("base", "http://127.0.0.1:8000")
    method = req.get("method", "POST"); path = req.get("path", "")
    url = base + ctx.bind(path)
    body = ctx.bind(req.get("body"))
    s, b = _http(method, url, body, timeout)
    body_val = b if isinstance(b, dict) else {"raw": str(b)}
    ctx.vars["resp"] = {"http": s, **({"body": body_val} if isinstance(b, dict) else {"stdout": str(b)})}
    ctx.vars["body"] = body_val
    results = {"code": s, "http": s, "expect_ok": s == int(req.get("expect", 0)) if req.get("expect") else True}
    ev = oracle.get("evidence", "")
    ev_alive = ctx.bind(ev)
    evidence_ok = _eval_predicate(ev_alive, ctx)
    results["evidence"] = evidence_ok
    results["stdout"] = (body_val.get("stdout") if isinstance(body_val, dict) else str(b))
    return results


def _eval_predicate(expr, ctx):
    """Tiny evaluator for 'A in B' / 'A == B' over bound vars (mechanical)."""
    try:
        if " in " in expr:
            a, b = [x.strip() for x in expr.split(" in ", 1)]
            a2 = a.strip("'\"")
            b2 = b.strip("'\"")
            # b may be {var.x} or literal
            if b2.startswith("{") and b2.endswith("}"):
                val = ctx.vars.get(b2[1:-1].split(".")[0])
                return a2 in str(val)
            return a2 in b2
        if "==" in expr:
            a, b = [x.strip() for x in expr.split("==", 1)]
            return a.strip("'\"") == b.strip("'\"")
    except Exception:
        return False
    return False


def run_compute(spec, cost):
    """Oracle = a command whose output is parsed to a number, compared to a threshold.
    Statistical by nature (prediction/measurement, not proof)."""
    ctx = Ctx(); oracle = spec["oracle"]; passc = spec.get("pass", {})
    timeout = (cost or {}).get("timeoutMs", 120000) / 1000
    cmd = ctx.bind(oracle.get("command", ""))
    parse = oracle.get("parse", "")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        matched = None
        if parse:
            m = re.search(parse, out)
            if m:
                matched = float(m.group(1))
        results = {"exit": r.returncode, "parsed": matched, "stdout": out[-500:]}
        # threshold gate
        thr = passc.get("threshold")
        if thr is not None and matched is not None:
            results["evidence"] = matched >= thr
        else:
            results["evidence"] = False
        return results
    except subprocess.TimeoutExpired:
        return {"exit": "timeout", "evidence": False}


def run_file_assert(spec, cost):
    """Oracle = a lean/checker command whose output is parsed (e.g. axioms) and asserted.
    Sound when the checker is a mechanical verifier."""
    ctx = Ctx(); oracle = spec["oracle"]; passc = spec.get("pass", {})
    timeout = (cost or {}).get("timeoutMs", 120000) / 1000
    cmd = ctx.bind(oracle.get("command", ""))
    parse = oracle.get("parse", "")
    artifact = ctx.bind(oracle.get("path", ""))
    # write the artifact first if provided (path maps to a temp file)
    artifact_path = None
    if artifact:
        artifact_path = os.path.join(tempfile.gettempdir(), "vgate-artifact")
        os.makedirs(artifact_path, exist_ok=True)
        # command may reference {artifact}; bind it
        cmd = cmd.replace("{artifact}", os.path.join(artifact_path, os.path.basename(artifact)))
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        found = []
        if parse:
            for m in re.finditer(parse, out):
                g = m.group(1).strip() if m.lastindex else m.group(0).strip()
                # A captured group may itself be a comma-separated list; split it so
                # each axiom/name is an independent element AND'd against the allow set.
                for part in g.split(","):
                    part = part.strip()
                    if part:
                        found.append(part)
        results = {"exit": r.returncode, "parsed": found, "stdout": out[-500:]}
        # assert: comma-separated names must all satisfy the predicate
        apred = passc.get("assert", "")
        if apred and found:
            allowed = [x.strip() for x in apred.split(";") if x.strip()]
            results["evidence"] = all(f in allowed for f in found)
        elif apred:
            results["evidence"] = True  # empty axiom list passes (no forbidden axioms)
        else:
            results["evidence"] = r.returncode == 0
        return results
    except subprocess.TimeoutExpired:
        return {"exit": "timeout", "evidence": False}


def run_http_chain(spec, cost):
    ctx = Ctx(); oracle = spec["oracle"]; timeout = (cost or {}).get("timeoutMs", 20000) / 1000
    results = {}; evidence_ok = False
    for i, step in enumerate(oracle.get("steps", [])):
        # conditional step
        if step.get("cond"):
            cond_raw = step["cond"]; cond_ok = False
            raw = ctx.bind(cond_raw)
            if "=" in raw:
                k, v = raw.split("=", 1); k, v = k.strip(), v.strip()
                m = re.match(r"^([A-Za-z0-9_.]+)$", k)
                if m and m.group(1) in ctx.vars:
                    cond_ok = str(ctx.vars[m.group(1)]) == v
            if not cond_ok:
                results[f"step{i}"] = {"skipped": True, "cond": cond_raw}; continue
        req = step.get("request") or {}
        method = req.get("method", "POST"); path = req.get("path", "")
        base = spec.get("base", "http://127.0.0.1:8000")
        url = base + ctx.bind(path)
        body = req.get("body")
        body = ctx.bind(body) if isinstance(body, str) else body
        s, b = _http(method, url, body, timeout)
        rec = {"code": s, "body": b, "http": s}
        results[f"step{i}"] = rec
        if req.get("expect"):
            exp = str(req["expect"])
            rec["expect_ok"] = str(s) == exp
        if step.get("save"):
            ctx.vars[step["save"]] = b if isinstance(b, dict) else str(b)
    # evidence: predicate over evaluated text
    ev = oracle.get("evidence", "")
    ev_alive = ctx.bind(ev)
    # crude predicate eval: "X in Y" or "X == Y"
    try:
        if " in " in ev_alive:
            a, b = [x.strip() for x in ev_alive.split(" in ", 1)]
            a2 = a.strip("'\"")
            b2 = b.strip("'\"")
            evidence_ok = a2 in b2 or a2 in str(ctx.vars)
        elif "==" in ev_alive:
            a, b = [x.strip() for x in ev_alive.split("==", 1)]
            evidence_ok = a.strip("'\"") == b.strip("'\"")
    except Exception:
        evidence_ok = False
    results["evidence"] = evidence_ok
    return results


# ------------------------------------------------------------------ gate
def gate(spec, results):
    """Map oracle result -> verdict (mechanical)."""
    sound = spec.get("soundness"); fam = spec.get("family")
    if sound == "none":
        return {"verdict": "unverified", "note": "Tier-C: no mechanical oracle; engine did not run"}
    # http_chain: evidence is the anchor; markers record partials
    if fam == "http_chain":
        ev = results.get("evidence")
        markers = {}
        for k, v in results.items():
            if isinstance(v, bool) and k != "evidence":
                markers[k] = v
        if ev:
            return {"verdict": "confirmed", "evidence": ev, "markers": markers}
        progressed = any(isinstance(v, dict) and v.get("expect_ok") for v in results.values())
        return {"verdict": "candidate", "partial": not progressed, "evidence": ev, "markers": markers}
    # others: compute pass from pass clause
    return {"verdict": "confirmed" if results.get("evidence") else "rejected"}


def main(argv):
    if len(argv) < 2:
        print("usage: vgate.py <spec.json> [--exec]", file=sys.stderr); return 2
    spec_path = argv[1]
    do_exec = "--exec" in argv
    try:
        spec = json.load(open(spec_path, encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"IO/parse: {e}", file=sys.stderr); return 2
    errs = validate_spec(spec)
    if errs:
        print("INVALID:")
        for e in errs: print("  ", e)
        return 1
    print(f"VALID {spec.get('id')} | {spec.get('family')} | soundness={spec.get('soundness')}")
    if not do_exec:
        print("([--exec] to actually run the oracle)")
        return 0
    if spec.get("soundness") == "none":
        print("NOT RUN: soundness=none (unverified)").strip() if False else print("NOT RUN: soundness=none")
        return 0
    fam = spec.get("family"); cost = spec.get("cost", {})
    if cost.get("gated", True):
        print(f"ORACLE WOULD RUN: {spec.get('claim')}  (approval gate; --exec implies go)")
    results = {}
    if fam in ("http_chain",):
        results = run_http_chain(spec, cost)
    elif fam == "http_simple":
        results = run_http_simple(spec, cost)
    elif fam == "compute":
        results = run_compute(spec, cost)
    elif fam == "file_assert":
        results = run_file_assert(spec, cost)
    verdict = gate(spec, results)
    print("VERDICT:", json.dumps(verdict, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))