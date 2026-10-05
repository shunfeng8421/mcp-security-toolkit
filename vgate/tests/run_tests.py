#!/usr/bin/env python3
"""VGATE regression suite — proves the gate does not lie (xros: no verification, no claim).

Run: python3 tests/run_tests.py  (needs sandbox-runtime on 127.0.0.1:8001)

Tests:
  T1. http_simple 正样本 -> confirmed   (real marker present)
  T2. http_simple 负样本 -> rejected    (wrong marker: gate must NOT fabricate)
  T3. http_chain 正样本   -> confirmed   (2-step chain, health-gated)
  T4. invalid spec        -> exit 1      (schema/semantic gate fires)
  T5. soundness=none      -> engine does NOT run (Tier-C)
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VG = [sys.executable, os.path.join(ROOT, "vgate.py")]

def run_spec(spec_path, do_exec):
    cmd = VG + [spec_path] + (["--exec"] if do_exec else [])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    return r.returncode, r.stdout + r.stderr

def mk_spec(marker, fam="http_simple", exec_code=None):
    base = json.load(open(os.path.join(ROOT, "specs", "v-asr.json"), encoding="utf-8"))
    clean = "".join(c for c in marker if c.isalnum() or c == "-").lower()
    base["id"] = f"v-test-{clean}"
    base["family"] = fam
    # exec_code is what actually runs; evidence checks `marker`. For a true negative,
    # run a marker but assert a DIFFERENT one so stdout does not contain it.
    run_marker = exec_code if exec_code is not None else marker
    base["oracle"] = {
        "mode": "request" if fam == "http_simple" else "steps",
        "request": {"method": "POST", "path": "/v1/run",
                    "body": {"value": f"print('{run_marker}')"}, "expect": "200"},
        "evidence": f"{marker} in {{body.stdout}}",
    }
    return base


# --- health check + skip helper: HTTP tests need a live service; if it's down, SKIP (not FAIL) ---
import urllib.request
def _reachable(port, path="/health", timeout=2):
    try:
        direct = urllib.request.ProxyHandler({}); opener = urllib.request.build_opener(direct)
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False

ASR_OK = _reachable(8001)
AEG_OK = _reachable(8000, "/api/hosts")

def need(name, ok):
    if not ok:
        print(f"SKIP  {name}  (service not reachable — skip, not failure)")
        return False
    return True


results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")

# T1 正样本
if need("T1 http_simple positive -> confirmed", ASR_OK):
    spec = mk_spec("__T1_REAL_MARKER__")
    json.dump(spec, open(os.path.join(ROOT, "specs", "_t1.json"), "w"))
    rc, out = run_spec(os.path.join(ROOT, "specs", "_t1.json"), True)
    check("T1 http_simple positive -> confirmed", '"confirmed"' in out, f"(rc={rc})")

# T2 负样本: 请求体打真marker, evidence查假marker -> stdout不含假marker -> rejected
if need("T2 http_simple negative -> rejected", ASR_OK):
    spec = mk_spec("__T2_NOPE__", exec_code="__T2_REAL__")
    json.dump(spec, open(os.path.join(ROOT, "specs", "_t2.json"), "w"))
    rc, out = run_spec(os.path.join(ROOT, "specs", "_t2.json"), True)
    check("T2 http_simple negative -> rejected", '"rejected"' in out, f"(rc={rc})")

# T3 http_chain
if need("T3 http_chain -> confirmed", ASR_OK):
    rc, out = run_spec(os.path.join(ROOT, "specs", "v-httpchain.json"), True)
    check("T3 http_chain -> confirmed", '"confirmed"' in out, f"(rc={rc})")

# T4 invalid spec
bad = json.load(open(os.path.join(ROOT, "specs", "v-asr.json"), encoding="utf-8"))
bad["soundness"] = "statistical"  # statistical requires ceiling; drop it
bad.pop("ceiling", None)
json.dump(bad, open(os.path.join(ROOT, "specs", "_t4.json"), "w"))
rc, out = run_spec(os.path.join(ROOT, "specs", "_t4.json"), False)
check("T4 statistical w/o ceiling -> INVALID(exit1)", rc == 1, f"(rc={rc})")

# T5 soundness=none -> engine not run
spec = mk_spec("__T5__")
spec["soundness"] = "none"
json.dump(spec, open(os.path.join(ROOT, "specs", "_t5.json"), "w"))
rc, out = run_spec(os.path.join(ROOT, "specs", "_t5.json"), True)
check("T5 soundness=none -> NOT RUN", "NOT RUN" in out, f"(rc={rc})")

# T6 AEG 3-step unauthenticated RCE chain (needs AEG on 127.0.0.1:8000)
if need("T6 http_chain AEG RCE -> confirmed", AEG_OK):
    rc, out = run_spec(os.path.join(ROOT, "specs", "v-aeg-chain.json"), True)
    check("T6 http_chain AEG RCE -> confirmed", '"confirmed"' in out, f"(rc={rc})")

# T7 compute 正样本 (metric 0.73 >= 0.5) -> confirmed
rc, out = run_spec(os.path.join(ROOT, "specs", "v-compute.json"), True)
check("T7 compute positive -> confirmed", '"confirmed"' in out, f"(rc={rc})")

# T8 compute 负样本 (metric 0.30 < 0.5) -> rejected
rc, out = run_spec(os.path.join(ROOT, "specs", "v-compute-below.json"), True)
check("T8 compute negative -> rejected", '"rejected"' in out, f"(rc={rc})")

# T9 file_assert 正样本 (clean axioms) -> confirmed
rc, out = run_spec(os.path.join(ROOT, "specs", "v-file-assert-clean.json"), True)
check("T9 file_assert clean -> confirmed", '"confirmed"' in out, f"(rc={rc})")

print()
fails = [n for n, ok, _ in results if not ok]
print(f"{len(results)-len(fails)}/{len(results)} passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)