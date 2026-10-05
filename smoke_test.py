#!/usr/bin/env python3
"""Smoke test for mcp-security-toolkit — verifies every tool is syntactically valid.

These tools are reference implementations of proven detection patterns, authored in a
specific audit environment (paths like I:/ or D:/ in their bodies point at that
environment's data dirs). They are NOT expected to be runnable in a fresh checkout —
they document HOW to detect a pattern, and the ones that are environment-independent
can be executed directly.

This test therefore:
  1. parses every .py with ast (syntax gate), and
  2. for tools with NO machine-specific absolute paths (portable ones), also runs
     --help to confirm they at least start.

Usage: python3 smoke_test.py   (exit 0 = all pass; nonzero = a tool broke the gate)
"""
import ast
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ABSPATH = re.compile(r"[A-Za-z]:/|/(?:i|d|mnt|home)/")
TOOLS = [f for f in sorted(os.listdir(HERE)) if f.endswith(".py") and f != "smoke_test.py"]

# vgate submodule: every .py must be syntax-valid (it is the verification engine)
VGATE_SUB = os.path.join(HERE, "vgate")
VGATE_FILES = []
if os.path.isdir(VGATE_SUB):
    VGATE_FILES = [os.path.join(VGATE_SUB, f) for f in sorted(os.listdir(VGATE_SUB)) if f.endswith(".py")]

def is_portable(path):
    """True when the tool has no machine-specific absolute path -> runnable anywhere."""
    with open(path, encoding="utf-8") as fh:
        return not ABSPATH.search(fh.read())

failed = []
portable = 0
# syntax-check vgate engine files (they must parse in CI even if they need a live service to run)
for vp in VGATE_FILES:
    try:
        with open(vp, "r", encoding="utf-8") as fh:
            ast.parse(fh.read(), filename=vp)
    except (SyntaxError, UnicodeDecodeError) as e:
        failed.append((os.path.basename(vp), f"vgate syntax/parse: {e}"))

for t in TOOLS:
    p = os.path.join(HERE, t)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            ast.parse(fh.read(), filename=t)
    except (SyntaxError, UnicodeDecodeError) as e:
        failed.append((t, f"syntax/parse: {e}"))
        continue
    if is_portable(p):
        portable += 1
        try:
            r = subprocess.run([sys.executable, p, "--help"],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 1 and "Traceback" in r.stderr:
                failed.append((t, "start failed (import/module error)"))
        except subprocess.TimeoutExpired:
            failed.append((t, "start timed out"))

if failed:
    print("FAILED:")
    for t, why in failed:
        print(f"  - {t}: {why}")
    sys.exit(1)
print(f"OK: {len(TOOLS)} tools syntax-valid; {portable} portable ones also passed start smoke test")