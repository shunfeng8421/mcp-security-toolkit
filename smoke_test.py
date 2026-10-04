#!/usr/bin/env python3
"""Smoke test for mcp-security-toolkit — verifies every tool loads and has valid CLI.

Usage: python3 smoke_test.py  (exit 0 = all pass; nonzero = a tool failed)
CI:   python3 smoke_test.py
"""
import ast
import importlib.util
import sys
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = [
    "bulk_readonly_gate_scan.py",
    "bulk_ssrf_scan.py",
    "bulk_subprocess_scan.py",
    "bulk_subprocess_scan2.py",
    "bulk_expand_scan.py",
    "scan_pypi.py",
    "scan_npm.py",
    "typosquat_probe.py",
    "mcp_readonly_trust_test.py",
]

def check_syntax(path):
    with open(path, "rb") as f:
        ast.parse(f.read(), filename=path)
    return True

def check_cli_help(path):
    # most tools print usage when called with no args (and exit nonzero) — just
    # confirm they at least start the interpreter without a ModuleNotFoundError
    r = subprocess.run([sys.executable, path, "--help"],
                       capture_output=True, text=True, timeout=30)
    # exit 2 from argparse/argparse-style is fine; exit 1 with an import
    # traceback is a real failure.
    if r.returncode == 1 and "Traceback" in r.stderr:
        return False
    return True

failed = []
for t in TOOLS:
    p = os.path.join(HERE, t)
    try:
        check_syntax(p)
    except SyntaxError as e:
        failed.append((t, f"syntax: {e}"))
        continue
    try:
        if not check_cli_help(p):
            failed.append((t, "CLI start failed (import/module error)"))
    except subprocess.TimeoutExpired:
        failed.append((t, "CLI timed out"))

if failed:
    print("FAILED:")
    for t, why in failed:
        print(f"  - {t}: {why}")
    sys.exit(1)
print(f"OK: {len(TOOLS)} tools pass syntax + CLI-start smoke test")
