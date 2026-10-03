#!/usr/bin/env python3
"""sim只读: 批量扫描 MCP 仓库的命令注入面 (v2, 扩大池+排除test/example误报)."""
import os, re, subprocess, sys, json

BASE = r"I:/audit/cmdscan2"
os.makedirs(BASE, exist_ok=True)

# 只匹配真正的 run_command(f" 或 subprocess...(f" 拼接 (含 shell=True)
RCE_PATS = [
    re.compile(r'subprocess\.(run|call|Popen|check_output|check_call)\(\s*f["\']', re.S),
    re.compile(r'os\.system\(\s*f["\']'),
    re.compile(r'os\.popen\(\s*f["\']'),
    re.compile(r'run_command\(\s*f["\']'),
    re.compile(r'subprocess\.(run|call|Popen|check_output|check_call)\([^)]*shell\s*=\s*True'),
]

def gh_search(limit=60):
    # 多个关键词面扩大池
    queries = [
        "mcp-server language:python pushed:>2026-09-01 stars:0..60",
        "mcp server language:python pushed:>2026-09-01 stars:0..60 shell",
        "fastmcp language:python pushed:>2026-09-01 stars:0..60",
    ]
    seen = {}
    for q in queries:
        r = subprocess.run(["gh","api","--method","GET","search/repositories",
            "-f", f"q={q}", "-f","per_page=20","-f","sort=updated"],
            capture_output=True, text=True, timeout=60)
        if r.returncode: continue
        try:
            d = json.loads(r.stdout)
        except: continue
        for i in d.get("items", []):
            seen.setdefault(i["full_name"], (i.get("description") or ""))
    return list(seen.items())

def clone(repo):
    t = os.path.join(BASE, repo.replace("/","__"))
    if os.path.exists(t): return t
    r = subprocess.run(["git","clone","--depth","1","-q", f"https://github.com/{repo}.git", t],
        capture_output=True, text=True, timeout=90)
    return t if r.returncode==0 else None

def scan(target, repo):
    hits=[]
    for root, dirs, fs in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ("__pycache__",".git","venv",".venv","node_modules","test","tests","examples")]
        for f in fs:
            if not f.endswith(".py"): continue
            fp = os.path.join(root, f)
            try:
                code = open(fp, encoding="utf-8", errors="ignore").read()
            except: continue
            for pat in RCE_PATS:
                for m in pat.finditer(code):
                    ln = code.count("\n",0,m.start())+1
                    lines = code.splitlines()
                    ctx = lines[ln-1].strip()[:130] if ln-1<len(lines) else ""
                    hits.append((f, ln, ctx))
    return hits

def main():
    repos = gh_search()
    print(f"候选池 {len(repos)}")
    interesting=[]
    for repo, desc in repos:
        t = clone(repo)
        if not t: continue
        hits = scan(t, repo)
        if hits:
            uniq = set((f,l) for f,l,_ in hits)
            print(f"\n🔴 {repo} ({len(uniq)} 命中)")
            for f,l,c in hits[:6]:
                print(f"    {f}:{l} {c}")
            interesting.append((repo, hits))
    print(f"\n=== 疑似命令注入 {len(interesting)} 个 ===")
    for repo,_ in interesting: print(" ", repo)

if __name__=="__main__":
    main()