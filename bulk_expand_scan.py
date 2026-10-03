#!/usr/bin/env python3
"""批量扫描 248 候选: 快速克隆 + 高危签名扫描 (2026-09-28 方向B)。
聚焦可本地验证的 Python/TS/JS 0-60★。输出分级表。
"""
import json, subprocess, os, re, sys, concurrent.futures, shutil

BASE = r"I:/audit/expand0928"
os.makedirs(BASE, exist_ok=True)
DATA = json.load(open(r"D:/ll/knowledge-base/10-security/overnight-findings/_expand_repos.json", encoding="utf-8"))

DISCARD = {"jgravelle/jcodemunch-mcp","mifunedev/orchestra"}
def keep(r):
    if r["lang"] not in ("Python","JavaScript","TypeScript"): return False
    if r["stars"]>60: return False
    if r["full_name"] in DISCARD: return False
    return True
cand = [r for r in DATA if keep(r)]

# 高危签名
SIGNS = {
    "shell_exec": r"shell=True|os\.system\(|os\.popen\(|subprocess\.(run|call|Popen)\([^)]*shell=True",
    "cmd_inject_fmt": r"subprocess\.(run|call|Popen|check_output)\(f[\"']|os\.system\(f[\"']|\bPopen\(f[\"']",
    "http_bind": r"(?:host|bind|listen)\s*=\s*[\"']0\.0\.0\.0[\"']|0\.0\.0\.0:\d+|listen\(\s*\d+",
    "fastmcp_http": r"mcp\.run\(transport=[\"']http[\"']|FastMCP\([^)]*transport|run_server_http|streamable.?http",
    "fastapi": r"FastAPI\(|uvicorn\.run|APIRouter\(",
    "no_auth_signal": r"(?:no.?auth|unauthenticated|without.auth|no.?token)[^.\n]{0,40}",
    "ssrf": r"requests\.(get|post|put)\((url|target|link|src)|httpx\.(get|post)\((url|target)|axios\.(get|post)\((url|target)",
    "startswith_path": r"startswith\([^)]*path|str\(path\)\.startswith",
    "sql_exec": r"cursor\.execute\(f|\.execute\(f[\"']|sqlite3\.connect|psycopg|asyncpg|mysql\.connector|aiosqlite",
    "readonly_gate": r"startswith\([^)]*['\"](select|with)|read_heads|allowed_start|SELECT\s+ONLY",
    "token_in_source": r"api[_-]?key\s*=\s*[\"'][A-Za-z0-9]{16,}|Bearer\s+[A-Za-z0-9._-]{20,}",
}

def clone(repo):
    target = os.path.join(BASE, repo.replace("/", "__"))
    if os.path.exists(target) and os.path.isdir(target):
        return target
    r = subprocess.run(["git","clone","--depth","1","-q",f"https://github.com/{repo}.git",target],
        capture_output=True, text=True, timeout=120)
    return target if r.returncode==0 else None

def scan(repo):
    # 防御: 入口可能是 dict (全量) 或 string (修复前 bug 来源), 统一取 full_name
    if isinstance(repo, dict):
        repo = repo.get("full_name") or repo.get("fullName") or ""
    if not repo:
        return (str(repo), {"clone": False})
    t = clone(repo)
    if not t: return (repo, {"clone":False})
    hits = {}
    # 只扫源码文件 (排除 node_modules/venv/dist)
    for root, dirs, fs in os.walk(t):
        dirs[:] = [d for d in dirs if d not in ("node_modules",".git","venv",".venv","dist","build","__pycache__","site-packages")]
        for f in fs:
            if not f.endswith((".py",".js",".ts",".go",".rb",".sh")): continue
            fp = os.path.join(root,f)
            try:
                with open(fp,encoding="utf-8",errors="ignore") as fh: code=fh.read()
            except Exception: continue
            for name,pat in SIGNS.items():
                if re.search(pat, code, re.S):
                    hits.setdefault(name,[]).append(os.path.relpath(fp,t)[:80])
    return (repo, {"clone":True, "hits":hits})

def main():
    print(f"扫描 {len(cand)} 候选...", flush=True)
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for repo,info in ex.map(lambda r: scan(r["full_name"]), cand):
            results[repo]=info
    # 分级: 高价值 = shell_exec/cmd_inject_fmt + http_bind/fastmcp_http/fastapi
    high = []
    med = []
    for repo,info in results.items():
        if not info.get("clone"): continue
        h=info.get("hits",{})
        score = len(h)
        has_exec = "shell_exec" in h or "cmd_inject_fmt" in h
        has_net = any(k in h for k in ("http_bind","fastmcp_http","fastapi"))
        has_db = "sql_exec" in h
        if has_exec and (has_net or has_db): high.append((repo,h))
        elif has_net and has_db: high.append((repo,h))
        elif has_exec or has_net: med.append((repo,h))
    print(f"\n=== 高危候选 {len(high)} ===")
    for repo,h in sorted(high,key=lambda x:sum(len(v) for v in x[1].values()),reverse=True):
        print(f"  {repo}")
        for k,v in list(h.items())[:6]:
            print(f"      {k}: {v[:2]}")
    print(f"\n=== 中危候选 {len(med)} ===")
    for repo,h in med:
        print(f"  {repo}: {','.join(sorted(h.keys()))[:80]}")
    json.dump(results, open(os.path.join(BASE,"scan_results.json"),"w",encoding="utf-8"),ensure_ascii=False,indent=2)
    print(f"\n结果存 {BASE}/scan_results.json")

if __name__=="__main__":
    main()
