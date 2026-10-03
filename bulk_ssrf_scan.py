#!/usr/bin/env python3
"""批量检测 MCP 仓库的 SSRF / 任意 URL fetch 面 (2026-09-23).

高危模式: 工具参数(url/endpoint/target) 直接进 HTTP 客户端(httpx/requests/urllib/aiohttp),
无内网拦截(拒绝 localhost/169.254.169.254/10.x/192.168/172.16) = SSRF.

分级:
  🔴 SSRF 疑似: 用户 URL 直进请求, 无内网拦截
  🟡 有 URL fetch 但可疑(参数化/有防护/固定域名)
  ⚪ 有 http client 但 URL 固定/安全
  ⚫ 无 fetch 面

用法: python bulk_ssrf_scan.py
只读: 不写外部, 克隆 I:/audit/ssrfscan/.
"""
import os, re, subprocess, sys, json

BASE = r"I:/audit/ssrfscan"
os.makedirs(BASE, exist_ok=True)

# HTTP 客户端调用, 第一个/url 位置可能来自用户参数
HTTP_CALL = re.compile(
    r"(httpx|requests|urllib\.request|aiohttp|urllib3|http\.Client|curl)\.\w*\("
    r"([^)]*)", re.S)
URL_PARAM_HINT = re.compile(r"url|endpoint|target|uri|link|fetch|remote", re.I)
# SSRF 防护信号 (存在则缓解)
SSRF_GUARD = re.compile(
    r"(?i)localhost|127\.0\.0\.1|169\.254|metadata\.google|169\.254\.169\.254"
    r"|private[_ ]?ip|block.*(private|loopback|internal)|_is_private|is_private"
    r"|allowlist|whitelist|resolved?.*(ip|host)|socket\.inet_aton|ipaddress|check_host", re.S)
# 常见 fetcher 参数命名
FETCH_SIG = re.compile(r"def (\w*fetch\w*|\w*get\w*|\w*request\w*|\w*download\w*)\([^)]*(url|endpoint|target|uri)[^)]*\)", re.I)

def gh_search(limit=60):
    queries = [
        "mcp-server language:python pushed:>2026-09-05 stars:0..60",
        "mcp server language:python pushed:>2026-09-05 stars:0..60",
        "fastmcp language:python pushed:>2026-09-05 stars:0..60",
        "mcp fetch url language:python pushed:>2026-09-05",
    ]
    seen = {}
    for q in queries:
        r = subprocess.run(["gh","api","--method","GET","search/repositories",
            "-f", f"q={q}", "-f","per_page=20","-f","sort=updated"],
            capture_output=True, text=True, timeout=60)
        if r.returncode: continue
        try: d=json.loads(r.stdout)
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

def scan(target):
    hits=[]
    guarded=[]
    fetch_files=[]
    for root, dirs, fs in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ("__pycache__",".git","venv",".venv","node_modules","test","tests","examples")]
        for f in fs:
            if not f.endswith(".py"): continue
            fp=os.path.join(root,f)
            try: code=open(fp,encoding="utf-8",errors="ignore").read()
            except: continue
            if not re.search(r"httpx|requests|urllib\.request|aiohttp|urllib3", code):
                continue
            # 找 fetch 函数
            for fm in FETCH_SIG.finditer(code):
                fetch_files.append((f, fm.group(1)))
            # 找用户 URL 直进调用
            for cm in HTTP_CALL.finditer(code):
                inner = cm.group(2)
                if not URL_PARAM_HINT.search(inner): continue
                # 简化: 匹配 url=... 或 (url... 含参数名
                if not re.search(r"url\s*=|url\b|\(.*(url|endpoint|target)", inner, re.I):
                    continue
                ln = code.count("\n",0,cm.start())+1
                lines = code.splitlines()
                ctx = lines[ln-1].strip()[:130] if ln-1<len(lines) else ""
                # 该文件是否含 SSRF guard
                has_guard = bool(SSRF_GUARD.search(code))
                hits.append((f, ln, ctx, has_guard))
    return hits, fetch_files

def main():
    repos = gh_search()
    print(f"候选池 {len(repos)}")
    interesting=[]
    for repo, desc in repos:
        t = clone(repo)
        if not t: continue
        hits, fetchers = scan(t)
        if hits:
            # 无 guard 的才是重点
            no_guard = [h for h in hits if not h[3]]
            print(f"\n{'🔴' if no_guard else '🟡'} {repo} ({len(hits)} fetch, {len(no_guard)} 无guard)")
            for f,l,c,g in hits[:6]:
                print(f"    {f}:{l} [{'guard' if g else 'NO-GUARD'}] {c}")
            if no_guard: interesting.append((repo, no_guard))
        elif fetchers:
            print(f"🟡 {repo} (fetch函数 {len(fetchers)}: {[n for _,n in fetchers[:3]]})")
    print(f"\n=== 疑似 SSRF 无防护 {len(interesting)} 个 ===")
    for repo, nh in interesting: print(" ", repo, f"({len(nh)} no-guard hit)")

if __name__=="__main__":
    main()