#!/usr/bin/env python3
"""批量检测 MCP/agent 仓库的 subprocess 命令注入面 (2026-09-23)。

针对高危 RCE 模式:
  - subprocess.call/run/Popen/os.system/os.popen 用 字符串+shell=True 且 参数来自用户输入
  - f-string / 变量拼接 进 command
  - shell=True 且参数 list 用户可控 (list 在 shell=True 下有 window 注入)
  - 无参数化/无 argv list 分隔

分级:
  🔴 疑似命令注入 (subprocess + shell + 变量/拼接/f-string)
  🟡 有 subprocess 但可疑 (参数来自变量, 需人工看)
  🟢 安全 (list argv 无 shell / 参数化常量)
  ⚫ 无 subprocess 面

用法: python bulk_subprocess_scan.py [--limit N] [--noreclone 0|1]
只读: 不写外部, 不申请 CVE, 克隆放 I:/audit/cmdscan/.
"""
import os, re, subprocess, sys, json, shutil, time

BASE = r"I:/audit/cmdscan"
os.makedirs(BASE, exist_ok=True)

# 疑似 RCE: shell + 命令字符串来自变量/拼接/f-string
RCE_PATTERNS = [
    (r"subprocess\.(run|call|Popen|check_output|check_call)\(\s*[^,)]*\{", "fstring_in_cmd"),
    (r"subprocess\.(run|call|Popen|check_output|check_call)\(\s*[^,)]*\w+\s*[+]", "concat_in_cmd"),
    (r"os\.system\(\s*[^)]*[_a-z]", "os_system_var"),
    (r"os\.popen\(\s*[^)]*[_a-z]", "os_popen_var"),
    (r"shell\s*=\s*True", "shell_true"),
    (r"subprocess\.(run|call|Popen|check_output|check_call)\(\s*[^,)]*,\s*shell\s*=\s*True", "sp_shell_true"),
    (r"os\.system\(\s*f[\"']", "os_system_fstring"),
    (r"exec\(|eval\(|__import__", "exec_eval"),
]
# subprocess 存在但可能是安全的 (list argv 无 shell)
SP_PRESENT = [r"subprocess\.", r"os\.system", r"os\.popen", r"create_subprocess", r"asyncio\.create_subprocess"]

def gh_search(limit=25):
    q = "mcp-server language:python pushed:>2026-09-16 stars:0..80"
    r = subprocess.run(["gh","api","--method","GET","search/repositories",
        "-f", f"q={q}", "-f", f"per_page={limit}", "-f", "sort=updated"],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print("gh err", r.stderr[:200], file=sys.stderr)
        return []
    try:
        d = json.loads(r.stdout)
    except Exception as e:
        print("json err", e, r.stdout[:200], file=sys.stderr)
        return []
    return [(i["full_name"], (i.get("description") or "")) for i in d.get("items", [])]

def clone(repo):
    target = os.path.join(BASE, repo.replace("/", "__"))
    if os.path.exists(target):
        return target
    r = subprocess.run(["git","clone","--depth","1","-q",
        f"https://github.com/{repo}.git", target],
        capture_output=True, text=True, timeout=90)
    return target if r.returncode == 0 else None

def scan(target):
    res = {"rce": [], "sp": [], "other": []}
    files = []
    for root, dirs, fs in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ("__pycache__",".git","venv",".venv","node_modules")]
        for f in fs:
            if f.endswith(".py") or f.endswith(".go"):
                files.append(os.path.join(root, f))
    for fp in files[:100]:
        try:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                code = fh.read()
        except Exception:
            continue
        base = os.path.basename(fp)
        for pat, name in RCE_PATTERNS:
            for m in re.finditer(pat, code, re.S):
                line = code.count("\n", 0, m.start()) + 1
                # 截取该行上下文
                lines = code.splitlines()
                ctx = lines[line-1].strip()[:110] if line-1 < len(lines) else ""
                res["rce"].append((base, name, line, ctx))
        if re.search("|".join(SP_PRESENT), code):
            res["sp"].append(base)
    return res

def main():
    limit = int(os.environ.get("SCAN_LIMIT", "15"))
    repos = gh_search(limit)
    print(f"候选 {len(repos)}:\n", "\n".join(f"  {n} | {d[:50]}" for n,d in repos), "\n")
    hits = []
    for repo, _ in repos:
        t = clone(repo)
        if not t:
            print(f"[clone失败] {repo}")
            continue
        res = scan(t)
        tag = ""
        if res["rce"]:
            # 去重同文件同类型
            unique = set((f,n) for f,n,_,_ in res["rce"])
            tag = f"🔴 疑似命令注入 ({len(unique)})"
            hits.append((repo, res))
        elif res["sp"]:
            tag = "🟡 有 subprocess"
        else:
            tag = "⚫ 无 subprocess 面"
        print(f"[{tag}] {repo}")
        seen = set()
        for f,n,l,c in res["rce"]:
            key=(f,n)
            if key in seen: continue
            seen.add(key)
            print(f"    RCE {f}:{l} [{n}] {c}")
    print(f"\n=== 疑似命令注入 {len(hits)} 个 ===")
    for repo, res in hits:
        u = sorted(set((f,n) for f,n,_,_ in res["rce"]))
        print(f"  {repo}: {[(f,n) for f,n in u[:3]]}")

if __name__ == "__main__":
    main()