#!/usr/bin/env python3
"""批量检测 SQL/DB MCP 只读门禁的脆弱实现 (2026-09-23)。

针对已知高危模式 (db-connector CWE-281 同源):
  - 只读门禁用 startswith / 首词分类 (WHITELIST 含 WITH 或 SELECT 就放行)
  - 没有 AST 解析 (sqlparse/sqlglot)、没有连接层只读 (readonly=1 / SET TRANSACTION READ ONLY / mode=ro)

用法: python bulk_readonly_gate_scan.py [--limit N] [--gh 0|1]
  --gh 1 用 gh api 扫新仓库 (默认 1)
  输出: 每个仓库的 gate 实现分级, 标出疑似脆弱 (sloppy gate) 的。

只读安全研究: 不写外部, 不申请 CVE, 克隆放 I:/audit/gate-scan/。
"""
import os, re, subprocess, sys, json, tempfile, shutil

BASE = r"I:/audit/gate-scan"
os.makedirs(BASE, exist_ok=True)

# 脆弱信号: 只读门禁依赖首词/白名单, 且把 WITH 或 SELECT 当只读
VULN_PATTERNS = {
    "startswith_w_select": r"startswith\([^)]*['\"](select|with)",
    "head_first_word": r"(?i)head\s*=\s*.{0,10}words?\s*\[\s*0\s*\]",
    "read_heads_includes_with": r"(?i)read_heads?\s*=.*['\"]with['\"]",
    "allowed_start": r"(?i)allowed?\s*(start|begin|prefix|verbs?)\s*=.*['\"](select|with)",
    "select_or_with": r"(?i)if\s+.{0,30}\b(select|with)\b.{0,30}(upper|lstrip|startswith)",
}

# 强信号: 有正确防护
STRONG_PATTERNS = {
    "sqlparse": r"import\s+sqlparse|sqlparse\.",
    "sqlglot": r"import\s+sqlglot|sqlglot\.",
    "readonly_conn": r"(?i)readonly\s*=\s*[01]|default_transaction_read_only|SET\s+TRANSACTION\s+READ\s+ONLY|mode\s*=\s*['\"]ro|read.only\s*(connection|transaction|role)",
    "privilege_principal": r"(?i)db_datareader|readonly.*principal|least.privilege|read.only.*role",
}

def gh_search(limit=25):
    """gh api 搜 SQL/DB MCP 仓库。"""
    q = "mcp+sql+language:python+pushed:%3E2026-04-01"
    r = subprocess.run(["gh","api",
        f"search/repositories?q={q}&sort=updated&per_page={limit}"],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print("gh api err:", r.stderr[:200])
        return []
    try:
        d = json.loads(r.stdout)
    except Exception as e:
        print("json err:", e, r.stdout[:200])
        return []
    return [i["full_name"] for i in d.get("items", [])]

def clone(repo):
    target = os.path.join(BASE, repo.replace("/","__"))
    if os.path.exists(target):
        return target
    r = subprocess.run(["git","clone","--depth","1","-q",
        f"https://github.com/{repo}.git", target],
        capture_output=True, text=True, timeout=90)
    return target if r.returncode == 0 else None

def scan_gate(repo, target):
    """找 py 文件里的只读门禁, 分级。"""
    hits = {"vuln": [], "strong": [], "other": []}
    files = []
    for root, dirs, fs in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ("__pycache__",".git","venv",".venv")]
        for f in fs:
            if f.endswith(".py"):
                files.append(os.path.join(root, f))
    for fp in files[:80]:  # 限文件数
        try:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                code = fh.read()
        except Exception:
            continue
        for name, pat in VULN_PATTERNS.items():
            if re.search(pat, code, re.S):
                hits["vuln"].append((os.path.basename(fp), name))
        for name, pat in STRONG_PATTERNS.items():
            if re.search(pat, code, re.S):
                hits["strong"].append((os.path.basename(fp), name))
        if re.search(r"(?i)read.?only|只读|is_read|can_read", code, re.S):
            hits["other"].append(os.path.basename(fp))
    return hits

def main():
    limit = int(os.environ.get("SCAN_LIMIT", "20"))
    repos = gh_search(limit)
    print(f"候选 {len(repos)}: {repos}\n")
    interesting = []
    for repo in repos:
        t = clone(repo)
        if not t:
            print(f"[clone失败] {repo}")
            continue
        hits = scan_gate(repo, t)
        # 判定: 有 vuln 模式 -> 潜在洞; 有 strong 无 vuln -> 设计良好; 有 vuln+strong 都无 -> 看情况
        tag = ""
        if hits["vuln"]:
            tag = "🔴 疑似脆弱门禁"
            interesting.append((repo, hits))
        elif hits["strong"]:
            tag = "🟢 有正确防护"
        elif hits["other"]:
            tag = "⚪ 有只读逻辑, 待细看"
        else:
            tag = "⚫ 未见门禁逻辑"
        print(f"[{tag}] {repo}")
        for f,n in hits["vuln"][:3]: print(f"    VULN {f}: {n}")
        for f,n in hits["strong"][:3]: print(f"    safe {f}: {n}")
        if hits["other"] and not hits["vuln"] and not hits["strong"]:
            for f in hits["other"][:3]: print(f"    gate {f}")
    print(f"\n=== 疑似脆弱 {len(interesting)} 个 ===")
    for repo, hits in interesting:
        print(f"  {repo} (vuln: {[n for _,n in hits['vuln'][:4]]})")

if __name__ == "__main__":
    main()