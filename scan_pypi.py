"""PyPI MCP supply-chain scan - fixed candidate list. Fetch metadata (author/time/versions) +
latest sdist source, scan malicious signatures. Writes candidates.json + hits.json."""
import json, io, zipfile, tarfile, re, hashlib, urllib.request
from datetime import datetime

OUT = r"I:/audit/supply-chain-20261002"
PKGS = ["mcp-server","mcp-client","mcp-agent","mcp-tools","mcp-utils","mcp-config",
        "mcp-server-tools","mcp-index","mcp-gateway","mcps","mcp-server-postgres",
        "mcp-server-sqlite","mcp-server-browser","mcp-proxy"]

def get(url, timeout=30):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"}), timeout=timeout).read()

SIGS = [
    (r"base64\.b64decode\s*\(\s*['\"][A-Za-z0-9+/=]{50,}", "base64-blob"),
    (r"\beval\s*\(", "eval"),
    (r"\bexec\s*\(", "exec"),
    (r"subprocess.*shell\s*=\s*True", "subprocess-shell"),
    (r"os\.system\s*\(|os\.popen\s*\(", "os-shell"),
    (r"(?:curl|wget)\s+[\"']http", "download-exec"),
    (r"requests\.(?:get|post)\s*\(.+?https?://", "exfil-http"),
    (r"(?:socket|smpt|smtplib)\.(?:connect|sendmail)", "network-exfil"),
    (r"\benviron\b.{0,60}(?:KEY|TOKEN|SECRET|PASSWORD|AWS|AZURE|GCP|_AUTH)", "creds-collect"),
    (r"__(?:import|builtins__)__.*system|importlib.+exec", "obfuscated-exec"),
    (r"chmod.{0,10}\d{3,4}", "chmod"),
    (r"\.gitconfig|\.ssh|id_rsa|\.aws|\.kube|\.gcloud", "cred-file"),
    (r"(?:pyppeteer|selenium|playwright).{0,60}(?:steal|auth|cookie|login)", "browser-cred"),
]

def scan(name, text):
    hits=set()
    for pat,label in SIGS:
        try:
            if re.search(pat, text, re.I): hits.add(label)
        except: pass
    if "os.environ" in text and ("request" in text or "socket" in text or "http" in text):
        hits.add("env-exfil")
    return hits

def main():
    cands=[]
    dead=[]
    for pkg in PKGS:
        try:
            j=json.loads(get(f"https://pypi.org/pypi/{pkg}/json"))
        except Exception as e:
            dead.append((pkg,str(e)[:40])); continue
        info=j["info"]; v=info.get("version")
        author=(info.get("author") or info.get("author_email") or "")[:40]
        home=info.get("home_page") or ""
        summary=(info.get("summary") or "")[:80]
        rels=j.get("releases",{})
        # upload times of all versions
        times=[]
        for ver,arts in rels.items():
            for a in arts:
                t=a.get("upload_time")
                if t: times.append((ver,t))
        times.sort(key=lambda x:x[1])
        first=times[0][1] if times else "?"
        urls=None
        for rel in rels.get(v,[]):
            if rel.get("filename","").endswith((".tar.gz",".whl",".zip")): urls=rel; break
        # download latest sdist
        src=""; sha=""; files_hits=[]
        if urls:
            try:
                data=get(urls["url"],timeout=60); sha=hashlib.sha256(data).hexdigest()[:12]
                fn=urls["filename"]
                bio=io.BytesIO(data); fs={}
                if fn.endswith(".whl") or fn.endswith(".zip"):
                    z=zipfile.ZipFile(bio)
                    fs={n:z.read(n) for n in z.namelist() if not n.endswith("/") and n.count("/")<=6 and (n.endswith(".py") or n.endswith(".sh") or n.endswith(".js"))}
                else:
                    t=tarfile.open(fileobj=bio,mode="r:*")
                    fs={n:t.extractfile(n).read() for n in t.getnames() if not n.endswith("/") and t.getmember(n).isfile() and (n.endswith(".py") or n.endswith(".sh") or n.endswith(".js"))}
                for n,c in fs.items():
                    try: txt=c.decode("utf-8","replace")
                    except: continue
                    h=scan(n,txt)
                    if h: files_hits.append((n,list(h)))
            except Exception as e:
                files_hits.append(("ERR",str(e)[:40]))
        r=dict(pkg=pkg,ver=v,author=author,home=home,summary=summary,first_upload=first,
               num_versions=len([x for x in times if times]),sha=sha,file_hits=files_hits)
        cands.append(r)
    json.dump(cands,open(OUT+"/candidates.json","w"),indent=1)
    print("=== CANDIDATES ({} alive, {} dead) ===".format(len(cands),len(dead)))
    for c in cands:
        flag="*** HITS" if c["file_hits"] else ""
        print(f"[{c['pkg']}] v{c['ver']} author={c['author'][:28]} first={c['first_upload'][:10]} {flag}")
        if c["file_hits"]:
            for n,h in c["file_hits"][:6]: print("   ",n[:50],h)
    if dead: print("dead:",dead)

if __name__=="__main__":
    main()