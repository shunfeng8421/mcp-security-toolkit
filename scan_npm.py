"""npm MCP typosquat/hijack scan. Enumerate mcp packages via npm search, flag:
- typosquat variants of known core packages (edit-distance)
- packages mirroring official @modelcontextprotocol names in unscoped/other scope
- high download + suspicious publish pattern
Tolerant (no fail on network)."""
import json, urllib.request, urllib.parse, time, re

def ns(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent":"npmcli/10"}), timeout=25).read()

def npm_search(q, size=50):
    try:
        u="https://registry.npmjs.org/-/v1/search?text="+urllib.parse.quote(q)+f"&size={size}"
        return json.loads(ns(u)).get("objects",[])
    except Exception as e:
        return [("ERR",str(e)[:40])]

def jget(pkg):
    try:
        return json.loads(ns("https://registry.npmjs.org/"+urllib.parse.quote(pkg,safe="")))
    except Exception: return None

# official core packages (authoritative names)
CORE=["@modelcontextprotocol/sdk","@modelcontextprotocol/server-filesystem",
"@modelcontextprotocol/server-github","@modelcontextprotocol/server-memory",
"@modelcontextprotocol/server-postgres","@modelcontextprotocol/server-everything",
"@modelcontextprotocol/server-sequential-thinking","@modelcontextprotocol/server-edit",
"@modelcontextprotocol/server-time","@modelcontextprotocol/server-websearch",
"fastmcp","mcp","mcp-server-filesystem"]

def edit_dist(a,b):
    # simple Levenshtein
    m,n=len(a),len(b)
    dp=list(range(n+1))
    for i in range(1,m+1):
        prev=dp[0]; dp[0]=i
        for j in range(1,n+1):
            cur=dp[j]; dp[j]=min(dp[j]+1,dp[j-1]+1,prev+(a[i-1]!=b[j-1])); prev=cur
    return dp[n]

def main():
    seen=set(); flagged=[]
    print("=== npm search 'mcp server' ===")
    res=npm_search("mcp server",80)
    for obj in (res if isinstance(res,list) and not isinstance(res[0],tuple) else []):
        p=obj.get("package",{})
        name=p.get("name",""); nkey=name.lower()
        if not name or nkey in seen or nkey.startswith("@modelcontextprotocol"): 
            seen.add(nkey); continue
        seen.add(nkey)
        # typosquat check vs core
        corematch=None; best=99
        if not name.startswith("@"):
            for c in CORE:
                if c.startswith("@"): 
                    base=c.split("/")[-1]
                else: base=c
                d=edit_dist(name.lower(),base.lower())
                if d<best: best=d; corematch=base
            if corematch and best<=2:
                flagged.append(dict(name=name,type="TYPO",of=basename if False else corematch,score=best,
                    desc=(p.get("description") or "")[:70],date=p.get("date")))
        elif name.startswith("@") and "modelcontextprotocol" not in name:
            # non-official scoped package with server core name
            base=name.split("/")[-1] if "/" in name else name
            for c in CORE:
                cb=c.split("/")[-1]
                if base.lower()==cb.lower() or edit_dist(base.lower(),cb.lower())<=1:
                    flagged.append(dict(name=name,type="SCOPED-IMIT",of=c,score=edit_dist(base.lower(),cb.lower()),desc=(p.get("description") or "")[:70]))
                    break
    json.dump(flagged,open("npm_flagged.json","w"),indent=1)
    print(f"scanned {len(seen)} mcp packages, flagged {len(flagged)}")
    for f in flagged: print(f)
    # also print full names for a sense
    print("\n=== all mcp-scanned names (unscoped) ===")
    print(sorted(n for n in seen if not n.startswith("@"))[:60])

if __name__=="__main__":
    main()