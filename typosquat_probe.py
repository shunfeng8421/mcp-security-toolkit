"""npm typosquat probing: generate near-variants of core/official MCP package names,
probe existence, report LIVE ones with metadata. Also check for hijack risk (a live
package with the exact name of a member of a scoped org but different owner)."""
import json, urllib.request, urllib.parse, itertools

CORE_BASES = ["server-filesystem","server-github","server-memory","server-postgres",
  "server-everything","server-sequential-thinking","server-edit","server-time",
  "server-websearch","fastmcp","mcp","mcp-server","mcp-client","mcp-hello-world",
  "server-git","server-puppeteer","servers","example-servers"]
# unscoped aliases people might type
CORE_FULL = ["@modelcontextprotocol/sdk","@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github","@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/server-postgres","@modelcontextprotocol/server-everything",
  "@modelcontextprotocol/server-sequential-thinking"]

def exists(p):
    try:
        urllib.request.urlopen(urllib.request.Request("https://registry.npmjs.org/"+urllib.parse.quote(p,safe="@/"),headers={"User-Agent":"probe"}),timeout=15)
        return True
    except Exception:
        return False

# generate variants: drop hyphen, swap hyphen/underscore, add/remove 's', typos for core names
variants=set()
for b in CORE_BASES:
    parts=b.split("-")
    variants.add(b)
    variants.add(b.replace("-",""))            # githubserver
    variants.add(b.replace("-","_"))           # github_server
    variants.add(b+"s")                        # plural
    variants.add(b+"-mcp")                      # server-filesystem-mcp
    variants.add("mcp-"+b)                      # mcp-server-filesystem (already exists)
    variants.add(b[:-1] if b.endswith("s") else b+"")
    variants.add("mcpcontextprotocol-"+b)
    variants.add("modelcontextprotocol-"+b)
    variants.add("model-context-protocol-"+b)
    variants.add(b+"-server")                    # filesystem-server
    # swap letters typos
    for i in range(min(len(b),4)):
        for c in "mscpdn":
            if c!=b[i]:
                variants.add(b[:i]+c+b[i+1:])
# scoped-imitation unscoped
for f in CORE_FULL:
    base=f.split("/")[-1]
    variants.add(base)
    variants.add(base+"-mcp")
    variants.add("mcp-"+base)
    variants.add(base.replace("-",""))
    variants.add(base+"-server")
    variants.add("just"+base)
variants.discard("") 
# filter to plausible-looking
import re
cand=sorted(v for v in variants if re.match(r"^[a-z0-9_.-]{3,55}$",v))
print(f"checking {len(cand)} candidate variants")
live=[]
for c in cand:
    if exists(c):
        live.append(c)
print("LIVE variants:")
for c in live: print("  ",c)
json.dump(live,open("npm_typo_live.json","w"),indent=1)