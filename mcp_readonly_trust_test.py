"""
MCP client black-box test: does an MCP client trust a server's readOnlyHint
declaration enough to treat a destructive tool as safe?

Connects to the PoC server (mcp_poc_server.py), lists tools (showing readOnlyHint),
then calls the tool and verifies the marker file is actually deleted — proving the
server's self-declared "read-only" annotations are honored by clients.
Author: Shiqiang Chen (PoC only, marker file, no real harm).
"""
import asyncio, json, os, sys, tempfile
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

MARKER = os.path.join(tempfile.gettempdir(), "claude_code_poc_marker.txt")

def ensure_marker():
    with open(MARKER, "w") as f:
        f.write("SENSITIVE_POC_DATA")

async def main():
    ensure_marker()
    print("=== [1] marker 已建:", os.path.exists(MARKER))

    server = StdioServerParameters(
        command=sys.executable,
        args=["D:/hermes/mcp-claude-code-poc/mcp_poc_server.py"],
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("=== [2] 工具列表 (观察 readOnlyHint/destructiveHint 声明) ===")
            tools = await session.list_tools()
            for t in tools.tools:
                ann = t.annotations
                print(f"  工具: {t.name}")
                print(f"    desc: {t.description[:80]}")
                print(f"    readOnlyHint={ann.readOnlyHint if ann else '?'} destructiveHint={ann.destructiveHint if ann else '?'}")
                print(f"    inputSchema: {json.dumps(t.inputSchema)[:120]}")

            print("=== [3] 调用 read_insights (声明只读, 实际删 marker) ===")
            result = await session.call_tool("read_insights", {"path": "default"})
            for c in result.content:
                if hasattr(c, "text"):
                    print(f"  工具返回: {c.text[:150]}")

            print("=== [4] 验证 marker 是否被删 (工具声明只读但实际破坏) ===")
            deleted = not os.path.exists(MARKER)
            print(f"  marker 存在: {os.path.exists(MARKER)}")
            print(f"  >>> 声明只读的工具执行了破坏性删除: {'CONFIRMED (readOnlyHint 未被强制)' if deleted else '未删除'}")

            # 恢复 marker 清理
            if deleted:
                ensure_marker()

if __name__ == "__main__":
    asyncio.run(main())