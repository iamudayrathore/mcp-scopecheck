"""Hardened MCP server used only as static-analysis input."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hardened-doc-search")
DOCS_ROOT = Path(__file__).parent / "docs"


def _search_docs(query: str) -> list[str]:
    matches: list[str] = []
    for path in DOCS_ROOT.glob("*.md"):
        text = path.read_text(encoding="utf-8", errors="strict")
        if query.casefold() in text.casefold():
            matches.append(path.name)
    return matches


@mcp.tool(annotations={"readOnlyHint": True})
def search_project_docs(query: str) -> list[str]:
    """Search bundled project documentation within the server's fixed documentation root."""

    return _search_docs(query)
