"""Synapse MCP Server.

Supports two modes controlled by the MCP_MODE environment variable:
  - "api"      (default) — Storm-powered toolkit; agent writes Storm directly
  - "abstract" — Structured-parameter tools that generate Storm internally
"""

from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

from synapse_mcp.client import SynapseClient

MCP_MODE = os.environ.get("MCP_MODE", "api").lower()

mcp = FastMCP(
    "synapse",
    host=os.environ.get("MCP_HOST", "0.0.0.0"),
    port=int(os.environ.get("MCP_PORT", "8000")),
    json_response=True,
    stateless_http=True,
)

_client: SynapseClient | None = None


def _get_client() -> SynapseClient:
    global _client
    if _client is None:
        _client = SynapseClient()
    return _client


# ── Shared tools (always registered) ────────────────────────────────


@mcp.tool()
async def get_cortex_info() -> str:
    """Get Synapse Cortex version and configuration info."""
    client = _get_client()
    info = await client.get_cortex_info()
    return json.dumps(info, indent=2, default=str)


@mcp.tool()
async def search_views(query: str | None = None, limit: int = 10) -> str:
    """Search for views in the Cortex by name or iden.

    Returns matching views with their iden (needed for the 'view' parameter on other tools),
    name, creator, and layer info.

    Args:
        query: Optional search string. Matches case-insensitively against view name and iden.
               If omitted, returns all views.
        limit: Maximum number of views to return (default 10). Total match count is always included.
    """
    client = _get_client()
    views = await client.list_views()
    if not isinstance(views, list):
        return json.dumps(views, indent=2, default=str)

    needle = query.lower() if query else None
    matched = []
    for v in views:
        if not isinstance(v, dict):
            continue
        if needle:
            name = (v.get("name") or "").lower()
            iden = (v.get("iden") or "").lower()
            if needle not in name and needle not in iden:
                continue
        matched.append({
            "iden": v.get("iden"),
            "name": v.get("name"),
            "creator": v.get("creator"),
            "layers": [
                {"iden": lyr.get("iden"), "name": lyr.get("name")}
                for lyr in v.get("layers", [])
                if isinstance(lyr, dict)
            ],
            **({"parent": v["parent"]} if v.get("parent") else {}),
        })

    result = {"total": len(matched), "views": matched[:limit]}
    if query is not None:
        result["query"] = query
    return json.dumps(result, indent=2, default=str)


# ── Mode-specific tool registration ─────────────────────────────────


def _register_tools() -> None:
    """Register tools based on MCP_MODE."""
    if MCP_MODE == "abstract":
        from synapse_mcp.tools_abstract import register_abstract_tools
        register_abstract_tools(mcp, _get_client)
    else:
        from synapse_mcp.tools_api import register_api_tools
        register_api_tools(mcp, _get_client)


_register_tools()


def main():
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
