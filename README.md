# synapse-mcp

MCP server for [Synapse](https://github.com/vertexproject/synapse), the open-source intelligence hypergraph platform. Gives AI agents structured access to a Synapse Cortex for threat intelligence analysis, indicator pivoting, and data exploration.

## Modes

The server supports two tool modes, controlled by the `MCP_MODE` environment variable:

| Mode | `MCP_MODE` | Description |
|------|-----------|-------------|
| **API** | `api` (default) | Storm-powered toolkit. The agent writes Storm queries directly. Includes a Storm quick-reference resource. |
| **Abstract** | `abstract` | Structured-parameter tools that generate Storm internally. The agent describes what it wants (form, tags, filters) without knowing Storm syntax. |

Both modes share `get_cortex_info`, `search_views`, and `get_model` tools.

### API mode tools

| Tool | Description |
|------|-------------|
| `storm_query` | Execute a Storm query, returns parsed nodes or print output |
| `storm_call` | Execute a Storm query that returns a single value via `return()` |
| `get_model` | Look up data model forms and their properties |
| `count_by_form` | Node counts grouped by form type |

### Abstract mode tools

| Tool | Description |
|------|-------------|
| `lookup` | Look up a node by form and value |
| `search_by_tag` | Find nodes by tag(s), with count/grouping options |
| `search_by_value` | Substring search on node values |
| `pivot` | Query, filter, and optionally pivot through connected nodes. Without hops: lift + filter. With hops: single or multi-hop pivots with per-hop filters. |
| `explore_edges` | Count-only pivot showing what's connected to a node |
| `traverse_edge` | Traverse light edges (refs, uses, seen, etc.) |
| `get_model` | Look up data model forms and their properties |

## Setup

### Prerequisites

- Python 3.10+
- A running Synapse Cortex (see [Synapse deployment docs](https://synapse.docs.vertex.link/en/stable/synapse/deploymentguide.html))

### Install

```bash
git clone <repo-url> && cd synapse-mcp
uv venv && uv pip install -e .
```

### Local Synapse stack (optional)

A `docker-compose.yml` is included for running a full local stack (AHA, Axon, JSONStor, Cortex):

```bash
# First time: provisions services and creates root user
./scripts/bootstrap.sh

# With data import (place .nodes files in data/)
./scripts/bootstrap.sh --load-data

# Subsequent runs
docker compose up -d
```

## Configuration

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SYNAPSE_URL` | Yes | | Cortex HTTPS URL (e.g. `https://localhost:4443`) |
| `SYNAPSE_USER` | | | Username for basic auth |
| `SYNAPSE_PASS` | | | Password for basic auth |
| `SYNAPSE_API_KEY` | | | API key auth (takes precedence over user/pass) |
| `SYNAPSE_VERIFY_SSL` | | `true` | Set `false` for self-signed certs |
| `SYNAPSE_VIEW` | | | Default view iden (32-char hex). If unset, uses Cortex default view. |
| `MCP_MODE` | | `api` | Tool mode: `api` or `abstract` |
| `MCP_TRANSPORT` | | `stdio` | Transport: `stdio` or `sse` |

### MCP client configuration

Copy the example and fill in your values:

```bash
cp .mcp.json.example .mcp.json
```

Example `.mcp.json`:

```json
{
  "mcpServers": {
    "synapse": {
      "command": "synapse-mcp",
      "env": {
        "SYNAPSE_URL": "https://localhost:4443",
        "SYNAPSE_USER": "root",
        "SYNAPSE_PASS": "secret",
        "SYNAPSE_VERIFY_SSL": "false",
        "MCP_MODE": "abstract",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

## Views

All query tools accept an optional `view` parameter (32-char hex iden) to target a non-default view. You can also set `SYNAPSE_VIEW` to change the default for all queries.

Use `search_views` to find views by name:

```
search_views(query="threat-intel")
```

Precedence: per-query `view` param > `SYNAPSE_VIEW` env var > Cortex default view.