"""Implementation A: API Mirror tools.

Storm-powered toolkit where the agent writes Storm queries directly.
Registered when MCP_MODE=api.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from synapse_mcp.client import SynapseClient
from synapse_mcp.parse import format_node_brief, parse_nodes, parse_print_messages

STORM_REFERENCE = """\
# Storm Query Language — Quick Reference

## Lifts (retrieve nodes)
  inet:fqdn=google.com              # lift by form=value
  inet:fqdn                         # lift ALL nodes of a form (careful!)
  hash:md5=<hash>                   # lift by hash value
  file:bytes=sha256:<hash>          # lift file by sha256

## Filters (applied to pipeline with + / -)
  +inet:fqdn                        # keep only inet:fqdn nodes
  -inet:fqdn                        # remove inet:fqdn nodes
  +{ :asn=1234 }                    # keep nodes where prop asn == 1234
  +#tag.name                        # keep nodes with a tag
  -#tag.name                        # remove nodes with a tag
  +:prop=value                      # property equality
  +:prop~="regex"                   # regex match on property
  +:prop>10                         # comparison operators: > < >= <= !=

## Pivots (traverse edges)
  -> inet:dns:a                     # pivot to inet:dns:a nodes connected to current
  <- inet:dns:a                     # reverse pivot
  -> *                              # pivot to ALL connected forms

## Light Edges
  -(refs)> *                        # traverse "refs" light edge forward
  <(refs)- *                        # traverse "refs" light edge reverse
  -(uses)> *                        # traverse "uses" light edge
  -(seen)> *                        # traverse "seen" light edge

## Tags
  #cno.threat.apt1                   # nodes tagged with this
  +#cno.threat.apt1                  # filter: keep only tagged nodes
  -#cno.threat.apt1                  # filter: remove tagged nodes

## Useful Commands
  | count                            # count nodes in pipeline
  | limit 10                         # take only first N nodes
  | uniq                             # deduplicate nodes
  | spin                             # consume pipeline (no output)
  +$lib.len(:prop) > 0              # filter by property existence

## Variables & Functions
  $count = $lib.len($nodes)          # count in variable
  return($value)                     # return single value (use with storm_call)
  $lib.view.get().layers.0.getFormCounts()  # get form counts

## Common Patterns
  inet:fqdn#cno.threat.apt1         # all FQDNs tagged APT1
  inet:fqdn#cno.threat.apt1 -> inet:dns:a -> inet:ipv4  # APT1 FQDNs -> IPs
  file:bytes +:mime:pe:pdbpath~="bark"  # files with PDB path containing "bark"
  media:news -(refs)> *              # articles referencing any node
"""


def register_api_tools(mcp: FastMCP, get_client) -> None:
    """Register API mirror tools on the given FastMCP instance."""

    @mcp.resource("storm://reference")
    def storm_reference() -> str:
        """Storm query language quick reference guide."""
        return STORM_REFERENCE

    @mcp.tool()
    async def storm_query(query: str, limit: int = 0, opts: str | None = None, view: str | None = None) -> str:
        """Execute a Storm query and return parsed node data.

        Returns structured node data (form, value, props, tags) instead of raw messages.
        If the query produces print output (e.g. count), that is returned instead.

        Args:
            query: A valid Storm query string.
            limit: Max number of nodes to return (0 = unlimited). Appends '| limit N' to query.
            opts: Optional JSON string of Storm query options.
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        parsed_opts = json.loads(opts) if opts else None

        effective_query = query
        if limit > 0:
            effective_query = f"{query} | limit {limit}"

        messages = await client.storm(effective_query, opts=parsed_opts, view=view)

        # Check for print messages first (e.g. from count)
        prints = parse_print_messages(messages)
        if prints:
            return json.dumps({"print_output": prints}, default=str)

        nodes = parse_nodes(messages)
        result = [format_node_brief(n) for n in nodes]
        return json.dumps(result, default=str)

    @mcp.tool()
    async def storm_call(query: str, opts: str | None = None, view: str | None = None) -> str:
        """Execute a Storm query that returns a single value via return().

        Use this for queries like: return($lib.user.name()) or return($lib.view.get().iden)

        Args:
            query: A Storm query that uses return() to produce a single value.
            opts: Optional JSON string of Storm query options.
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        parsed_opts = json.loads(opts) if opts else None
        result = await client.storm_call(query, opts=parsed_opts, view=view)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def get_model(name_filter: str | None = None) -> str:
        """Look up Synapse data model forms and their properties.

        Returns a concise summary: form names with their property names and types.
        Use this to discover what forms exist and what properties they have.

        Args:
            name_filter: Substring to filter forms by name (e.g. 'inet:fqdn', 'file', 'hash').
        """
        client: SynapseClient = get_client()
        model = await client.get_model()
        return _format_model(model, name_filter)

    @mcp.tool()
    async def count_by_form(tag: str | None = None, view: str | None = None) -> str:
        """Get node counts grouped by form type.

        Returns a dict of {form_name: count} for all forms in the view.
        If a tag is specified, counts only nodes with that tag.

        Args:
            tag: Optional tag to filter by (e.g. 'cno.threat.apt1'). Only count nodes with this tag.
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        if tag:
            # Lift all tagged nodes and build counts
            messages = await client.storm(f"#{tag}", view=view)
            nodes = parse_nodes(messages)
            counts: dict[str, int] = {}
            for node in nodes:
                form = node["form"]
                counts[form] = counts.get(form, 0) + 1
            return json.dumps(counts, default=str)
        else:
            result = await client.storm_call(
                "return($lib.view.get().layers.0.getFormCounts())",
                view=view,
            )
            return json.dumps(result, default=str)


def _format_model(model: dict, name_filter: str | None = None) -> str:
    """Format the model into a concise summary of forms and properties."""
    forms = model.get("forms", {})
    if not isinstance(forms, dict):
        return json.dumps(model, default=str)

    summary = {}
    for form_name, form_info in forms.items():
        if name_filter and name_filter.lower() not in form_name.lower():
            continue

        props = {}
        if isinstance(form_info, dict):
            for prop_name, prop_info in form_info.items():
                if isinstance(prop_info, dict):
                    prop_type = prop_info.get("type", {})
                    type_name = prop_type[0] if isinstance(prop_type, (list, tuple)) and prop_type else str(prop_type)
                    props[prop_name] = type_name
                elif isinstance(prop_info, (list, tuple)):
                    # Some model formats have [name, {info}] pairs
                    if len(prop_info) >= 2 and isinstance(prop_info[1], dict):
                        prop_type = prop_info[1].get("type", {})
                        type_name = prop_type[0] if isinstance(prop_type, (list, tuple)) and prop_type else str(prop_type)
                        props[prop_name] = type_name
                    else:
                        props[prop_name] = "unknown"

        summary[form_name] = props

    return json.dumps(summary, indent=2, default=str)
