"""Implementation B: Query Abstraction tools.

Structured-parameter tools that abstract away Storm syntax.
The agent describes what it wants; tools generate and run Storm internally.
Registered when MCP_MODE=abstract.
"""

from __future__ import annotations

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from synapse_mcp.client import SynapseClient
from synapse_mcp.parse import format_node_brief, parse_nodes, parse_print_messages


def _normalize_str_list(value: list[str] | str | None) -> list[str] | None:
    """Normalize a string-or-list parameter to a proper list.

    LLMs sometimes send a JSON-encoded string like '["a","b"]' instead of
    an actual list ["a","b"]. This detects and parses that case.
    """
    if value is None:
        return None
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        if value.startswith("["):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return [str(x) for x in parsed]
            except (json.JSONDecodeError, ValueError):
                pass
        return [value]
    return [str(value)]


def _escape_storm_str(value: str) -> str:
    """Escape a string for use in a Storm query."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _build_filter_clause(filters: list[dict], as_lift: bool = False) -> str:
    """Build Storm filter clauses from a list of {prop, operator, value} dicts.

    Args:
        filters: List of filter dicts with prop, operator, value.
        as_lift: If True, use secondary property lift syntax (form:prop=val)
                 for the first equality filter — more efficient than +:prop=val.

    Special operators:
      - 'exists': property has a value (+:prop)
      - '!exists': property has no value (-:prop)
    """
    clauses = []
    used_lift = False
    for f in filters:
        prop = f.get("prop", "")
        op = f.get("operator", "=")
        if op == "exists":
            clauses.append(f"+:{prop}")
        elif op == "!exists":
            clauses.append(f"-:{prop}")
        else:
            val = f.get("value", "")
            # Use secondary property lift for first equality filter when as_lift
            if as_lift and not used_lift and op == "=":
                used_lift = True
                if isinstance(val, str):
                    clauses.append(f':{prop}="{_escape_storm_str(val)}"')
                else:
                    clauses.append(f":{prop}={val}")
            else:
                if isinstance(val, str):
                    clauses.append(f'+:{prop}{op}"{_escape_storm_str(val)}"')
                else:
                    clauses.append(f"+:{prop}{op}{val}")
    return " ".join(clauses)


def _build_tag_clauses(tags: list[str] | str | None) -> str:
    """Build Storm tag filter clauses from a single tag or list of tags.

    Prefix a tag with '!' to EXCLUDE it (generates -#tag in Storm).
    """
    tags = _normalize_str_list(tags)
    if not tags:
        return ""
    parts = []
    for t in tags:
        if t.startswith("!"):
            parts.append(f"-#{t[1:]}")
        else:
            parts.append(f"+#{t}")
    return " ".join(parts)


def _build_tag_lift(tags: list[str] | str | None) -> str:
    """Build a Storm lift from tags (for when no form is given)."""
    tags = _normalize_str_list(tags)
    if not tags:
        return ""
    # First tag is the lift, rest are filters
    parts = [f"#{tags[0]}"]
    for t in tags[1:]:
        parts.append(f"+#{t}")
    return " ".join(parts)


def _find_referring_forms(model: dict, target_form: str) -> list[str]:
    """Find forms that have properties whose type matches the target form.

    Used by explore_edges to discover reverse references — forms whose
    properties point TO a given node type (e.g. inet:dns:request has a
    :query:name:fqdn property of type inet:fqdn).
    """
    referring: set[str] = set()
    forms = model.get("forms", {})
    for form_name, form_info in forms.items():
        if form_name == target_form:
            continue
        if not isinstance(form_info, dict):
            continue
        props = form_info.get("props", {})
        for prop_name, prop_info in props.items():
            if not isinstance(prop_info, dict):
                continue
            prop_type = prop_info.get("type", [])
            type_name = prop_type[0] if isinstance(prop_type, list) and prop_type else None
            if type_name == target_form:
                referring.add(form_name)
                break  # One match per form is enough
    return sorted(referring)


async def _run_query(
    client: SynapseClient,
    query: str,
    count_only: bool,
    limit: int = 100,
    distinct_prop: str | None = None,
    view: str | None = None,
):
    """Run a Storm query and return count, nodes, or distinct property values.

    Modes (checked in priority order):
      count_only=True → {"count": N}
      distinct_prop="prop" → {"distinct_count": M, "values": [...]}
      default → {"count": N, "nodes": [...]}
    """
    if count_only:
        count = await client.storm_count(query, view=view)
        return json.dumps({"count": count}, default=str)

    if distinct_prop:
        # Fetch all nodes and extract unique values of the specified property
        nodes = await client.storm_nodes(query, view=view)
        values = set()
        for n in nodes:
            v = n.get("props", {}).get(distinct_prop)
            if v is not None:
                values.add(v)
        sorted_values = sorted(values, key=lambda x: str(x))
        return json.dumps({
            "distinct_count": len(sorted_values),
            "total_nodes": len(nodes),
            "values": sorted_values,
        }, default=str)

    limited_query = f"{query} | limit {limit}"
    nodes = await client.storm_nodes(limited_query, view=view)
    formatted = [format_node_brief(n) for n in nodes]
    if len(nodes) >= limit:
        count = await client.storm_count(query, view=view)
    else:
        count = len(nodes)
    return json.dumps({"count": count, "nodes": formatted}, default=str)


def register_abstract_tools(mcp: FastMCP, get_client) -> None:
    """Register query abstraction tools on the given FastMCP instance."""

    @mcp.tool()
    async def lookup(form: str, value: str, view: str | None = None) -> str:
        """Look up a specific node by its form and value. Returns the node with all properties and tags.

        Args:
            form: The node form/type (e.g. 'inet:fqdn', 'hash:md5', 'file:bytes').
            value: The node value (e.g. 'google.com', an MD5 hash, 'sha256:...').
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        query = f'{form}="{_escape_storm_str(value)}"'
        nodes = await client.storm_nodes(query, view=view)
        if not nodes:
            return json.dumps({"error": "Node not found", "form": form, "value": value})
        return json.dumps([format_node_brief(n) for n in nodes], default=str)

    @mcp.tool()
    async def search_by_tag(
        tags: list[str] | str,
        form: str | None = None,
        count_only: bool = False,
        count_per_form: bool = False,
        count_by_tag_prefix: str | None = None,
        limit: int = 100,
        view: str | None = None,
    ) -> str:
        """Find nodes that have one or more tags. When multiple tags are given,
        returns only nodes that have ALL of them (intersection).

        Args:
            tags: Tag or list of tags. All must be present on matching nodes.
                  Examples: 'rep.mandiant.apt1' or ['rep.mandiant.apt1', 'rep.symantec.commentcrew']
                  Prefix with '!' to EXCLUDE (e.g. '!rep.mandiant.apt1' = nodes WITHOUT that tag).
            form: Optional form to filter results (e.g. 'inet:fqdn'). If omitted, searches all forms.
            count_only: If True, return just the total count instead of node data.
            count_per_form: If True, return count grouped by form type (e.g. {'inet:fqdn': 1833, ...}).
                           Useful for finding the most common indicator type.
            count_by_tag_prefix: If set, return counts grouped by sub-tags under this prefix.
                                Example: count_by_tag_prefix='rep.mandiant' on hash:md5#rep.mandiant.apt1
                                returns {"rep.mandiant.greencat": 89, "rep.mandiant.starsypound": 49, ...}.
                                Useful for finding which malware families or sub-categories are most common.
            limit: Maximum number of nodes to return (default 100). Ignored if count_only/count_per_form/count_by_tag_prefix.
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        tags = _normalize_str_list(tags) or []
        if form:
            query = f"{form}#{tags[0]}"
        else:
            query = f"#{tags[0]}"
        for t in tags[1:]:
            query += f" +#{t}"

        if count_by_tag_prefix:
            prefix = count_by_tag_prefix.rstrip(".")
            depth = prefix.count(".") + 1  # target tag depth = prefix depth + 1
            nodes = await client.storm_nodes(query, view=view)
            tag_counts: dict[str, int] = {}
            for n in nodes:
                for t in n.get("tags", {}).keys():
                    if t.startswith(prefix + ".") and t.count(".") == depth:
                        tag_counts[t] = tag_counts.get(t, 0) + 1
            sorted_tags = sorted(tag_counts.items(), key=lambda x: -x[1])
            return json.dumps({
                "total_nodes": len(nodes),
                "tag_counts": dict(sorted_tags),
            }, default=str)

        if count_per_form:
            # Get all nodes and count by form
            nodes = await client.storm_nodes(query, view=view)
            counts: dict[str, int] = {}
            for n in nodes:
                f = n["form"]
                counts[f] = counts.get(f, 0) + 1
            total = sum(counts.values())
            return json.dumps({"total": total, "form_counts": counts}, default=str)

        return await _run_query(client, query, count_only, limit, view=view)

    @mcp.tool()
    async def search_by_value(
        form: str,
        value_match: str,
        tags: list[str] | str | None = None,
        count_only: bool = False,
        distinct_prop: str | None = None,
        limit: int = 100,
        view: str | None = None,
    ) -> str:
        """Search for nodes whose primary value contains a substring (case-insensitive).

        Use this for partial/fuzzy matching on node values. For exact value lookups, use 'lookup' instead.

        Args:
            form: Node form to search (e.g. 'it:av:signame', 'inet:fqdn').
            value_match: Substring to match against node values (e.g. 'barkiofork', 'firefox').
            tags: Optional tag(s) that nodes must also have.
            count_only: If True, return just the count instead of node data.
            distinct_prop: If set, return unique values of this property from matching nodes.
            limit: Maximum number of nodes to return (default 100). Ignored if count_only/distinct_prop.
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        query = f'{form}~="{_escape_storm_str(value_match)}"'
        if tags:
            query += " " + _build_tag_clauses(tags)
        return await _run_query(client, query, count_only, limit, distinct_prop=distinct_prop, view=view)

    @mcp.tool()
    async def pivot(
        src_form: str,
        hops: list[str | dict] | str | None = None,
        src_value: str | None = None,
        src_value_match: str | None = None,
        src_tags: list[str] | str | None = None,
        src_filters: list[dict] | None = None,
        src_prop_in: dict | None = None,
        count_only: bool = False,
        distinct_prop: str | None = None,
        unique: bool = True,
        limit: int = 100,
        view: str | None = None,
    ) -> str:
        """Query, filter, and optionally pivot through connected nodes.

        Without hops: finds and filters nodes (lift + filter).
        With hops: pivots from source nodes through one or more forms.
        Each hop can be a form string or a dict with form + inline filters/tags.

        Examples:
            Count APT1 FQDNs (no hops, just lift+filter):
              pivot(src_form='inet:fqdn', src_tags='rep.mandiant.apt1', count_only=True)
            Get unique PDB paths from APT1 files:
              pivot(src_form='file:bytes', src_tags='rep.mandiant.apt1',
                    src_filters=[{'prop': 'mime:pe:pdbpath', 'operator': 'exists'}],
                    distinct_prop='mime:pe:pdbpath')
            Count files matching a set of PDB paths:
              pivot(src_form='file:bytes',
                    src_prop_in={'prop': 'mime:pe:pdbpath', 'values': [path1, path2, ...]},
                    count_only=True)
            FQDNs to IPs (single hop):
              pivot(src_form='inet:fqdn', hops='inet:dns:a', src_value='google.com')
            APT1 files with PDB paths -> all files sharing those paths (multi-hop):
              pivot(src_form='file:bytes', src_tags='rep.mandiant.apt1',
                    src_filters=[{'prop': 'mime:pe:pdbpath', 'operator': 'exists'}],
                    hops=['file:path', 'file:bytes'], count_only=True)
            AV vendors detecting files matching 'barkiofork':
              pivot(src_form='it:av:signame', src_value_match='barkiofork',
                    hops=['it:av:filehit', 'it:prod:soft'], count_only=True)
            Files querying earthsolution.org subdomains, filtered to APT1:
              pivot(src_form='inet:fqdn',
                    src_filters=[{'prop': 'zone', 'operator': '=', 'value': 'earthsolution.org'}],
                    hops=['inet:dns:request',
                          {'form': 'file:bytes', 'tags': 'rep.mandiant.apt1'}],
                    count_only=True)

        Args:
            src_form: Source node form (e.g. 'inet:fqdn', 'file:bytes').
            hops: Optional form(s) to pivot through. Omit to just find/filter nodes.
                  Each element is either:
                  - A string: just the form name (e.g. 'inet:dns:a')
                  - A dict with:
                    - form (required): the form to pivot to
                    - tags: tag(s) to filter at this hop (prefix with '!' to exclude)
                    - filters: property filters at this hop
                  Examples: 'inet:dns:a', ['inet:dns:a', 'inet:ipv4'],
                    [{'form': 'inet:dns:a', 'tags': 'rep.mandiant.apt1'}, 'inet:ipv4']
            src_value: Optional specific source node value (exact match).
            src_value_match: Optional substring to match in source node values (case-insensitive).
                             Useful for partial matching (e.g. 'barkiofork' to find AV signatures).
            src_tags: Optional tag(s) to filter source nodes (e.g. 'rep.mandiant.apt1' or list).
            src_filters: Optional property filters on source nodes. Each filter is a dict with:
                         - prop: property name (e.g. 'host', 'mime:pe:pdbpath')
                         - operator: =, !=, ~=, >, <, >=, <=, 'exists', '!exists'
                         - value: value to compare (not needed for exists/!exists)
            src_prop_in: Match source nodes where a property equals ANY value in a list.
                         Dict with 'prop' (property name) and 'values' (list of values).
                         Useful with distinct_prop results to find all nodes sharing certain values.
            count_only: If True, return just the count instead of node data.
            distinct_prop: If set, return unique values of this property from result nodes.
                          Returns {"distinct_count": N, "total_nodes": M, "values": [...]}.
            unique: If True, deduplicate result nodes (default True).
            limit: Maximum number of result nodes (default 100). Ignored if count_only/distinct_prop.
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        src_tags = _normalize_str_list(src_tags)

        # Normalize hops
        hops_list: list[str | dict] = []
        if hops is not None:
            if isinstance(hops, str):
                hops_list = [hops]
            elif isinstance(hops, list):
                hops_list = hops
            else:
                hops_list = [hops]

        # Build lift
        if src_prop_in:
            # Union of lifts: form:prop=val1 form:prop=val2 ...
            prop = src_prop_in["prop"]
            values = src_prop_in["values"]
            lift_parts = []
            for v in values:
                if isinstance(v, str):
                    lift_parts.append(f'{src_form}:{prop}="{_escape_storm_str(v)}"')
                else:
                    lift_parts.append(f'{src_form}:{prop}={v}')
            lift = " ".join(lift_parts)
            if src_tags:
                lift += " " + _build_tag_clauses(src_tags)
            if src_filters:
                lift += " " + _build_filter_clause(src_filters)
        elif src_value:
            lift = f'{src_form}="{_escape_storm_str(src_value)}"'
        elif src_value_match:
            lift = f'{src_form}~="{_escape_storm_str(src_value_match)}"'
        elif src_tags:
            lift = f"{src_form}#{src_tags[0]}"
            for t in src_tags[1:]:
                lift += f" +#{t}"
        else:
            lift = src_form

        # Add tag filter if value was specified but tags also given
        if not src_prop_in and src_value and src_tags:
            lift += " " + _build_tag_clauses(src_tags)

        # Add source property filters (skip if already handled by prop_in branch)
        if not src_prop_in and src_filters:
            as_lift = not src_value and not src_value_match and not src_tags
            clause = _build_filter_clause(src_filters, as_lift=as_lift)
            lift += clause if as_lift else f" {clause}"

        # If no hops, just lift+filter (replaces filter_nodes)
        if not hops_list:
            return await _run_query(client, lift, count_only, limit, distinct_prop=distinct_prop, view=view)

        # Build pivot chain with per-hop filters
        hop_parts = []
        for hop in hops_list:
            if isinstance(hop, str):
                hop_parts.append(hop)
            elif isinstance(hop, dict):
                part = hop.get("form", "")
                hop_tags = hop.get("tags")
                hop_filters = hop.get("filters")
                if hop_tags:
                    part += " " + _build_tag_clauses(hop_tags)
                if hop_filters:
                    part += " " + _build_filter_clause(hop_filters)
                hop_parts.append(part)

        pivot_chain = " -> ".join(hop_parts)
        query = f"{lift} -> {pivot_chain}"

        if unique:
            query += " | uniq"

        return await _run_query(client, query, count_only, limit, distinct_prop=distinct_prop, view=view)

    @mcp.tool()
    async def explore_edges(form: str, value: str, view: str | None = None) -> str:
        """Show what forms/types are connected to a node and how many of each.

        This is a count-only pivot: it tells you what's reachable from a node
        without returning all the data. Useful for understanding a node's neighborhood.

        Checks both directions: nodes this node's properties point to (forward),
        and nodes whose properties reference this node (reverse).

        Args:
            form: The node form (e.g. 'inet:fqdn').
            value: The node value (e.g. 'google.com').
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        lift = f'{form}="{_escape_storm_str(value)}"'

        # Forward pivot: follow this node's own properties outward
        query = f"{lift} -> * | groupby form {{}}"
        messages = await client.storm(query, view=view)
        nodes = parse_nodes(messages)

        counts: dict[str, int] = {}
        for node in nodes:
            f = node["form"]
            counts[f] = counts.get(f, 0) + 1

        # Reverse reference check: find forms that have properties pointing
        # TO this node type. The -> * pivot only follows the source node's own
        # properties outward. Many forms reference inet:fqdn, inet:ipv4, etc.
        # via their properties but -> * won't find those.
        try:
            model = await client.get_model()
            referring_forms = [f for f in _find_referring_forms(model, form) if f not in counts]

            async def _check_ref(ref_form: str):
                try:
                    c = await client.storm_count(f'{lift} -> {ref_form}', view=view)
                    return (ref_form, c) if c and c > 0 else None
                except Exception:
                    return None

            results = await asyncio.gather(*[_check_ref(f) for f in referring_forms])
            for r in results:
                if r:
                    counts[r[0]] = r[1]
        except Exception:
            pass

        # Also check light edges
        light_edge_query = f'{lift} $edges=$lib.list() {{ -(*)> * $verb=$path.trace().0.1 $edges.append($verb) }} spin return($edges)'
        try:
            light_edges = await client.storm_call(light_edge_query, view=view)
        except Exception:
            light_edges = []

        result: dict = {"node": f"{form}={value}", "connected_forms": counts}
        if light_edges:
            result["light_edges"] = light_edges
        return json.dumps(result, default=str)

    @mcp.tool()
    async def traverse_edge(
        form: str,
        value: str,
        verb: str,
        reverse: bool = False,
        dst_form: str | None = None,
        count_only: bool = False,
        limit: int = 100,
        view: str | None = None,
    ) -> str:
        """Traverse a named light edge (e.g. refs, uses, seen) from a node.

        Light edges represent semantic relationships between nodes.

        Args:
            form: Source node form (e.g. 'inet:fqdn', 'media:news').
            value: Source node value.
            verb: The light edge verb (e.g. 'refs', 'uses', 'seen').
            reverse: If True, traverse the edge in reverse direction (default False).
                     Forward: node -(verb)> targets.  Reverse: node <(verb)- sources.
            dst_form: Optional form to filter results (e.g. 'media:news'). Only return
                      nodes of this type from the edge traversal.
            count_only: If True, return just the count instead of node data.
            limit: Maximum number of result nodes (default 100). Ignored if count_only=True.
            view: Optional view iden to query. Uses default view if not specified.
        """
        client: SynapseClient = get_client()
        lift = f'{form}="{_escape_storm_str(value)}"'
        target = dst_form if dst_form else "*"
        if reverse:
            query = f"{lift} <({verb})- {target}"
        else:
            query = f"{lift} -({verb})> {target}"
        return await _run_query(client, query, count_only, limit, view=view)

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
                    if len(prop_info) >= 2 and isinstance(prop_info[1], dict):
                        prop_type = prop_info[1].get("type", {})
                        type_name = prop_type[0] if isinstance(prop_type, (list, tuple)) and prop_type else str(prop_type)
                        props[prop_name] = type_name
                    else:
                        props[prop_name] = "unknown"

        summary[form_name] = props

    return json.dumps(summary, indent=2, default=str)
