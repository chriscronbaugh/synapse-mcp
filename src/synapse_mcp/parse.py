"""Shared node parsing logic for Storm stream messages.

Synapse's /api/v1/storm endpoint returns a stream of JSON messages.
Node messages have the shape: ["node", [<ndef>, {"props": ..., "tags": ..., ...}]]
This module extracts clean structured data from those messages.
"""

from __future__ import annotations


def parse_node(msg: list) -> dict | None:
    """Parse a single Storm stream message into a clean node dict.

    Returns None if the message is not a node message.
    """
    if not isinstance(msg, list) or len(msg) < 2:
        return None
    if msg[0] != "node":
        return None

    ndef = msg[1]
    if not isinstance(ndef, (list, tuple)) or len(ndef) < 2:
        return None

    form_valu = ndef[0]
    node_info = ndef[1] if len(ndef) > 1 else {}

    if not isinstance(form_valu, (list, tuple)) or len(form_valu) < 2:
        return None

    form = form_valu[0]
    value = form_valu[1]

    props = node_info.get("props", {}) if isinstance(node_info, dict) else {}
    tags = node_info.get("tags", {}) if isinstance(node_info, dict) else {}
    tagprops = node_info.get("tagprops", {}) if isinstance(node_info, dict) else {}

    return {
        "form": form,
        "value": value,
        "props": props,
        "tags": tags,
        "tagprops": tagprops,
    }


def parse_nodes(messages: list[list]) -> list[dict]:
    """Parse a list of Storm stream messages, returning only node data."""
    nodes = []
    for msg in messages:
        node = parse_node(msg)
        if node is not None:
            nodes.append(node)
    return nodes


def parse_print_messages(messages: list[list]) -> list[str]:
    """Extract print messages from a Storm stream (e.g., from 'count' command)."""
    prints = []
    for msg in messages:
        if isinstance(msg, list) and len(msg) >= 2 and msg[0] == "print":
            prints.append(str(msg[1].get("mesg", msg[1]) if isinstance(msg[1], dict) else msg[1]))
    return prints


def format_node_brief(node: dict) -> dict:
    """Return a compact representation of a parsed node for tool output."""
    result: dict = {
        "form": node["form"],
        "value": node["value"],
    }
    if node.get("props"):
        result["props"] = node["props"]
    if node.get("tags"):
        result["tags"] = list(node["tags"].keys())
    return result
