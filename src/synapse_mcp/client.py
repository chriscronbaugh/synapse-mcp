"""Synapse HTTP API client."""

from __future__ import annotations

import os
import re

import httpx

_IDEN_RE = re.compile(r"^[0-9a-f]{32}$")

from synapse_mcp.parse import parse_nodes, parse_print_messages


class SynapseClient:
    """Thin wrapper around the Synapse HTTP/REST API."""

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        user: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        view: str | None = None,
    ):
        self.url = (url or os.environ.get("SYNAPSE_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("SYNAPSE_API_KEY")
        self.user = user or os.environ.get("SYNAPSE_USER")
        self.password = password or os.environ.get("SYNAPSE_PASS")
        self.default_view = view or os.environ.get("SYNAPSE_VIEW") or None
        if self.default_view and not _IDEN_RE.match(self.default_view):
            raise ValueError(
                f"SYNAPSE_VIEW must be a 32-char hex iden, got: {self.default_view!r}"
            )
        if verify_ssl is True:
            self.verify_ssl = os.environ.get("SYNAPSE_VERIFY_SSL", "true").lower() != "false"
        else:
            self.verify_ssl = verify_ssl

        if not self.url:
            raise ValueError("SYNAPSE_URL is required")

        self._http = httpx.AsyncClient(
            base_url=self.url,
            verify=self.verify_ssl,
            timeout=60.0,
        )

    def _auth_headers(self) -> dict[str, str]:
        if self.api_key:
            return {"X-API-KEY": self.api_key}
        return {}

    def _basic_auth(self) -> httpx.BasicAuth | None:
        if not self.api_key and self.user and self.password:
            return httpx.BasicAuth(self.user, self.password)
        return None

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        kwargs.setdefault("headers", {}).update(self._auth_headers())
        auth = self._basic_auth()
        if auth:
            kwargs["auth"] = auth
        resp = await self._http.request(method, path, **kwargs)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "err":
            raise RuntimeError(f"Synapse error [{data.get('code')}]: {data.get('mesg')}")
        return data.get("result", data)

    def _merge_opts(self, opts: dict | None = None, view: str | None = None) -> dict | None:
        """Merge view into opts, preferring explicit view > opts view > default_view."""
        if view and not _IDEN_RE.match(view):
            raise ValueError(f"view must be a 32-char hex iden, got: {view!r}")
        effective_view = view or (opts.get("view") if opts else None) or self.default_view
        if not effective_view and not opts:
            return None
        merged = dict(opts) if opts else {}
        if effective_view:
            merged["view"] = effective_view
        return merged or None

    async def storm_call(self, query: str, opts: dict | None = None, view: str | None = None) -> dict:
        """Execute a Storm query via /api/v1/storm/call (single return value)."""
        body: dict = {"query": query}
        merged = self._merge_opts(opts, view)
        if merged:
            body["opts"] = merged
        return await self._request("GET", "/api/v1/storm/call", json=body)

    async def storm(self, query: str, opts: dict | None = None, view: str | None = None) -> list[dict]:
        """Execute a Storm query via /api/v1/storm and collect streamed messages."""
        body: dict = {"query": query, "stream": "jsonlines"}
        merged = self._merge_opts(opts, view)
        if merged:
            body["opts"] = merged

        headers = self._auth_headers()
        auth = self._basic_auth()
        kwargs: dict = {"headers": headers, "json": body}
        if auth:
            kwargs["auth"] = auth

        import json as _json

        messages: list[dict] = []
        async with self._http.stream("GET", "/api/v1/storm", **kwargs) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.strip():
                    continue
                msg = _json.loads(line)
                messages.append(msg)
        return messages

    async def get_model(self) -> dict:
        """Fetch the full Synapse data model."""
        return await self._request("GET", "/api/v1/model")

    async def get_model_norm(self, prop: str, value) -> dict:
        """Normalize a value according to the data model."""
        return await self._request("POST", "/api/v1/model/norm", json={"prop": prop, "value": value})

    async def get_cortex_info(self) -> dict:
        """Get Cortex version and feature info."""
        return await self._request("GET", "/api/v1/core/info")

    async def storm_nodes(self, query: str, opts: dict | None = None, view: str | None = None) -> list[dict]:
        """Execute a Storm query and return parsed node dicts."""
        messages = await self.storm(query, opts=opts, view=view)
        return parse_nodes(messages)

    async def storm_count(self, query: str, opts: dict | None = None, view: str | None = None) -> int | None:
        """Execute a Storm query piped to count and return the integer result."""
        import re

        if not query.rstrip().endswith("| count"):
            query = f"{query} | count"
        messages = await self.storm(query, opts=opts, view=view)
        prints = parse_print_messages(messages)
        for p in prints:
            # Handle "Counted N nodes." format from Storm count command
            m = re.search(r"(\d[\d,]*)", p)
            if m:
                return int(m.group(1).replace(",", ""))
        return None

    async def list_views(self) -> list[dict]:
        """List all views in the Cortex."""
        return await self.storm_call("return($lib.view.list())")

    async def close(self):
        await self._http.aclose()
