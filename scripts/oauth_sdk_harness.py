#!/usr/bin/env python3
"""MCP SDK harness: real OAuth against the live stack.

Flow (no browser):
  1. Official MCP Python SDK client hits POST /mcp unauthenticated.
  2. SDK sees 401 -> RFC 9728 protected-resource metadata -> RFC 8414 AS metadata
     -> RFC 7591 dynamic registration (our static /oauth/register -> mcp-public).
  3. Authorization-code + S256 PKCE against Keycloak; the redirect_handler plays the
     browser: GET the authorize URL, POST the login form with alice's credentials,
     capture ?code= from the callback redirect.
  4. Token exchange, then a real MCP session: initialize, list_tools, call_tool.
  5. RBAC: alice (airflow-viewer) may list DAGs, must be denied trigger_dag_run.
"""
from __future__ import annotations

import asyncio
import html
import json
import re
import sys
import urllib.parse

import httpx
from mcp.client.auth import (
    AuthorizationCodeResult,
    OAuthClientProvider,
    TokenStorage,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.auth import OAuthClientMetadata

MCP_URL = "http://localhost:8081/mcp"
CALLBACK = "http://localhost:5173/callback"
CALLBACK_BASE = "http://localhost:5173/"
USERNAME, PASSWORD = "alice", "alice-demo"

failures: list[str] = []


def ok(name: str, cond: bool, extra: object = "") -> None:
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f"  -> {str(extra)[:400]}"))
    if not cond:
        failures.append(name)


class Memory(TokenStorage):
    def __init__(self) -> None:
        self._tokens = None
        self._info = None

    async def get_tokens(self):
        return self._tokens

    async def set_tokens(self, tokens) -> None:
        self._tokens = tokens

    async def get_client_info(self):
        return self._info

    async def set_client_info(self, info) -> None:
        self._info = info


captured: dict[str, str | None] = {"code": None, "state": None, "iss": None}


def _capture(location: str) -> bool:
    if not location.startswith(CALLBACK_BASE):
        return False
    q = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    captured["code"] = q.get("code", [None])[0]
    captured["state"] = q.get("state", [None])[0]
    captured["iss"] = q.get("iss", [None])[0]
    return True


def _strip_secure(hc: httpx.AsyncClient) -> None:
    # Keycloak marks cookies Secure even on plain http; httpx stores them but
    # refuses to send them over http -> KC rejects the login POST (cookie_not_found).
    for cookie in hc.cookies.jar:
        cookie.secure = False


async def open_authorization_url(url: str) -> None:
    """redirect_handler: behave like a browser walking the Keycloak login form."""

    async def get(client: httpx.AsyncClient, target: str) -> httpx.Response:
        resp = await client.get(target)
        _strip_secure(client)
        return resp

    async def post(client: httpx.AsyncClient, target: str, data: dict[str, str]) -> httpx.Response:
        resp = await client.post(target, data=data)
        _strip_secure(client)
        return resp

    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as hc:
        r = await get(hc, url)
        for _ in range(10):
            if r.status_code not in (301, 302, 303, 307, 308):
                break
            if _capture(r.headers.get("location", "")):
                return
            r = await get(hc, r.headers["location"])
        m = re.search(r'<form[^>]*action="([^"]+)"', r.text)
        if not m:
            raise RuntimeError(f"no login form found (status={r.status_code})")
        action = html.unescape(urllib.parse.urljoin(str(r.url), m.group(1)))
        r = await post(hc, action, {"username": USERNAME, "password": PASSWORD})
        for _ in range(10):
            if r.status_code not in (301, 302, 303, 307, 308):
                break
            if _capture(r.headers.get("location", "")):
                return
            r = await get(hc, r.headers["location"])
        raise RuntimeError(f"never reached callback: {r.status_code} {r.text[:300]}")


async def wait_for_callback() -> AuthorizationCodeResult:
    if not captured["code"]:
        raise RuntimeError("no authorization code captured")
    # RFC 9207: Keycloak stamps iss=its own issuer, but our filtered AS metadata
    # (RFC 8414 §3.3) declares issuer=http://localhost:8081 — strict comparison
    # fails by construction behind a metadata-normalizing proxy. We don't advertise
    # authorization_response_iss_parameter_supported, so omitting iss is valid and
    # matches how today's MCP clients behave.
    return AuthorizationCodeResult(code=captured["code"], state=captured["state"], iss=None)


def tool_text(result) -> str:
    return "\n".join(getattr(c, "text", "") for c in (result.content or []))


async def main() -> int:
    storage = Memory()
    oauth = OAuthClientProvider(
        server_url=MCP_URL,
        client_metadata=OAuthClientMetadata(
            redirect_uris=[CALLBACK],
            client_name="mcp-oauth-harness",
            scope="openid profile email",
            token_endpoint_auth_method="none",
        ),
        storage=storage,
        redirect_handler=open_authorization_url,
        callback_handler=wait_for_callback,
    )

    http_client = create_mcp_http_client(auth=oauth)
    async with streamable_http_client(MCP_URL, http_client=http_client) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            server = getattr(init, "server_info", None)
            ok("SDK initialize", server is not None, init)
            print(f"      server: {getattr(server, 'name', '?')} protocol={init.protocol_version}")

            ok("static DCR used pre-registered client",
               storage._info is not None and storage._info.client_id == "mcp-public",
               getattr(storage._info, "client_id", None))

            tok = storage._tokens
            ok("token received via auth-code + PKCE", tok is not None and bool(tok.access_token))
            if tok:
                payload = tok.access_token.split(".")[1]
                payload += "=" * (-len(payload) % 4)
                import base64
                claims = json.loads(base64.urlsafe_b64decode(payload))
                print(f"      aud={claims.get('aud')} groups={claims.get('groups')} scope={claims.get('scope')}")
                ok("claims: audience + airflow-viewer group",
                   claims.get("aud") == "http://localhost:8081/mcp" and claims.get("groups") == ["airflow-viewer"], claims)

            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            ok("tools/list via SDK", names == ["get_dag_runs", "get_task_logs", "list_dags", "trigger_dag_run"], names)

            res = await session.call_tool("list_dags", {"limit": 10})
            text = tool_text(res)
            ok("call list_dags (allowed)", not res.is_error and "demo_report" in text, text[:300])

            res = await session.call_tool("trigger_dag_run", {"dag_id": "demo_report"})
            text = tool_text(res)
            ok("call trigger_dag_run denied for viewer",
               bool(res.is_error) and "airflow-operator" in text and "airflow-viewer" in text, text[:300])
            print(f"      denial: {text.splitlines()[-1][:220] if text else '(empty)'}")

    print()
    print("FAILURES:", failures if failures else "none — OAuth + MCP SDK harness fully passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
