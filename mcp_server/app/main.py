"""FastAPI app: MCP Streamable HTTP endpoint + OAuth 2.1 discovery/validation layer.

Request flow:

    MCP client                FastAPI (this file)               Keycloak / Airflow
    ───────────               ─────────────────────             ──────────────────
    POST /mcp  ───────────►   OAuthBearerMiddleware
                                ├─ no/invalid Bearer ── 401 + WWW-Authenticate
                                │    resource_metadata=… (RFC 9728 discovery)
                                └─ valid JWT ── claims into contextvar
                                                   │
                              MCP tool (main.py) ── rbac.authorize(tool)
                                                   │  ok
                              airflow_client ──────┴── POST /auth/token → /api/v2/...
    GET /.well-known/*  ───►  static/filtered OAuth metadata (no auth required)
"""

from __future__ import annotations

import contextlib
import json
import os
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from app import airflow_client, oauth, rbac

# ── MCP server + tools ─────────────────────────────────────────────────────────

mcp = MCPServer(
    "airflow3-oidc-mcp",
    instructions=(
        "Airflow 3 REST API v2 tools guarded by Keycloak OAuth 2.1 tokens. "
        "Read tools require group 'airflow-viewer'; trigger_dag_run requires 'airflow-operator'."
    ),
)

_READ_ONLY = ToolAnnotations(**{"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
_WRITE = ToolAnnotations(**{"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})


@mcp.tool(annotations=_READ_ONLY)
async def list_dags(limit: int = 25, only_active: bool = True) -> dict[str, Any]:
    """List DAGs from Airflow 3 (GET /api/v2/dags). Requires group 'airflow-viewer'."""
    rbac.authorize("list_dags")
    return await airflow_client.list_dags(limit=limit, only_active=only_active)


@mcp.tool(annotations=_READ_ONLY)
async def get_dag_runs(dag_id: str, limit: int = 20, state: str | None = None) -> dict[str, Any]:
    """List DAG runs for a DAG (GET /api/v2/dags/{dag_id}/dagRuns). Requires group 'airflow-viewer'."""
    rbac.authorize("get_dag_runs")
    return await airflow_client.get_dag_runs(dag_id=dag_id, limit=limit, state=state)


@mcp.tool(annotations=_READ_ONLY)
async def get_task_logs(
    dag_id: str,
    dag_run_id: str,
    task_id: str,
    try_number: int = 1,
    full_content: bool = False,
) -> dict[str, Any]:
    """Fetch one task's log text (GET /api/v2/.../logs/{try_number}). Requires group 'airflow-viewer'."""
    rbac.authorize("get_task_logs")
    return await airflow_client.get_task_logs(
        dag_id=dag_id,
        dag_run_id=dag_run_id,
        task_id=task_id,
        try_number=try_number,
        full_content=full_content,
    )


@mcp.tool(annotations=_WRITE)
async def trigger_dag_run(
    dag_id: str,
    conf: dict[str, Any] | None = None,
    dag_run_id: str | None = None,
) -> dict[str, Any]:
    """Trigger a DAG run (POST /api/v2/dags/{dag_id}/dagRuns). Requires group 'airflow-operator'."""
    rbac.authorize("trigger_dag_run")
    return await airflow_client.trigger_dag_run(dag_id=dag_id, conf=conf, dag_run_id=dag_run_id)


# ── Bearer auth middleware (ASGI, outside the MCP transport) ───────────────────


async def _send_unauthorized(send: Any, error: oauth.OAuthError | None) -> None:
    status = error.status_code if error is not None else 401
    body = json.dumps(oauth.unauthorized_body(error)).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", oauth.www_authenticate(error).encode()),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class OAuthBearerMiddleware:
    """Terminate Bearer auth on /mcp before the MCP transport sees the request.

    Missing token -> 401 whose WWW-Authenticate carries the RFC 9728
    resource_metadata URL (this is what starts MCP OAuth discovery).
    Invalid token -> 401 with the RFC 6750 error. Valid token -> claims are
    stored in a ContextVar that rbac.authorize() reads inside tool calls.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return
        if not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        authorization = headers.get("authorization")
        error: oauth.OAuthError | None = None
        claims: dict[str, Any] | None = None

        if authorization:
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer":
                try:
                    claims = await oauth.validate_bearer(value.strip())
                except oauth.OAuthError as exc:
                    error = exc
            else:
                error = oauth.OAuthError("invalid_request", "unsupported authorization scheme; use Bearer")

        if claims is None:
            await _send_unauthorized(send, error)
            return

        claim_token = rbac.current_claims.set(claims)
        try:
            await self.app(scope, receive, send)
        finally:
            rbac.current_claims.reset(claim_token)


# ── App wiring ─────────────────────────────────────────────────────────────────

_allowed_origins = [
    o.strip()
    for o in os.getenv(
        "MCP_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if o.strip()
]
_allowed_hosts = [
    h.strip()
    for h in os.getenv("MCP_ALLOWED_HOSTS", "localhost:8081,127.0.0.1:8081").split(",")
    if h.strip()
]

# Build the MCP Streamable HTTP sub-app first: mcp.session_manager only exists
# after streamable_http_app() has been called.
mcp_http_app = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    stateless_http=True,
    transport_security=TransportSecuritySettings(
        allowed_hosts=_allowed_hosts,
        allowed_origins=_allowed_origins,
    ),
)


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    # A mounted sub-app's own lifespan never runs: the top-level app must own it.
    async with mcp.session_manager.run():
        yield


app = FastAPI(title="Airflow 3 OIDC MCP demo", version="0.1.0", lifespan=lifespan)

# Innermost first: auth runs for /mcp; CORS wraps everything (browser preflights
# are answered before auth sees them).
app.add_middleware(OAuthBearerMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Mcp-Session-Id"],
)


def _metadata_error(exc: oauth.OAuthError) -> JSONResponse:
    return JSONResponse(
        {"error": exc.error, "error_description": exc.description},
        status_code=exc.status_code,
    )


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource() -> dict[str, Any]:
    """RFC 9728 Protected Resource Metadata (root and /mcp path variants)."""
    return oauth.protected_resource_metadata()


@app.get("/.well-known/oauth-authorization-server", response_model=None)
@app.get("/.well-known/openid-configuration", response_model=None)
async def authorization_server() -> dict[str, Any] | JSONResponse:
    """Filtered/normalized AS metadata; OIDC discovery is served as an alias."""
    try:
        return await oauth.authorization_server_metadata()
    except oauth.OAuthError as exc:
        return _metadata_error(exc)


@app.api_route("/oauth/register", methods=["GET", "POST"])
async def register() -> dict[str, Any]:
    """RFC 7591-style registration: always returns the pre-registered PKCE client."""
    return oauth.static_client_registration()


# Mount last: FastAPI's own routes win, everything else falls through to MCP.
app.mount("/", mcp_http_app)