"""RBAC: map Keycloak group claims to MCP tool permissions.

Keycloak's group claim (``groups``, from ``oidc-group-membership-mapper``) is the
single source of truth. This module is intentionally small enough to drop on a
slide: one dict, one check, one clear error message.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

# ToolError (official MCP SDK): its message is returned to the client in the
# tool-call error result instead of being swallowed as an unexpected crash.
from mcp.server.mcpserver.exceptions import ToolError

VIEWER_GROUP = "airflow-viewer"      # read-only tools
OPERATOR_GROUP = "airflow-operator"  # read + write tools

# Which Keycloak groups may invoke each tool. Operators are a superset of viewers.
TOOL_ACCESS: dict[str, frozenset[str]] = {
    "list_dags": frozenset({VIEWER_GROUP, OPERATOR_GROUP}),
    "get_dag_runs": frozenset({VIEWER_GROUP, OPERATOR_GROUP}),
    "get_task_logs": frozenset({VIEWER_GROUP, OPERATOR_GROUP}),
    "trigger_dag_run": frozenset({OPERATOR_GROUP}),
}

# Claims of the bearer token that authorized the in-flight MCP request.
# Set by the auth middleware in main.py; read by every tool.
current_claims: ContextVar[dict[str, Any] | None] = ContextVar("mcp_current_claims", default=None)


class AuthorizationError(ToolError):
    """Tool-call denial; the message is surfaced verbatim to the MCP client."""


def token_groups(claims: dict[str, Any]) -> frozenset[str]:
    """Extract the Keycloak ``groups`` claim (missing claim => no groups)."""
    groups = claims.get("groups") or []
    return frozenset(str(g) for g in groups)


def authorize(tool_name: str) -> dict[str, Any]:
    """Allow the call only if the token carries one of the tool's groups.

    Returns the token claims on success; raises AuthorizationError otherwise.
    """
    claims = current_claims.get()
    if claims is None:
        raise AuthorizationError("no authenticated token on this request")

    allowed = TOOL_ACCESS.get(tool_name)
    if allowed is None:
        raise AuthorizationError(f"tool {tool_name!r} is not registered in the RBAC map")

    groups = token_groups(claims)
    if not groups & allowed:
        need = ", ".join(sorted(allowed)) or "none"
        have = ", ".join(sorted(groups)) or "none"
        raise AuthorizationError(
            f"denied: tool {tool_name!r} requires Keycloak group [{need}]; token groups: [{have}]"
        )
    return claims