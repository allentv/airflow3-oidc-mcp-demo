"""Async client for the Airflow 3 REST API v2.

Airflow 3's public API authenticates with JWTs minted by its auth manager:
``POST /auth/token {username, password} -> {access_token}`` (simple auth manager
here; swap the endpoint for your real IdP in production).

Least privilege: reads use ``mcp-reader`` (viewer role), ``trigger_dag_run`` uses
``mcp-writer`` (op role). Even if the MCP-side RBAC were bypassed, the write
identity could not do what its Airflow role forbids — and vice versa.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib.parse import quote

import httpx
import jwt as pyjwt

# ToolError: deliberate failures (unknown DAG, 409, ...) reach the MCP client
# with this message; anything else would show up as a generic crash instead.
from mcp.server.mcpserver.exceptions import ToolError

AIRFLOW_BASE_URL = os.getenv("AIRFLOW_BASE_URL", "http://airflow:8080").rstrip("/")
READER = {
    "username": os.getenv("AIRFLOW_READER_USERNAME", "mcp-reader"),
    "password": os.getenv("AIRFLOW_READER_PASSWORD", "reader-demo"),
}
WRITER = {
    "username": os.getenv("AIRFLOW_WRITER_USERNAME", "mcp-writer"),
    "password": os.getenv("AIRFLOW_WRITER_PASSWORD", "writer-demo"),
}

MAX_LOG_CHARS = 50_000  # keep tool results MCP-friendly
_DAG_FIELDS = ("dag_id", "description", "is_paused", "tags", "owners")
_RUN_FIELDS = ("dag_run_id", "state", "logical_date", "note")


class AirflowAPIError(ToolError):
    """Airflow answered with an error; the message is safe to show the client."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"Airflow API {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


_client: httpx.AsyncClient | None = None
_tokens: dict[str, tuple[str, float]] = {}  # role -> (jwt, monotonic expiry)


def _http() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
    return _client


def _token_expiry(token: str) -> float:
    """Seconds until expiry, read without signature verification (we just minted it)."""
    claims = pyjwt.decode(token, options={"verify_signature": False}, algorithms=["RS256", "HS256"])
    return max(float(claims["exp"]) - time.time(), 0.0) if "exp" in claims else 60.0


async def _access_token(role: str) -> str:
    cached = _tokens.get(role)
    if cached is not None and cached[1] > time.monotonic() + 30:
        return cached[0]
    creds = READER if role == "reader" else WRITER
    try:
        response = await _http().post(f"{AIRFLOW_BASE_URL}/auth/token", json=creds)
    except httpx.HTTPError as exc:
        raise AirflowAPIError(0, f"cannot reach Airflow at {AIRFLOW_BASE_URL}: {exc}") from exc
    if response.status_code >= 400:
        raise AirflowAPIError(
            response.status_code,
            f"/auth/token rejected {creds['username']!r}: {response.text[:200]}",
        )
    token = response.json()["access_token"]
    _tokens[role] = (token, time.monotonic() + _token_expiry(token))
    return token


async def _request(
    method: str,
    path: str,
    *,
    role: str = "reader",
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Any:
    """Call Airflow, refreshing our own JWT once on a 401/403 (expired or rotated service key)."""
    for attempt in (1, 2):
        headers = {"Authorization": f"Bearer {await _access_token(role)}"}
        headers.update(kwargs.pop("headers", {}))
        try:
            response = await _http().request(method, f"{AIRFLOW_BASE_URL}{path}", headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise AirflowAPIError(0, f"cannot reach Airflow at {AIRFLOW_BASE_URL}: {exc}") from exc
        if response.status_code in (401, 403) and attempt == 1:
            _tokens.pop(role, None)  # stale Airflow JWT (expired/rotated): mint a fresh one, retry once
            continue
        if response.status_code not in expected:
            raise AirflowAPIError(response.status_code, _error_detail(response))
        return response.json() if response.content else {}
    raise AssertionError("unreachable")


def _error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
        return str(payload.get("detail") or payload.get("message") or payload)[:500]
    except ValueError:
        return response.text[:500]


# ── Tools (thin wrappers over Airflow 3 REST API v2) ───────────────────────────

async def list_dags(limit: int = 25, only_active: bool = True) -> dict[str, Any]:
    """GET /api/v2/dags"""
    data = await _request(
        "GET",
        "/api/v2/dags",
        params={"limit": limit, "only_active": only_active, "order_by": "dag_id"},
    )
    dags = [{k: v for k, v in dag.items() if k in _DAG_FIELDS} for dag in data.get("dags", [])]
    return {"total_entries": data.get("total_entries", len(dags)), "dags": dags}


async def get_dag_runs(dag_id: str, limit: int = 20, state: str | None = None) -> dict[str, Any]:
    """GET /api/v2/dags/{dag_id}/dagRuns (newest first; AF3 allows e.g. start_date, not execution_date)"""
    params: dict[str, Any] = {"limit": limit, "order_by": "-start_date"}
    if state:
        params["state"] = state
    data = await _request(
        "GET",
        f"/api/v2/dags/{quote(dag_id, safe='')}/dagRuns",
        params=params,
        expected=(200, 404),
    )
    if "dag_runs" not in data:  # 404: unknown dag
        raise AirflowAPIError(404, f"unknown dag_id {dag_id!r}")
    runs = [{k: v for k, v in run.items() if k in _RUN_FIELDS} for run in data["dag_runs"]]
    return {"total_entries": data.get("total_entries", len(runs)), "dag_runs": runs}


async def get_task_logs(
    dag_id: str, dag_run_id: str, task_id: str, try_number: int = 1, full_content: bool = False
) -> dict[str, Any]:
    """GET /api/v2/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances/{task_id}/logs/{try_number}"""
    path = (
        f"/api/v2/dags/{quote(dag_id, safe='')}"
        f"/dagRuns/{quote(dag_run_id, safe='')}"
        f"/taskInstances/{quote(task_id, safe='')}"
        f"/logs/{max(try_number, 0)}"
    )
    data = await _request(
        "GET",
        path,
        params={"full_content": full_content},
        headers={"Accept": "application/json"},
        expected=(200, 400, 404, 409),
    )
    if "content" not in data:
        raise AirflowAPIError(404, f"no log for {dag_id}/{dag_run_id}/{task_id} try {try_number}")
    log = _render_log_content(data["content"])
    truncated = len(log) > MAX_LOG_CHARS
    result: dict[str, Any] = {
        "dag_id": dag_id,
        "dag_run_id": dag_run_id,
        "task_id": task_id,
        "try_number": try_number,
        "truncated": truncated,
        "log": log[:MAX_LOG_CHARS],
    }
    if data.get("continuation_token"):
        result["continuation_token"] = data["continuation_token"]
    return result


def _render_log_content(content: Any) -> str:
    """AF3 returns structured log events (dicts); render them as readable lines."""
    if not isinstance(content, list):
        return str(content)
    lines: list[str] = []
    for item in content:
        if isinstance(item, dict):
            text = item.get("message") or item.get("event") or json.dumps(item, ensure_ascii=False)
            timestamp = item.get("timestamp")
            lines.append(f"{timestamp} {text}" if timestamp else str(text))
        else:
            lines.append(str(item))
    return "\n".join(lines)


async def trigger_dag_run(dag_id: str, conf: dict[str, Any] | None = None, dag_run_id: str | None = None) -> dict[str, Any]:
    """POST /api/v2/dags/{dag_id}/dagRuns (writer identity only)."""
    body: dict[str, Any] = {"logical_date": None, "conf": conf or {}}
    if dag_run_id:
        body["dag_run_id"] = dag_run_id
    data = await _request(
        "POST",
        f"/api/v2/dags/{quote(dag_id, safe='')}/dagRuns",
        role="writer",
        json=body,
        expected=(200, 409),
    )
    if "dag_run_id" not in data:
        raise AirflowAPIError(409, f"dag run may already exist for {dag_id!r}: {str(data)[:200]}")
    return {
        "dag_run_id": data.get("dag_run_id"),
        "dag_id": dag_id,
        "state": data.get("state"),
        "logical_date": data.get("logical_date"),
    }