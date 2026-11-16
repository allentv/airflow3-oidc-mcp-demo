"""OAuth 2.1 / OIDC resource-server layer for the Airflow 3 MCP server.

What lives here (spec numbers matter for the talk):

* RFC 9728 Protected Resource Metadata  -> ``/.well-known/oauth-protected-resource``
* RFC 8414 Authorization Server Metadata -> proxied from Keycloak, then *filtered and
  normalized* so MCP clients (Inspector, Claude Desktop) don't choke on enterprise IdP
  quirks: 40-scope lists, a Dynamic Client Registration endpoint we don't want clients
  to use, and an issuer that must match the document URL.
* RFC 7591 Dynamic Client Registration   -> static response for one pre-registered
  public PKCE client (``mcp-public``); Keycloak's own DCR endpoint stays hidden.
* Bearer JWT validation against Keycloak's JWKS: signature, issuer, audience, expiry.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx
import jwt as pyjwt

# ── Configuration (override via environment; see .env.example) ─────────────────
# The *_PUBLIC_URL values are what a browser sees; KEYCLOAK_INTERNAL_URL is what
# this container uses for JWKS/discovery (docker-internal DNS).
MCP_PUBLIC_URL = os.getenv("MCP_PUBLIC_URL", "http://localhost:8081").rstrip("/")
MCP_RESOURCE = os.getenv("MCP_RESOURCE", f"{MCP_PUBLIC_URL}/mcp")
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "http://localhost:8080/realms/airflow-demo").rstrip("/")
KEYCLOAK_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", OIDC_ISSUER).rstrip("/")
KEYCLOAK_PUBLIC_URL = os.getenv("KEYCLOAK_PUBLIC_URL", OIDC_ISSUER).rstrip("/")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "mcp-public")

# The only scopes this resource server understands. Keycloak (like Okta) happily
# advertises dozens more; we filter them out of every document we publish.
SUPPORTED_SCOPES = ("openid", "profile", "email", "offline_access")

# Pre-registered redirect targets for local MCP clients (Inspector, playgrounds).
STATIC_REDIRECT_URIS = (
    "http://localhost:5173/*",
    "http://127.0.0.1:5173/*",
    "http://localhost:3000/*",
    "http://127.0.0.1:3000/*",
)

_METADATA_TTL_SECONDS = 300.0
_JWKS_TTL_SECONDS = 300.0
_REFRESH_MIN_INTERVAL_SECONDS = 10.0  # rate-limit forced JWKS refreshes


class OAuthError(Exception):
    """An RFC 6750 error, rendered as a 401 with a WWW-Authenticate header."""

    def __init__(self, error: str, description: str, status_code: int = 401) -> None:
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status_code = status_code


def _client() -> httpx.AsyncClient:
    client = getattr(_client, "instance", None)
    if client is None:
        client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        _client.instance = client
    return client


_as_metadata_cache: dict[str, Any] = {"fetched_at": 0.0, "data": None}
_jwks_cache: dict[str, Any] = {"fetched_at": 0.0, "by_kid": {}}


# ── RFC 9728: Protected Resource Metadata (static) ─────────────────────────────

def protected_resource_metadata() -> dict[str, Any]:
    """Advertise this MCP server as a protected resource (RFC 9728 §2).

    A 401 from ``/mcp`` points clients here; ``authorization_servers`` points at
    this host, where the *filtered* AS metadata is served.
    """
    return {
        "resource": MCP_RESOURCE,
        "authorization_servers": [MCP_PUBLIC_URL],
        "scopes_supported": list(SUPPORTED_SCOPES),
        "bearer_methods_supported": ["header"],
    }


# ── RFC 8414: Authorization Server Metadata (proxied + normalized) ─────────────

async def _idp_discovery() -> dict[str, Any]:
    """Fetch Keycloak's OIDC discovery document (cached)."""
    now = time.monotonic()
    if _as_metadata_cache["data"] is not None and now - _as_metadata_cache["fetched_at"] < _METADATA_TTL_SECONDS:
        return _as_metadata_cache["data"]
    url = f"{KEYCLOAK_INTERNAL_URL}/.well-known/openid-configuration"
    try:
        response = await _client().get(url)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise OAuthError("server_error", f"cannot reach IdP discovery document: {exc}", status_code=503) from exc
    _as_metadata_cache["fetched_at"] = now
    _as_metadata_cache["data"] = response.json()
    return _as_metadata_cache["data"]


async def authorization_server_metadata() -> dict[str, Any]:
    """RFC 8414 metadata as MCP clients should see it.

    Normalization layer for real-world enterprise IdP quirks:

    * ``issuer`` is rewritten to *this* document's URL (RFC 8414 §3.3: the issuer
      must equal the metadata URL, but the token's ``iss`` stays Keycloak's — the
      resource server is the one that checks that).
    * ``scopes_supported`` is filtered to what this stack actually enforces.
    * Keycloak's ``registration_endpoint`` is replaced with ours: clients must land
      on the pre-registered public PKCE client instead of minting rogue clients.
    * endpoints are pinned to explicit values instead of IdP-generated ones.
    """
    idp = await _idp_discovery()
    idp_scopes = set(idp.get("scopes_supported", ())) | {"openid"}
    return {
        "issuer": MCP_PUBLIC_URL,
        "authorization_endpoint": f"{KEYCLOAK_PUBLIC_URL}/protocol/openid-connect/auth",
        "token_endpoint": f"{KEYCLOAK_PUBLIC_URL}/protocol/openid-connect/token",
        "jwks_uri": f"{KEYCLOAK_PUBLIC_URL}/protocol/openid-connect/certs",
        "registration_endpoint": f"{MCP_PUBLIC_URL}/oauth/register",
        "scopes_supported": [s for s in SUPPORTED_SCOPES if s in idp_scopes],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "revocation_endpoint": f"{KEYCLOAK_PUBLIC_URL}/protocol/openid-connect/revoke",
        "userinfo_endpoint": f"{KEYCLOAK_PUBLIC_URL}/protocol/openid-connect/userinfo",
    }


# ── RFC 7591: static Dynamic Client Registration for one public PKCE client ────

def static_client_registration() -> dict[str, Any]:
    """A deterministic registration response: the pre-shared public PKCE client."""
    now = int(time.time())
    return {
        "client_id": OIDC_CLIENT_ID,
        "client_id_issued_at": now,
        "redirect_uris": list(STATIC_REDIRECT_URIS),
        "token_endpoint_auth_method": "none",  # public client + PKCE (S256)
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": " ".join(SUPPORTED_SCOPES),
        "application_type": "web",
        "client_uri": MCP_PUBLIC_URL,
    }


# ── Bearer JWT validation against Keycloak's JWKS ──────────────────────────────

async def _jwks_by_kid(force_refresh: bool = False) -> dict[str, dict[str, Any]]:
    """JWKS keyed by ``kid``, cached for 5 minutes with a rate-limited forced refresh."""
    now = time.monotonic()
    stale = now - _jwks_cache["fetched_at"] > _JWKS_TTL_SECONDS
    if _jwks_cache["by_kid"] and not force_refresh and not stale:
        return _jwks_cache["by_kid"]
    if force_refresh and now - _jwks_cache["fetched_at"] < _REFRESH_MIN_INTERVAL_SECONDS:
        return _jwks_cache["by_kid"]  # a flood of unknown kids must not hammer the IdP
    url = f"{KEYCLOAK_INTERNAL_URL}/protocol/openid-connect/certs"
    try:
        response = await _client().get(url)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise OAuthError("server_error", f"cannot reach IdP JWKS: {exc}", status_code=503) from exc
    keys: dict[str, dict[str, Any]] = {}
    for jwk in response.json().get("keys", []):
        if jwk.get("kid") and jwk.get("kty") == "RSA":
            keys[jwk["kid"]] = jwk
    _jwks_cache["fetched_at"] = now
    _jwks_cache["by_kid"] = keys
    return keys


async def validate_bearer(token: str) -> dict[str, Any]:
    """Validate a Keycloak access token: signature (JWKS), issuer, audience, expiry."""
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.InvalidTokenError as exc:
        raise OAuthError("invalid_token", f"malformed bearer token: {exc}") from exc

    kid = header.get("kid")
    keys = await _jwks_by_kid()
    jwk = keys.get(kid) if kid else None
    if jwk is None:  # key rotation: refresh once, then give up
        keys = await _jwks_by_kid(force_refresh=True)
        jwk = keys.get(kid) if kid else None
    if jwk is None:
        raise OAuthError("invalid_token", "token signed with an unknown key (kid)")

    key = pyjwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    try:
        return pyjwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=OIDC_ISSUER,
            audience=MCP_RESOURCE,  # RFC 8707 resource indicator
            leeway=10,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise OAuthError("invalid_token", "token expired") from exc
    except pyjwt.InvalidIssuerError as exc:
        raise OAuthError("invalid_token", f"issuer must be {OIDC_ISSUER}") from exc
    except pyjwt.InvalidAudienceError as exc:
        raise OAuthError("invalid_token", f"audience must include {MCP_RESOURCE}") from exc
    except pyjwt.PyJWTError as exc:
        raise OAuthError("invalid_token", str(exc)) from exc


# ── 401 responses (RFC 6750 + MCP "WWW-Authenticate" discovery) ────────────────

def www_authenticate(error: OAuthError | None = None) -> str:
    """Build the WWW-Authenticate header that steers MCP clients to discovery."""
    metadata = f'{MCP_PUBLIC_URL}/.well-known/oauth-protected-resource'
    parts = [f'Bearer resource_metadata="{metadata}"']
    if error is not None:
        description = error.description.replace('"', "'")
        parts.append(f'error="{error.error}"')
        parts.append(f'error_description="{description}"')
    return ", ".join(parts)


def unauthorized_body(error: OAuthError | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"resource_metadata": f"{MCP_PUBLIC_URL}/.well-known/oauth-protected-resource"}
    if error is not None:
        body["error"] = error.error
        body["error_description"] = error.description
    else:
        body["error_description"] = "Bearer token required (MCP OAuth 2.1 flow)"
    return body