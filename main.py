"""
API to MCP Engine — Central Server & Gateway
============================================
Handles Stateless OAuth 2.0 PKCE gatekeeping for Google Gemini Web Connectors
and routes /mcp traffic by Subdomain Host Header.
"""

import base64
import contextlib
import hashlib
import importlib
import logging
import os
import pkgutil
import secrets
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import jwt
from starlette.types import ASGIApp, Receive, Scope, Send

import connectors

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("mcp_engine")

JWT_SECRET = os.environ.get("JWT_SECRET", "super_secret_jwt_signing_key_please_change_in_production")
OAUTH_ADMIN_PIN = os.environ.get("OAUTH_ADMIN_PIN", "123456").strip()

# -----------------------------------------------------------------------------
# Dynamic Connector Discovery & FastMCP Setup
# -----------------------------------------------------------------------------
_connectors: Dict[str, Any] = {}
_connector_apps: Dict[str, Any] = {}

for finder, name, ispkg in pkgutil.iter_modules(connectors.__path__):
    if name.endswith("_mcp"):
        service_name = name[:-4].lower()  # strip '_mcp'
        try:
            mod = importlib.import_module(f"connectors.{name}")
            if hasattr(mod, "mcp"):
                _connectors[service_name] = mod.mcp
                # Build FastMCP HTTP App with streamable-http transport
                _connector_apps[service_name] = mod.mcp.http_app(
                    transport="streamable-http",
                    stateless_http=True,
                    allowed_hosts=["*"],
                    allowed_origins=["*"],
                )
                logger.info(f"Loaded MCP connector: '{service_name}' ({mod.mcp.name})")
        except Exception as e:
            logger.error(f"Failed to load connector '{name}': {e}", exc_info=True)


# -----------------------------------------------------------------------------
# FastAPI Core App & Combined Lifespan
# -----------------------------------------------------------------------------
@contextlib.asynccontextmanager
async def combined_lifespan(app: FastAPI):
    """Manages lifespans of all mounted FastMCP connector instances."""
    async with contextlib.AsyncExitStack() as stack:
        for s_name, sub_app in _connector_apps.items():
            if hasattr(sub_app, "router") and hasattr(sub_app.router, "lifespan_context"):
                try:
                    await stack.enter_async_context(sub_app.router.lifespan_context(sub_app))
                    logger.info(f"Lifespan active for connector: '{s_name}'")
                except Exception as e:
                    logger.warning(f"Note on lifespan for '{s_name}': {e}")
        yield


api_app = FastAPI(
    title="API to MCP Engine",
    description="Stateless OAuth 2.0 PKCE and Subdomain-Routed FastMCP Gateway",
    version="1.0.0",
    lifespan=combined_lifespan,
)


def _get_origin(request: Request) -> str:
    """Extract public scheme and host from headers or URL."""
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{proto}://{host}"


def _verify_jwt(token: str, expected_type: str = "access") -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != expected_type:
            raise HTTPException(status_code=401, detail=f"Invalid token type: expected {expected_type}")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


# -----------------------------------------------------------------------------
# 1. OAuth 2.0 RFC 9728 & RFC 8414 Discovery Endpoints
# -----------------------------------------------------------------------------

@api_app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request):
    """RFC 9728: Informs clients where to find authorization metadata."""
    origin = _get_origin(request)
    return {
        "resource": f"{origin}/mcp",
        "authorization_servers": [origin],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
    }


@api_app.get("/.well-known/oauth-authorization-server")
@api_app.get("/.well-known/openid-configuration")
async def oauth_authorization_server(request: Request):
    """RFC 8414: Exposes OAuth 2.0 and PKCE authorization server capabilities."""
    origin = _get_origin(request)
    return {
        "issuer": origin,
        "authorization_endpoint": f"{origin}/authorize",
        "token_endpoint": f"{origin}/token",
        "registration_endpoint": f"{origin}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "scopes_supported": ["mcp"],
    }


# -----------------------------------------------------------------------------
# 2. Dynamic Client Registration (RFC 7591)
# -----------------------------------------------------------------------------

@api_app.post("/register")
async def dynamic_client_registration(request: Request):
    """Stateless Dynamic Client Registration for Google Gemini Custom Connector."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    client_id = f"mcp-client-{secrets.token_hex(12)}"
    client_secret = secrets.token_hex(32)

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": body.get("client_name", "Gemini MCP Client"),
            "redirect_uris": body.get("redirect_uris", []),
            "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
            "response_types": body.get("response_types", ["code"]),
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,
        },
    )


# -----------------------------------------------------------------------------
# 3. OAuth 2.0 Authorization Endpoint (Browser Approval with PIN)
# -----------------------------------------------------------------------------

AUTHORIZATION_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Authorization & Gatekeeper</title>
    <style>
        :root {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --accent: #38bdf8;
            --success: #10b981;
            --danger: #ef4444;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { background-color: var(--bg); color: var(--text); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1.5rem; }
        .card { background-color: var(--card-bg); border: 1px solid var(--border); border-radius: 1rem; width: 100%; max-width: 460px; padding: 2.2rem; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5), 0 8px 10px -6px rgba(0,0,0,0.5); }
        .badge { display: inline-block; padding: 0.35rem 0.85rem; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; background: rgba(56, 189, 248, 0.15); color: var(--accent); border-radius: 9999px; border: 1px solid rgba(56, 189, 248, 0.3); margin-bottom: 1.2rem; }
        h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem; color: #ffffff; }
        p.subtitle { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.8rem; line-height: 1.5; }
        .details-box { background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border); border-radius: 0.6rem; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; }
        .details-row { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
        .details-row:last-child { margin-bottom: 0; }
        .details-label { color: var(--muted); }
        .details-value { color: var(--accent); font-family: monospace; font-weight: 600; word-break: break-all; text-align: right; margin-left: 0.5rem; }
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.5rem; color: #e2e8f0; }
        input[type="password"], input[type="text"] { width: 100%; padding: 0.85rem 1rem; background: #0f172a; border: 1px solid var(--border); border-radius: 0.5rem; color: #ffffff; font-size: 1rem; letter-spacing: 0.1em; transition: border-color 0.2s; outline: none; }
        input[type="password"]:focus, input[type="text"]:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(56,189,248,0.2); }
        .error-msg { background: rgba(239, 68, 68, 0.15); border: 1px solid var(--danger); color: #fca5a5; padding: 0.75rem 1rem; border-radius: 0.5rem; font-size: 0.85rem; margin-bottom: 1.2rem; }
        .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 0.85rem; }
        button { padding: 0.85rem; border: none; border-radius: 0.5rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: opacity 0.2s, transform 0.1s; }
        button:hover { opacity: 0.9; }
        button:active { transform: scale(0.98); }
        .btn-approve { background-color: var(--success); color: #ffffff; }
        .btn-deny { background-color: transparent; border: 1px solid var(--border); color: var(--muted); }
        .btn-deny:hover { background-color: rgba(239, 68, 68, 0.1); color: var(--danger); border-color: var(--danger); }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">API to MCP Engine</span>
        <h1>Authorize Connector</h1>
        <p class="subtitle">Google Gemini is requesting access to connect with this custom Model Context Protocol (MCP) server.</p>

        <div class="details-box">
            <div class="details-row">
                <span class="details-label">Host</span>
                <span class="details-value">{subdomain_display}</span>
            </div>
            <div class="details-row">
                <span class="details-label">Client ID</span>
                <span class="details-value">{client_id_display}</span>
            </div>
            <div class="details-row">
                <span class="details-label">PKCE S256</span>
                <span class="details-value">{pkce_status}</span>
            </div>
        </div>

        {error_html}

        <form method="POST" action="/authorize">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="response_type" value="{response_type}">
            <input type="hidden" name="scope" value="{scope}">
            <input type="hidden" name="state" value="{state}">
            <input type="hidden" name="code_challenge" value="{code_challenge}">
            <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">

            <div class="form-group">
                <label for="admin_pin">Master Admin PIN</label>
                <input type="password" id="admin_pin" name="admin_pin" placeholder="Enter PIN (e.g. 123456)" required autofocus>
            </div>

            <div class="actions">
                <button type="button" class="btn-deny" onclick="window.location.href='{deny_url}'">Deny</button>
                <button type="submit" class="btn-approve">Approve</button>
            </div>
        </form>
    </div>
</body>
</html>
"""


@api_app.get("/authorize", response_class=HTMLResponse)
async def authorize_get(
    request: Request,
    response_type: str = "code",
    client_id: str = "",
    redirect_uri: str = "",
    scope: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
):
    """Renders the admin approval screen for Google Gemini OAuth setup."""
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "mcp-server"))
    deny_url = f"{redirect_uri}?error=access_denied&state={state}" if redirect_uri else "#"

    html = AUTHORIZATION_HTML.format(
        subdomain_display=host,
        client_id_display=(client_id[:20] + "...") if len(client_id) > 20 else client_id,
        pkce_status="Active (SHA-256)" if code_challenge else "None",
        error_html="",
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        deny_url=deny_url,
    )
    return HTMLResponse(content=html)


@api_app.post("/authorize", response_class=HTMLResponse)
async def authorize_post(
    request: Request,
    admin_pin: str = Form(...),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    response_type: str = Form("code"),
    scope: str = Form(""),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
):
    """Validates Admin PIN and redirects to Gemini callback with short-lived signed code JWT."""
    if admin_pin.strip() != OAUTH_ADMIN_PIN:
        host = request.headers.get("x-forwarded-host", request.headers.get("host", "mcp-server"))
        deny_url = f"{redirect_uri}?error=access_denied&state={state}" if redirect_uri else "#"
        error_html = '<div class="error-msg">❌ Invalid Master Admin PIN. Please verify and try again.</div>'

        html = AUTHORIZATION_HTML.format(
            subdomain_display=host,
            client_id_display=(client_id[:20] + "...") if len(client_id) > 20 else client_id,
            pkce_status="Active (SHA-256)" if code_challenge else "None",
            error_html=error_html,
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            deny_url=deny_url,
        )
        return HTMLResponse(content=html, status_code=status.HTTP_401_UNAUTHORIZED)

    # PIN matches! Create stateless short-lived authorization code (10 minutes validity)
    auth_code_payload = {
        "sub": "auth_code",
        "type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
    }
    auth_code = jwt.encode(auth_code_payload, JWT_SECRET, algorithm="HS256")

    # Redirect to caller
    delim = "&" if "?" in redirect_uri else "?"
    callback_url = f"{redirect_uri}{delim}code={auth_code}"
    if state:
        callback_url += f"&state={state}"

    return RedirectResponse(url=callback_url, status_code=status.HTTP_302_FOUND)


# -----------------------------------------------------------------------------
# 4. OAuth 2.0 Token Endpoint (Stateless JWT + PKCE Verification)
# -----------------------------------------------------------------------------

def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """RFC 7636 PKCE Verifier."""
    if not code_challenge:
        return True
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return secrets.compare_digest(computed, code_challenge)
    elif method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    return False


@api_app.post("/token")
async def token_exchange(request: Request):
    """Exchanges Authorization Code or Refresh Token for long-lived Access & Refresh JWTs."""
    form_data = {}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            form_data = await request.json()
        except Exception:
            pass
    else:
        try:
            form = await request.form()
            form_data = dict(form)
        except Exception:
            pass

    grant_type = form_data.get("grant_type", "authorization_code")
    origin = _get_origin(request)

    if grant_type == "authorization_code":
        code = form_data.get("code")
        code_verifier = form_data.get("code_verifier", "")

        if not code:
            raise HTTPException(status_code=400, detail="Missing required 'code' parameter")

        # Decode and verify the authorization code JWT
        try:
            code_claims = jwt.decode(code, JWT_SECRET, algorithms=["HS256"])
            if code_claims.get("type") != "code":
                raise ValueError("Token is not an authorization code")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid authorization code: {e}")

        # Verify PKCE challenge
        stored_challenge = code_claims.get("code_challenge", "")
        method = code_claims.get("code_challenge_method", "S256")
        if stored_challenge:
            if not code_verifier or not _verify_pkce(code_verifier, stored_challenge, method):
                raise HTTPException(status_code=400, detail="PKCE code_verifier validation failed")

        # Issue long-lived stateless JWT access token (30 days) and refresh token (1 year)
        access_payload = {
            "sub": "gemini-mcp-user",
            "iss": origin,
            "type": "access",
            "exp": int(time.time()) + (30 * 86400),
            "iat": int(time.time()),
        }
        refresh_payload = {
            "sub": "gemini-mcp-user",
            "iss": origin,
            "type": "refresh",
            "exp": int(time.time()) + (365 * 86400),
            "iat": int(time.time()),
        }

        access_token = jwt.encode(access_payload, JWT_SECRET, algorithm="HS256")
        refresh_token = jwt.encode(refresh_payload, JWT_SECRET, algorithm="HS256")

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 30 * 86400,
            "refresh_token": refresh_token,
            "scope": "mcp",
        }

    elif grant_type == "refresh_token":
        refresh_token = form_data.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing 'refresh_token' parameter")

        _verify_jwt(refresh_token, expected_type="refresh")

        new_access_payload = {
            "sub": "gemini-mcp-user",
            "iss": origin,
            "type": "access",
            "exp": int(time.time()) + (30 * 86400),
            "iat": int(time.time()),
        }
        new_access_token = jwt.encode(new_access_payload, JWT_SECRET, algorithm="HS256")

        return {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": 30 * 86400,
            "scope": "mcp",
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {grant_type}")


# -----------------------------------------------------------------------------
# 5. Health Check & Root Dashboard
# -----------------------------------------------------------------------------

@api_app.get("/health")
async def health_check():
    """Application health endpoint for Coolify and Traefik checks."""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "connectors": list(_connectors.keys()),
    }


@api_app.get("/", response_class=HTMLResponse)
async def root_index(request: Request):
    """Provides human-readable overview of available MCP connectors."""
    origin = _get_origin(request)
    rows = "".join(
        f"<li><strong>{name.upper()} MCP</strong> &rarr; <code>{origin.replace('://', f'://{name}.mcp.')}/mcp</code></li>"
        for name in _connectors
    )
    return HTMLResponse(
        content=f"""<!DOCTYPE html>
<html>
<head><title>API to MCP Engine</title><style>body{{font-family:sans-serif;max-width:600px;margin:3rem auto;padding:1rem;background:#0f172a;color:#f8fafc;}}code{{background:#1e293b;padding:0.2rem 0.4rem;border-radius:4px;color:#38bdf8;}}ul{{line-height:2;}}a{{color:#38bdf8;}}</style></head>
<body>
    <h1>API to MCP Engine</h1>
    <p>Stateless OAuth 2.0 PKCE Gateway & Subdomain FastMCP Router.</p>
    <h3>Available MCP Endpoints:</h3>
    <ul>{rows}</ul>
    <p>Health Status: <a href="/health">/health</a></p>
</body>
</html>"""
    )


# -----------------------------------------------------------------------------
# 6. Composite ASGI App: Host-Header Subdomain Router for /mcp
# -----------------------------------------------------------------------------

class SubdomainMCPEngineApp:
    """Pure ASGI Dispatcher that intercepts /mcp calls and routes them to subdomains."""

    def __init__(self, fastapi_app: ASGIApp, connector_apps: Dict[str, Any]):
        self.fastapi_app = fastapi_app
        self.connector_apps = connector_apps

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            raw_path = scope.get("path", "")
            # Intercept /mcp and /mcp/ streamable transport endpoints
            if raw_path in ("/mcp", "/mcp/"):
                headers = dict(scope.get("headers", []))
                host = headers.get(b"host", b"").decode("utf-8").lower().split(":")[0]
                proto = headers.get(b"x-forwarded-proto", b"https").decode("utf-8")
                origin = f"{proto}://{host}"

                # 1. Bearer Token Verification
                auth_header = headers.get(b"authorization", b"").decode("utf-8")
                is_authorized = False
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:].strip()
                    try:
                        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                        if claims.get("type") == "access":
                            is_authorized = True
                    except Exception:
                        is_authorized = False

                if not is_authorized:
                    # Return RFC 9728 401 Unauthorized with resource metadata pointer
                    auth_challenge = (
                        f'Bearer realm="mcp", error="invalid_token", '
                        f'resource_metadata="{origin}/.well-known/oauth-protected-resource"'
                    )
                    body = b'{"error": "unauthorized", "message": "Valid Bearer access_token required for /mcp"}'
                    await send({
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"www-authenticate", auth_challenge.encode("utf-8")),
                            (b"content-length", str(len(body)).encode("utf-8")),
                        ],
                    })
                    await send({"type": "http.response.body", "body": body})
                    return

                # 2. Host Subdomain Resolution
                # host example: github.mcp.tmadhu.me -> first token is 'github'
                subdomain = host.split(".")[0].lower()
                target_app = self.connector_apps.get(subdomain)

                # Fallbacks if called directly or wildcard
                if not target_app:
                    if "github" in subdomain:
                        target_app = self.connector_apps.get("github")
                    elif "coolify" in subdomain:
                        target_app = self.connector_apps.get("coolify")
                    elif self.connector_apps:
                        target_app = list(self.connector_apps.values())[0]

                if target_app:
                    # Forward seamlessly to the connector's FastMCP streamable-http app
                    await target_app(scope, receive, send)
                    return

        # Pass all other endpoints (OAuth, Health, etc.) to FastAPI
        await self.fastapi_app(scope, receive, send)


# Expose root ASGI application for Uvicorn
app = SubdomainMCPEngineApp(api_app, _connector_apps)
