"""
Coolify MCP Connector
=====================
Provides full Coolify infrastructure and application management for Google Gemini.
Includes security guard to prevent accidental self-termination or modification of api-to-mcp-engine.
"""

import os
from typing import Any, Dict, List, Optional
import httpx
from fastmcp import FastMCP

mcp = FastMCP("Coolify MCP Connector")

COOLIFY_BASE_URL = os.environ.get("COOLIFY_BASE_URL", "http://140.238.160.99:8000/api/v1")
COOLIFY_API_TOKEN = os.environ.get("COOLIFY_API_TOKEN", "").strip()
SELF_SERVICE_NAME = os.environ.get("SELF_SERVICE_NAME", "api-to-mcp-engine").lower().strip()


def _get_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if COOLIFY_API_TOKEN and COOLIFY_API_TOKEN != "paste_the_coolify_token":
        headers["Authorization"] = f"Bearer {COOLIFY_API_TOKEN}"
    return headers


async def _coolify(method: str, path: str, **kwargs: Any) -> Any:
    url = f"{COOLIFY_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    headers = _get_headers()
    custom_headers = kwargs.pop("headers", {})
    headers.update(custom_headers)

    async with httpx.AsyncClient(timeout=45.0) as client:
        res = await client.request(method, url, headers=headers, **kwargs)
        if res.status_code >= 400:
            error_detail = res.text
            try:
                error_detail = res.json().get("message", res.text)
            except Exception:
                pass
            raise RuntimeError(f"Coolify API Error [{res.status_code}]: {error_detail}")

        if res.status_code == 204 or not res.content:
            return {"status": "success", "status_code": res.status_code}
        return res.json()


async def _verify_not_self(identifier: str, action_name: str) -> None:
    """Security Guard: Blocks operations that would alter or destroy this MCP engine."""
    clean_id = identifier.strip().lower()
    if clean_id == SELF_SERVICE_NAME or SELF_SERVICE_NAME in clean_id:
        raise ValueError(
            f"🛡️ SECURITY GUARD ACTIVATED: The operation '{action_name}' on '{identifier}' is blocked. "
            f"The API to MCP Engine cannot modify, stop, or delete itself."
        )

    # Check application name from Coolify
    try:
        app_data = await _coolify("GET", f"/applications/{identifier}")
        app_name = str(app_data.get("name", "")).lower()
        if SELF_SERVICE_NAME in app_name or app_name == SELF_SERVICE_NAME:
            raise ValueError(
                f"🛡️ SECURITY GUARD ACTIVATED: The application '{app_name}' ({identifier}) is the active "
                f"API to MCP Engine. Destructive or stopping actions are prohibited."
            )
    except ValueError:
        raise
    except Exception:
        pass


# -----------------------------------------------------------------------------
# 1. Projects & Servers
# -----------------------------------------------------------------------------

@mcp.tool()
async def list_projects() -> List[Dict[str, Any]]:
    """List all projects in Coolify."""
    return await _coolify("GET", "/projects")


@mcp.tool()
async def get_project(uuid: str) -> Dict[str, Any]:
    """Get project details and its environments."""
    return await _coolify("GET", f"/projects/{uuid}")


@mcp.tool()
async def list_servers() -> List[Dict[str, Any]]:
    """List all connected Coolify servers and their statuses."""
    return await _coolify("GET", "/servers")


# -----------------------------------------------------------------------------
# 2. Applications
# -----------------------------------------------------------------------------

@mcp.tool()
async def list_applications() -> List[Dict[str, Any]]:
    """List all deployed applications."""
    return await _coolify("GET", "/applications")


@mcp.tool()
async def get_application(uuid: str) -> Dict[str, Any]:
    """Get detailed information about an application."""
    return await _coolify("GET", f"/applications/{uuid}")


@mcp.tool()
async def create_application(
    project_uuid: str,
    environment_name: str,
    server_uuid: str,
    destination_uuid: str,
    git_repository: str,
    git_branch: str = "main",
    build_pack: str = "dockerfile",
    name: Optional[str] = None,
    ports_exposes: str = "8000",
) -> Dict[str, Any]:
    """Create a new application from a public Git repository."""
    payload = {
        "project_uuid": project_uuid,
        "environment_name": environment_name,
        "server_uuid": server_uuid,
        "destination_uuid": destination_uuid,
        "git_repository": git_repository,
        "git_branch": git_branch,
        "build_pack": build_pack,
        "ports_exposes": ports_exposes,
    }
    if name:
        payload["name"] = name
    return await _coolify("POST", "/applications/public", json=payload)


@mcp.tool()
async def update_application(
    uuid: str,
    fqdn: Optional[str] = None,
    name: Optional[str] = None,
    build_pack: Optional[str] = None,
    ports_exposes: Optional[str] = None,
    health_check_enabled: Optional[bool] = None,
    health_check_path: Optional[str] = None,
    health_check_port: Optional[int] = None,
) -> Dict[str, Any]:
    """Update application settings, domains, or health check configs."""
    await _verify_not_self(uuid, "update")
    payload: Dict[str, Any] = {}
    if fqdn is not None:
        payload["fqdn"] = fqdn
    if name is not None:
        payload["name"] = name
    if build_pack is not None:
        payload["build_pack"] = build_pack
    if ports_exposes is not None:
        payload["ports_exposes"] = ports_exposes
    if health_check_enabled is not None:
        payload["health_check_enabled"] = health_check_enabled
    if health_check_path is not None:
        payload["health_check_path"] = health_check_path
    if health_check_port is not None:
        payload["health_check_port"] = health_check_port

    return await _coolify("PATCH", f"/applications/{uuid}", json=payload)


@mcp.tool()
async def start_application(uuid: str) -> Dict[str, Any]:
    """Start an application."""
    return await _coolify("POST", f"/applications/{uuid}/start")


@mcp.tool()
async def stop_application(uuid: str) -> Dict[str, Any]:
    """Stop an application safely (protected by Security Guard)."""
    await _verify_not_self(uuid, "stop")
    return await _coolify("POST", f"/applications/{uuid}/stop")


@mcp.tool()
async def restart_application(uuid: str) -> Dict[str, Any]:
    """Restart an application safely (protected by Security Guard)."""
    await _verify_not_self(uuid, "restart")
    return await _coolify("POST", f"/applications/{uuid}/restart")


@mcp.tool()
async def delete_application(uuid: str, delete_volumes: bool = False) -> Dict[str, Any]:
    """Delete an application permanently (protected by Security Guard)."""
    await _verify_not_self(uuid, "delete")
    return await _coolify("DELETE", f"/applications/{uuid}", params={"delete_volumes": delete_volumes})


# -----------------------------------------------------------------------------
# 3. Deployments
# -----------------------------------------------------------------------------

@mcp.tool()
async def deploy_application(uuid: str, force: bool = False) -> Dict[str, Any]:
    """Trigger a new deployment for an application."""
    return await _coolify("POST", f"/deploy", params={"uuid": uuid, "force": force})


@mcp.tool()
async def list_deployments(uuid: str) -> List[Dict[str, Any]]:
    """List recent deployment history for an application."""
    return await _coolify("GET", f"/applications/{uuid}/deployments")


# -----------------------------------------------------------------------------
# 4. Environment Variables
# -----------------------------------------------------------------------------

@mcp.tool()
async def list_env_vars(uuid: str) -> List[Dict[str, Any]]:
    """List environment variables for an application."""
    return await _coolify("GET", f"/applications/{uuid}/envs")


@mcp.tool()
async def set_env_var(
    uuid: str,
    key: str,
    value: str,
    is_buildtime: bool = False,
    is_runtime: bool = True,
) -> Dict[str, Any]:
    """Create or update a single environment variable."""
    await _verify_not_self(uuid, "set_env_var")
    payload = {
        "key": key,
        "value": value,
        "is_buildtime": is_buildtime,
        "is_runtime": is_runtime,
    }
    return await _coolify("POST", f"/applications/{uuid}/envs", json=payload)


@mcp.tool()
async def bulk_set_env_vars(
    uuid: str,
    env_vars: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Bulk update multiple environment variables.
    
    Structure: [{"key": "MY_KEY", "value": "MY_VAL", "is_runtime": True}]
    """
    await _verify_not_self(uuid, "bulk_set_env_vars")
    return await _coolify("PATCH", f"/applications/{uuid}/envs/bulk", json={"data": env_vars})


# -----------------------------------------------------------------------------
# 5. Runtime Logs
# -----------------------------------------------------------------------------

@mcp.tool()
async def get_application_logs(uuid: str) -> Dict[str, Any]:
    """Get runtime container logs for an application."""
    return await _coolify("GET", f"/applications/{uuid}/logs")
