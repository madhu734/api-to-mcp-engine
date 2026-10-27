"""
Template MCP Connector
======================
Ready-made module for easily plugging in any new REST API as an MCP server.

To add a new service:
1. Copy this file to connectors/<service_name>_mcp.py
2. Define tools using @mcp.tool()
3. The engine automatically discovers and routes requests from <service_name>.mcp.<domain>/mcp
"""

import os
from typing import Any, Dict
import httpx
from fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("Template MCP Service")

API_TOKEN = os.environ.get("TEMPLATE_API_TOKEN", "")
BASE_URL = os.environ.get("TEMPLATE_BASE_URL", "https://api.example.com/v1")


async def _request(method: str, endpoint: str, **kwargs: Any) -> Dict[str, Any]:
    """Helper method for making authorized API requests."""
    headers = kwargs.pop("headers", {})
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    headers["Accept"] = "application/json"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.request(
            method,
            f"{BASE_URL.rstrip('/')}/{endpoint.lstrip('/')}",
            headers=headers,
            **kwargs,
        )
        response.raise_for_status()
        if response.status_code == 204 or not response.content:
            return {"status": "success"}
        return response.json()


@mcp.tool()
async def ping() -> Dict[str, str]:
    """Test connectivity for this connector."""
    return {"status": "ok", "message": "Template MCP Connector is active."}


@mcp.tool()
async def sample_get_item(item_id: str) -> Dict[str, Any]:
    """Sample tool to fetch an item by ID from the API."""
    return await _request("GET", f"/items/{item_id}")
