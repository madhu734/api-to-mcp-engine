"""
GitHub MCP Connector
====================
Provides comprehensive GitHub management tools for Google Gemini and MCP clients.
Requires GITHUB_PERSONAL_ACCESS_TOKEN environment variable.
"""

import base64
import os
from typing import Any, Dict, List, Optional
import httpx
from fastmcp import FastMCP

mcp = FastMCP("GitHub MCP Connector")

GITHUB_API_BASE = "https://api.github.com"


def _get_headers() -> Dict[str, str]:
    token = os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "").strip()
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token and token != "paste_your_github_token":
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _gh(method: str, path: str, **kwargs: Any) -> Any:
    url = f"{GITHUB_API_BASE}{path}"
    headers = _get_headers()
    custom_headers = kwargs.pop("headers", {})
    headers.update(custom_headers)

    async with httpx.AsyncClient(timeout=35.0) as client:
        res = await client.request(method, url, headers=headers, **kwargs)
        if res.status_code >= 400:
            error_detail = res.text
            try:
                error_detail = res.json().get("message", res.text)
            except Exception:
                pass
            raise RuntimeError(f"GitHub API Error [{res.status_code}]: {error_detail}")

        if res.status_code == 204 or not res.content:
            return {"status": "success", "status_code": res.status_code}
        return res.json()


# -----------------------------------------------------------------------------
# 1. Repositories Management
# -----------------------------------------------------------------------------

@mcp.tool()
async def list_repos(
    visibility: str = "all",
    sort: str = "updated",
    direction: str = "desc",
    per_page: int = 30,
) -> List[Dict[str, Any]]:
    """List authenticated user's repositories."""
    data = await _gh(
        "GET",
        "/user/repos",
        params={
            "visibility": visibility,
            "sort": sort,
            "direction": direction,
            "per_page": min(per_page, 100),
        },
    )
    return [
        {
            "id": r.get("id"),
            "name": r.get("name"),
            "full_name": r.get("full_name"),
            "private": r.get("private"),
            "html_url": r.get("html_url"),
            "description": r.get("description"),
            "default_branch": r.get("default_branch"),
            "updated_at": r.get("updated_at"),
        }
        for r in data
    ]


@mcp.tool()
async def get_repo(owner: str, repo: str) -> Dict[str, Any]:
    """Get detailed information about a repository."""
    return await _gh("GET", f"/repos/{owner}/{repo}")


@mcp.tool()
async def create_repo(
    name: str,
    description: str = "",
    private: bool = False,
    auto_init: bool = True,
) -> Dict[str, Any]:
    """Create a new GitHub repository."""
    payload = {
        "name": name,
        "description": description,
        "private": private,
        "auto_init": auto_init,
    }
    return await _gh("POST", "/user/repos", json=payload)


@mcp.tool()
async def update_repo(
    owner: str,
    repo: str,
    description: Optional[str] = None,
    private: Optional[bool] = None,
    default_branch: Optional[str] = None,
) -> Dict[str, Any]:
    """Update settings of an existing repository."""
    payload: Dict[str, Any] = {}
    if description is not None:
        payload["description"] = description
    if private is not None:
        payload["private"] = private
    if default_branch is not None:
        payload["default_branch"] = default_branch
    return await _gh("PATCH", f"/repos/{owner}/{repo}", json=payload)


@mcp.tool()
async def delete_repo(owner: str, repo: str) -> Dict[str, Any]:
    """Delete a repository permanently."""
    return await _gh("DELETE", f"/repos/{owner}/{repo}")


# -----------------------------------------------------------------------------
# 2. Branch Management
# -----------------------------------------------------------------------------

@mcp.tool()
async def list_branches(owner: str, repo: str) -> List[Dict[str, Any]]:
    """List all branches in a repository."""
    data = await _gh("GET", f"/repos/{owner}/{repo}/branches")
    return [
        {
            "name": b.get("name"),
            "commit_sha": b.get("commit", {}).get("sha"),
            "protected": b.get("protected"),
        }
        for b in data
    ]


@mcp.tool()
async def create_branch(
    owner: str, repo: str, branch: str, from_branch: Optional[str] = None
) -> Dict[str, Any]:
    """Create a new branch from a base branch."""
    if not from_branch:
        repo_data = await _gh("GET", f"/repos/{owner}/{repo}")
        from_branch = repo_data.get("default_branch", "main")

    ref_data = await _gh("GET", f"/repos/{owner}/{repo}/git/ref/heads/{from_branch}")
    sha = ref_data.get("object", {}).get("sha")

    payload = {"ref": f"refs/heads/{branch}", "sha": sha}
    return await _gh("POST", f"/repos/{owner}/{repo}/git/refs", json=payload)


# -----------------------------------------------------------------------------
# 3. File Operations & Multi-file Commits
# -----------------------------------------------------------------------------

@mcp.tool()
async def get_file_contents(
    owner: str, repo: str, path: str, branch: Optional[str] = None
) -> Dict[str, Any]:
    """Read and decode file contents from a repository."""
    params = {}
    if branch:
        params["ref"] = branch

    data = await _gh("GET", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}", params=params)
    content_raw = data.get("content", "")
    encoding = data.get("encoding", "")
    decoded_text = ""
    if encoding == "base64" and content_raw:
        decoded_text = base64.b64decode(content_raw).decode("utf-8", errors="replace")

    return {
        "name": data.get("name"),
        "path": data.get("path"),
        "sha": data.get("sha"),
        "size": data.get("size"),
        "content": decoded_text,
    }


@mcp.tool()
async def create_or_update_file(
    owner: str,
    repo: str,
    path: str,
    content: str,
    message: str,
    branch: Optional[str] = None,
    sha: Optional[str] = None,
) -> Dict[str, Any]:
    """Create or update a single file in a repository."""
    if sha is None:
        try:
            existing = await _gh("GET", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}", params={"ref": branch} if branch else None)
            sha = existing.get("sha")
        except Exception:
            sha = None

    content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    payload = {
        "message": message,
        "content": content_b64,
    }
    if sha:
        payload["sha"] = sha
    if branch:
        payload["branch"] = branch

    return await _gh("PUT", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}", json=payload)


@mcp.tool()
async def delete_file(
    owner: str,
    repo: str,
    path: str,
    message: str,
    sha: str,
    branch: Optional[str] = None,
) -> Dict[str, Any]:
    """Delete a file from a repository."""
    payload = {"message": message, "sha": sha}
    if branch:
        payload["branch"] = branch
    return await _gh("DELETE", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}", json=payload)


@mcp.tool()
async def push_files(
    owner: str,
    repo: str,
    files: List[Dict[str, str]],
    message: str,
    branch: str = "main",
) -> Dict[str, Any]:
    """Commit and push multiple files simultaneously via GitHub Git Data Tree API.
    
    files parameter structure: [{"path": "dir/file.txt", "content": "file contents"}]
    """
    ref_data = await _gh("GET", f"/repos/{owner}/{repo}/git/ref/heads/{branch}")
    latest_commit_sha = ref_data["object"]["sha"]

    commit_data = await _gh("GET", f"/repos/{owner}/{repo}/git/commits/{latest_commit_sha}")
    base_tree_sha = commit_data["tree"]["sha"]

    tree_items = []
    for f in files:
        blob = await _gh(
            "POST",
            f"/repos/{owner}/{repo}/git/blobs",
            json={"content": f["content"], "encoding": "utf-8"},
        )
        tree_items.append({
            "path": f["path"].lstrip("/"),
            "mode": "100644",
            "type": "blob",
            "sha": blob["sha"],
        })

    new_tree = await _gh(
        "POST",
        f"/repos/{owner}/{repo}/git/trees",
        json={"base_tree": base_tree_sha, "tree": tree_items},
    )

    new_commit = await _gh(
        "POST",
        f"/repos/{owner}/{repo}/git/commits",
        json={
            "message": message,
            "tree": new_tree["sha"],
            "parents": [latest_commit_sha],
        },
    )

    updated_ref = await _gh(
        "PATCH",
        f"/repos/{owner}/{repo}/git/refs/heads/{branch}",
        json={"sha": new_commit["sha"]},
    )

    return {
        "status": "success",
        "commit_sha": new_commit["sha"],
        "files_updated": len(files),
        "ref": updated_ref.get("ref"),
    }


# -----------------------------------------------------------------------------
# 4. GitHub Actions Workflows & Runs
# -----------------------------------------------------------------------------

@mcp.tool()
async def list_workflows(owner: str, repo: str) -> List[Dict[str, Any]]:
    """List GitHub Actions workflows for a repository."""
    data = await _gh("GET", f"/repos/{owner}/{repo}/actions/workflows")
    return [
        {
            "id": w.get("id"),
            "name": w.get("name"),
            "path": w.get("path"),
            "state": w.get("state"),
        }
        for w in data.get("workflows", [])
    ]


@mcp.tool()
async def trigger_workflow(
    owner: str,
    repo: str,
    workflow_id: str,
    ref: str = "main",
    inputs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Trigger a GitHub Actions workflow dispatch event."""
    payload = {"ref": ref}
    if inputs:
        payload["inputs"] = inputs
    return await _gh(
        "POST",
        f"/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
        json=payload,
    )


@mcp.tool()
async def list_workflow_runs(
    owner: str,
    repo: str,
    workflow_id: Optional[str] = None,
    status: Optional[str] = None,
    per_page: int = 10,
) -> List[Dict[str, Any]]:
    """List execution runs of GitHub Actions workflows."""
    params: Dict[str, Any] = {"per_page": min(per_page, 30)}
    if status:
        params["status"] = status

    endpoint = (
        f"/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"
        if workflow_id
        else f"/repos/{owner}/{repo}/actions/runs"
    )
    data = await _gh("GET", endpoint, params=params)
    return [
        {
            "id": r.get("id"),
            "name": r.get("name"),
            "status": r.get("status"),
            "conclusion": r.get("conclusion"),
            "event": r.get("event"),
            "created_at": r.get("created_at"),
            "html_url": r.get("html_url"),
        }
        for r in data.get("workflow_runs", [])
    ]


@mcp.tool()
async def get_workflow_run_details(owner: str, repo: str, run_id: int) -> Dict[str, Any]:
    """Get status, conclusion, and jobs for a specific workflow run."""
    run_info = await _gh("GET", f"/repos/{owner}/{repo}/actions/runs/{run_id}")
    jobs_info = await _gh("GET", f"/repos/{owner}/{repo}/actions/runs/{run_id}/jobs")
    return {
        "id": run_info.get("id"),
        "status": run_info.get("status"),
        "conclusion": run_info.get("conclusion"),
        "created_at": run_info.get("created_at"),
        "updated_at": run_info.get("updated_at"),
        "jobs": [
            {
                "id": j.get("id"),
                "name": j.get("name"),
                "status": j.get("status"),
                "conclusion": j.get("conclusion"),
                "failed_steps": [
                    s.get("name") for s in j.get("steps", []) if s.get("conclusion") == "failure"
                ],
            }
            for j in jobs_info.get("jobs", [])
        ],
    }


# -----------------------------------------------------------------------------
# 5. Issues & Pull Requests
# -----------------------------------------------------------------------------

@mcp.tool()
async def list_issues(
    owner: str, repo: str, state: str = "open", per_page: int = 20
) -> List[Dict[str, Any]]:
    """List repository issues."""
    data = await _gh("GET", f"/repos/{owner}/{repo}/issues", params={"state": state, "per_page": per_page})
    return [
        {
            "number": i.get("number"),
            "title": i.get("title"),
            "state": i.get("state"),
            "user": i.get("user", {}).get("login"),
            "comments": i.get("comments"),
            "html_url": i.get("html_url"),
            "created_at": i.get("created_at"),
        }
        for i in data
        if "pull_request" not in i
    ]


@mcp.tool()
async def create_issue(
    owner: str, repo: str, title: str, body: str = "", labels: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Create a new issue."""
    payload: Dict[str, Any] = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels
    return await _gh("POST", f"/repos/{owner}/{repo}/issues", json=payload)


@mcp.tool()
async def list_pull_requests(
    owner: str, repo: str, state: str = "open", per_page: int = 20
) -> List[Dict[str, Any]]:
    """List pull requests in a repository."""
    data = await _gh("GET", f"/repos/{owner}/{repo}/pulls", params={"state": state, "per_page": per_page})
    return [
        {
            "number": p.get("number"),
            "title": p.get("title"),
            "state": p.get("state"),
            "head": p.get("head", {}).get("ref"),
            "base": p.get("base", {}).get("ref"),
            "html_url": p.get("html_url"),
        }
        for p in data
    ]


@mcp.tool()
async def create_pull_request(
    owner: str, repo: str, title: str, head: str, base: str = "main", body: str = ""
) -> Dict[str, Any]:
    """Create a new pull request."""
    payload = {"title": title, "head": head, "base": base, "body": body}
    return await _gh("POST", f"/repos/{owner}/{repo}/pulls", json=payload)


@mcp.tool()
async def merge_pull_request(
    owner: str,
    repo: str,
    pull_number: int,
    commit_title: Optional[str] = None,
    merge_method: str = "merge",
) -> Dict[str, Any]:
    """Merge an open pull request."""
    payload: Dict[str, Any] = {"merge_method": merge_method}
    if commit_title:
        payload["commit_title"] = commit_title
    return await _gh("PUT", f"/repos/{owner}/{repo}/pulls/{pull_number}/merge", json=payload)
