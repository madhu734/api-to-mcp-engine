# API to MCP Engine

A lightweight, high-performance, containerized Python gateway powered by **FastAPI** and **FastMCP** that translates REST APIs (GitHub, Coolify, and custom modules) into standard **Model Context Protocol (MCP)** endpoints. 

Designed specifically for seamless integration with **Google Gemini Web** Custom MCP Connectors, including full **OAuth 2.0 PKCE** support and **Stateless JWT** session management.

---

## 🌟 Features

- **Stateless OAuth 2.0 & PKCE**: RFC 9728 & RFC 8414 compliant with Dynamic Client Registration and browser PIN approval.
- **Host-Header Subdomain Routing**: Single service automatically exposes:
  - `https://github.mcp.<domain>/mcp` &rarr; GitHub Tools
  - `https://coolify.mcp.<domain>/mcp` &rarr; Coolify Infrastructure Tools
  - `https://<service>.mcp.<domain>/mcp` &rarr; Auto-discovered connectors
- **Streamable HTTP Transport**: Modern MCP protocol version for instant execution and streaming.
- **Self-Protection Guard**: Hardcoded safety checks preventing the MCP engine from terminating or mutating its own container.

---

## 🛠️ Environment Variables

| Variable | Description | Default / Example |
|---|---|---|
| `GITHUB_PERSONAL_ACCESS_TOKEN` | GitHub PAT with repo, actions, workflow scopes | `paste_your_github_token` |
| `COOLIFY_API_TOKEN` | Coolify API Bearer Token | `paste_the_coolify_token` |
| `COOLIFY_BASE_URL` | Coolify API Base URL | `http://140.238.160.99:8000/api/v1` |
| `OAUTH_ADMIN_PIN` | Master PIN entered during browser authorization | `123456` |
| `JWT_SECRET` | 64-character secret key for signing tokens | *(Random Secret)* |
| `SELF_SERVICE_NAME` | Name of this container to guard against self-destruction | `api-to-mcp-engine` |

---

## 🚀 Adding to Google Gemini Web

1. Open **Google Gemini** &rarr; **Settings** &rarr; **Custom MCP Connectors**.
2. Add new Connector:
   - **GitHub**: `https://github.mcp.tmadhu.me/mcp`
   - **Coolify**: `https://coolify.mcp.tmadhu.me/mcp`
3. Gemini will trigger OAuth 2.0 flow &rarr; enter your `OAUTH_ADMIN_PIN` on the approval screen and click **Approve**.
4. Gemini will now have direct access to all GitHub and Coolify management tools!
