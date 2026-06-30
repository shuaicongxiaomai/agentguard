# AgentGuard — security checks for AI agents (MCP server)

<!-- mcp-name: io.github.shuaicongxiaomai/agentguard -->

A free, open-source, single-binary [MCP](https://modelcontextprotocol.io) server that gives any
AI agent (Claude Desktop, Cursor, Claude Code, …) security checks **in the loop**:

| Tool | What it does | Data source |
|---|---|---|
| `scan_secrets` | Flags hard-coded secrets (API keys, tokens, private keys) in text/code/diffs before the agent commits, logs, or sends them. Runs locally; values are masked. | local (regex + entropy) |
| `check_cve` | Whether a specific package version has known CVEs, with severity + fixed version. | [OSV.dev](https://osv.dev) (free) |
| `scan_dependencies` | Scans a `go.mod` / `package.json` / `requirements.txt` and reports every vulnerable pinned dependency. | OSV.dev (free) |

No API key, no account, no telemetry. Everything runs locally except CVE lookups, which hit the
free public [OSV.dev](https://osv.dev) API.

## Install

Pick whichever fits your setup. All three give the same stdio MCP server.

### Docker (no Go toolchain needed)

```sh
docker run -i --rm ghcr.io/shuaicongxiaomai/agentguard:latest demo
```

MCP client config (`mcpServers` block in Claude Desktop / Cursor / Claude Code):

```jsonc
{
  "mcpServers": {
    "agentguard": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/shuaicongxiaomai/agentguard:latest"]
    }
  }
}
```

### Go install

```sh
go install github.com/shuaicongxiaomai/agentguard@latest
```

```jsonc
{ "mcpServers": { "agentguard": { "command": "agentguard" } } }
```

### Prebuilt binary

Download the archive for your OS/arch from the [Releases](https://github.com/shuaicongxiaomai/agentguard/releases)
page, extract it, and point the config `command` at the absolute path to the binary.

## Build from source

```sh
go build -o agentguard .          # append .exe on Windows
```

## Three ways to run it

**1. `demo` — see it work, zero config:**

```sh
agentguard demo
```

Runs all three tools on sample inputs and prints the results.

**2. stdio (default) — local use; the MCP client launches the binary.** No port;
the client manages its lifecycle. Use any of the configs above, then ask your agent:
*"scan this for secrets"*, *"is lodash 4.17.20 vulnerable?"*,
*"check my package.json for vulnerable deps."*

**3. `serve` — Streamable HTTP service on a port (for a hosted/remote server):**

```sh
agentguard serve :8080          # or set PORT=8080
# health:   GET  http://host:8080/healthz
# MCP URL:  POST http://host:8080/mcp   (clients connect to this URL)
```

Use stdio for local use; use `serve` when you want a hosted server users connect to by URL
without installing anything.

## Notes

- `scan_secrets` runs locally and **never returns raw secret values — only masked previews.**
- `scan_dependencies` caps at 200 deps per call and queries OSV concurrently.
- `check_cve` / `scan_dependencies` need network access to OSV.dev; `scan_secrets` is fully offline.

## License

[MIT](LICENSE).
