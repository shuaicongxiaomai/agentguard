# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AgentGuard is a single-binary [MCP](https://modelcontextprotocol.io) server (Go) that exposes three
security tools to AI agents: `scan_secrets` (local regex + entropy), `check_cve` (single package via
OSV.dev), and `scan_dependencies` (manifest-wide via OSV.dev). Free and open source; everything runs
locally except CVE lookups, which hit the free public OSV.dev API.

## Commands

`main.go` is at the **repo root**, not under `cmd/` — the README's `go build ./cmd/agentguard` is stale.

```sh
go build -o agentguard .          # build (append .exe on Windows)
go test ./...                     # all tests
go test ./internal/agentguard -run TestScanSecrets -v   # single test
go vet ./...
./agentguard demo                 # run all three tools on sample inputs, zero config
./agentguard                      # stdio transport (default — MCP client launches the binary)
./agentguard serve :8080          # Streamable HTTP transport; also honors $PORT
```

Tests that hit `check_cve` / `scan_dependencies` paths reach OSV.dev over the network; the parser/secret
tests are offline. `go test` covers only the pure parsing + secret-scan logic — there are no tests for the
network (`QueryOSV`) or MCP-wiring layers.

## Architecture

Two layers, kept strictly separate:

- **`main.go`** — MCP wiring only. Defines the tool I/O structs (the `jsonschema:` struct tags generate the
  schema the agent sees), registers the three tools via `mcp.AddTool`, and builds human-readable text
  summaries. Both transports (`StdioTransport`, `NewStreamableHTTPHandler`) share one `newServer()`.
- **`internal/agentguard/`** — all logic, no MCP dependency, so it's unit-testable in isolation:
  - `secrets.go` — `ScanSecrets`: high-precision named patterns (AWS, GitHub, Anthropic, etc.) run first,
    then a generic `key = "..."` assignment regex gated by Shannon entropy ≥ 3.5 to cut false positives.
    Dedupes so a value caught by a named rule isn't re-reported as generic. **Raw secret values are never
    returned — only masked (`mask()`).**
  - `osv.go` — `QueryOSV`: POSTs to `https://api.osv.dev/v1/query`, decodes into a trimmed `Vuln`. No API key.
  - `deps.go` — `ParseManifest` dispatches on type (`go.mod` / `package.json` / `requirements.txt`) into
    per-format parsers, then `ScanDependencies` fans out to OSV concurrently (semaphore of 8, capped at
    `maxDeps` = 200). Parsers intentionally skip non-pinned specs (npm ranges/`latest`/URLs, pip non-`==`)
    since OSV needs an exact version.

When adding a tool: implement and unit-test it in `internal/agentguard/`, then register it in `newServer()`
with an input struct (using `jsonschema:` tags) and a text-summary builder. Keep MCP types out of the
internal package.

## Release / distribution

`server.json` (repo root) is the MCP Registry manifest; `Dockerfile` builds the published image
(`ghcr.io/shuaicongxiaomai/agentguard`, carrying the `io.modelcontextprotocol.server.name` label the
registry verifies). Pushing a `v*` git tag triggers `.github/workflows/release.yml`, which builds the
binaries + multi-arch image, cuts a GitHub Release, and publishes `server.json` to the official MCP
Registry via GitHub OIDC. Bump `version` in both `main.go` and `server.json` to match the tag.
