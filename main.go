// Command agentguard is an MCP server that gives AI agents security checks in the
// loop: local secret scanning, single-package CVE lookup, and manifest-wide
// dependency vulnerability scanning (CVE data via OSV.dev, free, no API key).
//
// Run it over stdio from any MCP client (Claude Desktop, Cursor, …):
//
//	{ "mcpServers": { "agentguard": { "command": "agentguard" } } }
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/shuaicongxiaomai/agentguard/internal/agentguard"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "0.1.2"

// --- tool I/O types (JSON schema is generated from these) ---

type scanSecretsIn struct {
	Text string `json:"text" jsonschema:"The text, code, or diff to scan for hard-coded secrets."`
}
type scanSecretsOut struct {
	Count    int                       `json:"count"`
	Findings []agentguard.SecretFinding `json:"findings"`
}

type checkCVEIn struct {
	Ecosystem string `json:"ecosystem" jsonschema:"Package ecosystem: npm, PyPI, Go, Maven, RubyGems, crates.io, NuGet, Packagist, etc."`
	Name      string `json:"name" jsonschema:"Package name."`
	Version   string `json:"version" jsonschema:"Exact installed version (e.g. 4.17.20)."`
}
type checkCVEOut struct {
	Count int               `json:"count"`
	Vulns []agentguard.Vuln `json:"vulns"`
}

type scanDepsIn struct {
	ManifestType string `json:"manifest_type" jsonschema:"One of: go.mod, package.json, requirements.txt."`
	Content      string `json:"content" jsonschema:"The full contents of the manifest file."`
}
type scanDepsOut struct {
	Count      int                    `json:"count"`
	Vulnerable []agentguard.DepResult `json:"vulnerable"`
}

func main() {
	// `agentguard demo` runs the three tools on sample inputs and prints the
	// results — a zero-config way to see what the server does without wiring it
	// into an MCP client.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "demo":
			runDemo()
			return
		case "serve":
			runHTTP(os.Args[2:])
			return
		}
	}

	// Default transport: stdio — the MCP client launches this binary as a
	// subprocess and talks over stdin/stdout (no port). Use `serve` for HTTP.
	server := newServer()
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		log.Fatalf("agentguard: %v", err)
	}
}

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "agentguard",
		Title:   "AgentGuard — security checks for AI agents",
		Version: version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_secrets",
		Description: "Scan text, code, or a diff for hard-coded secrets (API keys, tokens, private keys) before the agent commits, logs, or sends it. Runs locally; values are masked.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scanSecretsIn) (*mcp.CallToolResult, scanSecretsOut, error) {
		findings := agentguard.ScanSecrets(in.Text)
		out := scanSecretsOut{Count: len(findings), Findings: findings}
		var summary string
		if len(findings) == 0 {
			summary = "No secrets detected."
		} else {
			var b strings.Builder
			fmt.Fprintf(&b, "⚠ %d potential secret(s) detected:\n", len(findings))
			for _, f := range findings {
				fmt.Fprintf(&b, "  line %d: %s (%s)\n", f.Line, f.Type, f.Masked)
			}
			summary = b.String()
		}
		return textResult(summary), out, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_cve",
		Description: "Check whether a specific package version has known vulnerabilities (CVEs), with severity and the fixed version. Data from OSV.dev.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in checkCVEIn) (*mcp.CallToolResult, checkCVEOut, error) {
		vulns, err := agentguard.QueryOSV(ctx, in.Ecosystem, in.Name, in.Version)
		if err != nil {
			return nil, checkCVEOut{}, err
		}
		out := checkCVEOut{Count: len(vulns), Vulns: vulns}
		summary := fmt.Sprintf("%s %s (%s): no known vulnerabilities.", in.Name, in.Version, in.Ecosystem)
		if len(vulns) > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "⚠ %s %s has %d known vulnerabilit(y/ies):\n", in.Name, in.Version, len(vulns))
			for _, v := range vulns {
				fmt.Fprintf(&b, "  %s %s — %s", v.ID, sev(v.Severity), v.Summary)
				if len(v.FixedVersions) > 0 {
					fmt.Fprintf(&b, " (fixed in %s)", strings.Join(v.FixedVersions, ", "))
				}
				b.WriteString("\n")
			}
			summary = b.String()
		}
		return textResult(summary), out, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_dependencies",
		Description: "Scan a dependency manifest (go.mod, package.json, or requirements.txt) and report every pinned dependency with known vulnerabilities. Data from OSV.dev.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scanDepsIn) (*mcp.CallToolResult, scanDepsOut, error) {
		hits, err := agentguard.ScanDependencies(ctx, in.ManifestType, in.Content)
		if err != nil {
			return nil, scanDepsOut{}, err
		}
		out := scanDepsOut{Count: len(hits), Vulnerable: hits}
		summary := "No vulnerable dependencies found."
		if len(hits) > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "⚠ %d vulnerable dependenc(y/ies):\n", len(hits))
			for _, h := range hits {
				fmt.Fprintf(&b, "  %s %s — %d issue(s)\n", h.Name, h.Version, len(h.Vulns))
			}
			summary = b.String()
		}
		return textResult(summary), out, nil
	})

	return server
}

// runHTTP serves the same tools over Streamable HTTP — a long-lived service on a
// port that remote MCP clients connect to by URL (http://host:addr/mcp). Use this
// when you want a hosted server clients reach by URL without installing anything.
func runHTTP(args []string) {
	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	if len(args) > 0 && args[0] != "" {
		addr = args[0]
	}
	server := newServer()
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.Handle("/mcp/", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	log.Printf("agentguard MCP server (HTTP) on %s — MCP endpoint: %s/mcp", addr, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("agentguard: %v", err)
	}
}

func isCleanShutdown(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, mcp.ErrConnectionClosed) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "server is closing") || strings.Contains(msg, "connection closed")
}

func runDemo() {
	fmt.Print("AgentGuard demo — what the AI agent gets to call:\n\n")

	fmt.Println("1) scan_secrets — find hard-coded secrets in code")
	sample := "const awsKey = \"AKIAIOSFODNN7EXAMPLE\"\n// token: ghp_1234567890abcdefghijklmnopqrstuvwxyz\nport := 8080"
	for _, f := range agentguard.ScanSecrets(sample) {
		fmt.Printf("   ⚠ line %d: %s (%s)\n", f.Line, f.Type, f.Masked)
	}

	fmt.Println("\n2) check_cve — is npm 'minimist' 1.2.0 vulnerable?")
	if vulns, err := agentguard.QueryOSV(context.Background(), "npm", "minimist", "1.2.0"); err != nil {
		fmt.Printf("   (offline? %v)\n", err)
	} else {
		for _, v := range vulns {
			fmt.Printf("   ⚠ %s %s — %s (fixed in %s)\n", v.ID, sev(v.Severity), truncate(v.Summary, 70), strings.Join(v.FixedVersions, ", "))
		}
	}

	fmt.Println("\n3) scan_dependencies — scan a package.json")
	pkg := `{"dependencies":{"lodash":"4.17.20","minimist":"1.2.0","express":"4.18.2"}}`
	if hits, err := agentguard.ScanDependencies(context.Background(), "package.json", pkg); err != nil {
		fmt.Printf("   (offline? %v)\n", err)
	} else if len(hits) == 0 {
		fmt.Println("   no vulnerable dependencies")
	} else {
		for _, h := range hits {
			fmt.Printf("   ⚠ %s %s — %d issue(s)\n", h.Name, h.Version, len(h.Vulns))
		}
	}
	fmt.Println("\nThat's it. In Claude/Cursor the agent calls these automatically — see README.md.")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func sev(s string) string {
	if s == "" {
		return ""
	}
	return "[" + s + "]"
}
