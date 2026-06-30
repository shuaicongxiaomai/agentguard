package agentguard

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Dep is a parsed dependency.
type Dep struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// DepResult pairs a dependency with any vulnerabilities found for it.
type DepResult struct {
	Dep
	Vulns []Vuln `json:"vulns"`
}

const maxDeps = 200

// ParseManifest extracts dependencies from a manifest. manifestType is one of
// "go.mod", "package.json", "requirements.txt".
func ParseManifest(manifestType, content string) ([]Dep, error) {
	switch manifestType {
	case "go.mod":
		return parseGoMod(content), nil
	case "package.json":
		return parsePackageJSON(content)
	case "requirements.txt":
		return parseRequirements(content), nil
	default:
		return nil, fmt.Errorf("unsupported manifest type %q (use go.mod, package.json, or requirements.txt)", manifestType)
	}
}

var goModRe = regexp.MustCompile(`^\s*(?:require\s+)?([^\s/]+(?:/[^\s]+)?)\s+v(\S+)`)

func parseGoMod(content string) []Dep {
	var deps []Dep
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "module ") ||
			strings.HasPrefix(line, "go ") || line == "require (" || line == ")" {
			continue
		}
		if strings.HasSuffix(line, "// indirect") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "// indirect"))
		}
		m := goModRe.FindStringSubmatch(line)
		if m != nil {
			deps = append(deps, Dep{Ecosystem: "Go", Name: m[1], Version: "v" + m[2]})
		}
	}
	return deps
}

func parsePackageJSON(content string) ([]Dep, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}
	var deps []Dep
	for _, set := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, spec := range set {
			if v := cleanNPMVersion(spec); v != "" {
				deps = append(deps, Dep{Ecosystem: "npm", Name: name, Version: v})
			}
		}
	}
	return deps, nil
}

// cleanNPMVersion strips range operators to get a concrete-ish version. It skips
// non-pinned specs (URLs, "*", "latest", workspace refs) that OSV can't query.
func cleanNPMVersion(spec string) string {
	spec = strings.TrimSpace(spec)
	spec = strings.TrimLeft(spec, "^~>=<v ")
	if spec == "" || strings.ContainsAny(spec, ":/ ") || spec == "*" || spec == "latest" {
		return ""
	}
	return spec
}

var reqRe = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)`)

func parseRequirements(content string) []Dep {
	var deps []Dep
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := reqRe.FindStringSubmatch(line); m != nil {
			deps = append(deps, Dep{Ecosystem: "PyPI", Name: m[1], Version: m[2]})
		}
	}
	return deps
}

// ScanDependencies parses a manifest and checks every pinned dependency against
// OSV, returning only the dependencies that have vulnerabilities.
func ScanDependencies(ctx context.Context, manifestType, content string) ([]DepResult, error) {
	deps, err := ParseManifest(manifestType, content)
	if err != nil {
		return nil, err
	}
	if len(deps) > maxDeps {
		deps = deps[:maxDeps]
	}

	results := make([]DepResult, len(deps))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, d := range deps {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, d Dep) {
			defer wg.Done()
			defer func() { <-sem }()
			vulns, err := QueryOSV(ctx, d.Ecosystem, d.Name, d.Version)
			if err == nil && len(vulns) > 0 {
				results[i] = DepResult{Dep: d, Vulns: vulns}
			}
		}(i, d)
	}
	wg.Wait()

	var hits []DepResult
	for _, r := range results {
		if len(r.Vulns) > 0 {
			hits = append(hits, r)
		}
	}
	return hits, nil
}
