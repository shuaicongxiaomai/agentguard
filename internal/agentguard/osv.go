package agentguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const osvEndpoint = "https://api.osv.dev/v1/query"

var osvClient = &http.Client{Timeout: 20 * time.Second}

// Vuln is a trimmed view of an OSV vulnerability record.
type Vuln struct {
	ID            string   `json:"id"`
	Summary       string   `json:"summary"`
	Severity      string   `json:"severity"`       // highest CVSS score string, if any
	FixedVersions []string `json:"fixed_versions"` // versions that resolve it
	Aliases       []string `json:"aliases"`        // e.g. CVE ids
}

// QueryOSV asks OSV.dev whether a specific package version has known
// vulnerabilities. ecosystem is the OSV ecosystem (e.g. "npm", "PyPI", "Go").
func QueryOSV(ctx context.Context, ecosystem, name, version string) ([]Vuln, error) {
	reqBody := map[string]any{
		"version": version,
		"package": map[string]string{"name": name, "ecosystem": ecosystem},
	}
	b, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvEndpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := osvClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv.dev returned HTTP %d", resp.StatusCode)
	}

	var raw struct {
		Vulns []struct {
			ID       string   `json:"id"`
			Summary  string   `json:"summary"`
			Details  string   `json:"details"`
			Aliases  []string `json:"aliases"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Affected []struct {
				Ranges []struct {
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	out := make([]Vuln, 0, len(raw.Vulns))
	for _, v := range raw.Vulns {
		vuln := Vuln{ID: v.ID, Summary: v.Summary, Aliases: v.Aliases}
		if vuln.Summary == "" {
			vuln.Summary = truncate(v.Details, 200)
		}
		if len(v.Severity) > 0 {
			vuln.Severity = v.Severity[0].Score
		}
		fixed := map[string]bool{}
		for _, a := range v.Affected {
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" && !fixed[e.Fixed] {
						fixed[e.Fixed] = true
						vuln.FixedVersions = append(vuln.FixedVersions, e.Fixed)
					}
				}
			}
		}
		out = append(out, vuln)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
