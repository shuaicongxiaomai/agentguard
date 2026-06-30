package agentguard

import (
	"strings"
	"testing"
)

func TestScanSecrets(t *testing.T) {
	text := `package main
const awsKey = "AKIAIOSFODNN7EXAMPLE"
// github token: ghp_1234567890abcdefghijklmnopqrstuvwxyz
api_key = "S3cr3tV4lue_with_high_entropy_xyz987"
normal := "just a regular short string"
-----BEGIN RSA PRIVATE KEY-----
`
	findings := ScanSecrets(text)
	if len(findings) < 3 {
		t.Fatalf("expected >=3 findings, got %d: %+v", len(findings), findings)
	}

	// Raw secrets must never appear in output; values are masked.
	for _, f := range findings {
		if strings.Contains(f.Masked, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("raw AWS key leaked in masked output: %q", f.Masked)
		}
		if !strings.Contains(f.Masked, "*") && len(f.Masked) > 8 {
			t.Errorf("expected masking, got %q", f.Masked)
		}
	}

	types := map[string]bool{}
	for _, f := range findings {
		types[f.Type] = true
	}
	for _, want := range []string{"AWS Access Key ID", "GitHub Personal Access Token", "Private Key Block"} {
		if !types[want] {
			t.Errorf("expected to detect %q; got types %v", want, types)
		}
	}
}

func TestScanSecretsClean(t *testing.T) {
	if f := ScanSecrets("just some normal code\nx := 1 + 2\n"); len(f) != 0 {
		t.Errorf("expected no findings on clean text, got %+v", f)
	}
}

func TestParseGoMod(t *testing.T) {
	content := `module example.com/x
go 1.22

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.1.0 // indirect
)

require github.com/single/dep v2.0.0
`
	deps, err := ParseManifest("go.mod", content)
	if err != nil {
		t.Fatal(err)
	}
	got := depMap(deps)
	if got["github.com/foo/bar"] != "v1.2.3" || got["github.com/baz/qux"] != "v0.1.0" || got["github.com/single/dep"] != "v2.0.0" {
		t.Fatalf("unexpected go.mod parse: %+v", deps)
	}
	for _, d := range deps {
		if d.Ecosystem != "Go" {
			t.Errorf("expected Go ecosystem, got %q", d.Ecosystem)
		}
	}
}

func TestParsePackageJSON(t *testing.T) {
	content := `{"dependencies":{"lodash":"^4.17.20","express":"4.18.2"},"devDependencies":{"jest":"~29.0.0","local":"file:../x"}}`
	deps, err := ParseManifest("package.json", content)
	if err != nil {
		t.Fatal(err)
	}
	got := depMap(deps)
	if got["lodash"] != "4.17.20" || got["express"] != "4.18.2" || got["jest"] != "29.0.0" {
		t.Fatalf("unexpected package.json parse: %+v", deps)
	}
	if _, ok := got["local"]; ok {
		t.Errorf("non-pinned file: spec should be skipped")
	}
}

func TestParseRequirements(t *testing.T) {
	content := "Django==3.0\nrequests==2.25.1\n# a comment\nflask>=1.0\n"
	deps, err := ParseManifest("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}
	got := depMap(deps)
	if got["Django"] != "3.0" || got["requests"] != "2.25.1" {
		t.Fatalf("unexpected requirements parse: %+v", deps)
	}
	if _, ok := got["flask"]; ok {
		t.Errorf("non-== spec should be skipped")
	}
}

func TestParseManifestUnsupported(t *testing.T) {
	if _, err := ParseManifest("Gemfile", "x"); err == nil {
		t.Error("expected error for unsupported manifest type")
	}
}

func depMap(deps []Dep) map[string]string {
	m := map[string]string{}
	for _, d := range deps {
		m[d.Name] = d.Version
	}
	return m
}
