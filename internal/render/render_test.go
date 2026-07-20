package render

import (
	"os"
	"testing"
)

func TestRenderRawReadsManifest(t *testing.T) {
	path := writeFixture(t, "manifest.yaml", "kind: Deployment\nmetadata: {name: api}\n")
	got, err := Render(Options{Mode: Raw, Path: path})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if string(got) != "kind: Deployment\nmetadata: {name: api}\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestRenderRejectsUnknownMode(t *testing.T) {
	_, err := Render(Options{Mode: "unknown", Path: "ignored"})
	if err == nil {
		t.Fatal("Render() error = nil")
	}
}

func writeFixture(t *testing.T, name, body string) string {
	t.Helper()
	path := t.TempDir() + "/" + name
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
