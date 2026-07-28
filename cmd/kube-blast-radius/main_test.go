package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDiffRawReportsHighImpact(t *testing.T) {
	output, code := runCLI(t, "diff", "--before", fixture(t, "before/manifests.yaml"), "--after", fixture(t, "after/manifests.yaml"))
	if code != 1 {
		t.Fatalf("exit = %d, output = %s", code, output)
	}
	for _, code := range []string{"RBAC_SECRET_ACCESS_ADDED", "WORKLOAD_HOST_NETWORK_ADDED", "WORKLOAD_PRIVILEGED_ADDED"} {
		if !bytes.Contains(output, []byte(code)) {
			t.Fatalf("output = %s, missing %s", output, code)
		}
	}
}

func TestDiffRawJSONIsValid(t *testing.T) {
	output, code := runCLI(t, "diff", "--before", fixture(t, "before/manifests.yaml"), "--after", fixture(t, "after/manifests.yaml"), "--format", "json")
	if code != 1 || !bytes.Contains(output, []byte(`"findings"`)) {
		t.Fatalf("exit = %d, output = %s", code, output)
	}
}

func TestDiffRawSARIFIsValid(t *testing.T) {
	output, code := runCLI(t, "diff", "--before", fixture(t, "before/manifests.yaml"), "--after", fixture(t, "after/manifests.yaml"), "--format", "sarif")
	if code != 1 || !bytes.Contains(output, []byte(`"version": "2.1.0"`)) || !bytes.Contains(output, []byte(`"ruleId": "RBAC_SECRET_ACCESS_ADDED"`)) {
		t.Fatalf("exit = %d, output = %s", code, output)
	}
}

func TestExactExitCodes(t *testing.T) {
	clean := writeTemp(t, "clean.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: clean}\n")
	if _, code := runCLI(t, "diff", "--before", clean, "--after", clean); code != 0 {
		t.Fatalf("clean exit=%d", code)
	}
	if _, code := runCLI(t, "diff", "--before", fixture(t, "before/manifests.yaml"), "--after", fixture(t, "after/manifests.yaml")); code != 1 {
		t.Fatalf("finding exit=%d", code)
	}
	if _, code := runCLI(t, "diff", "--before", clean, "--after", clean, "--mode", "bad"); code != 2 {
		t.Fatalf("invalid mode exit=%d", code)
	}
}

func runCLI(t *testing.T, args ...string) ([]byte, int) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "kube-blast-radius")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	cmd := exec.Command(binary, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return out, exit.ExitCode()
	}
	t.Fatal(err)
	return nil, 0
}
func fixture(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	return path
}
func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
