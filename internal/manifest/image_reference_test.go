package manifest

import (
	"strings"
	"testing"
)

func TestAnalyzeReportsImageReferenceChangesWithSameNameAcrossContainerKinds(t *testing.T) {
	before := []byte(`apiVersion: v1
kind: Pod
metadata: {name: debug, namespace: payments}
spec:
  initContainers: [{name: setup, image: registry.example/setup:v1}]
  containers: [{name: setup, image: registry.example/api:v1}]
`)
	after := []byte(`apiVersion: v1
kind: Pod
metadata: {name: debug, namespace: payments}
spec:
  initContainers: [{name: setup, image: registry.example/setup:v2}]
  containers: [{name: setup, image: registry.example/api:v1}]
`)

	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if countFindings(findings, "WORKLOAD_IMAGE_REFERENCE_CHANGED") != 1 {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestAnalyzeReportsInitAndEphemeralContainerImageReferenceChanges(t *testing.T) {
	before := []byte(`apiVersion: v1
kind: Pod
metadata: {name: debug, namespace: payments}
spec:
  initContainers: [{name: prepare, image: registry.example/prepare:v1}]
  containers: [{name: api, image: registry.example/api:v1}]
  ephemeralContainers: [{name: inspect, image: registry.example/inspect:v1}]
`)
	after := []byte(`apiVersion: v1
kind: Pod
metadata: {name: debug, namespace: payments}
spec:
  initContainers: [{name: prepare, image: registry.example/prepare:v2}]
  containers: [{name: api, image: registry.example/api:v1}]
  ephemeralContainers: [{name: inspect, image: registry.example/inspect:v2}]
`)

	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if countFindings(findings, "WORKLOAD_IMAGE_REFERENCE_CHANGED") != 2 {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestAnalyzeIgnoresUnchangedAddedAndRemovedContainerImages(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers:
      - {name: unchanged, image: registry.example/unchanged:v1}
      - {name: removed, image: registry.example/removed@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
`)
	after := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers:
      - {name: unchanged, image: registry.example/unchanged:v1}
      - {name: added, image: registry.example/added:latest}
`)

	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if strings.HasPrefix(finding.Code, "WORKLOAD_IMAGE_") {
			t.Fatalf("unexpected image finding: %#v", finding)
		}
	}
}

func countFindings(findings []Finding, code string) int {
	count := 0
	for _, finding := range findings {
		if finding.Code == code {
			count++
		}
	}
	return count
}

func assertFindingSeverity(t *testing.T, findings []Finding, code, severity string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			if finding.Severity != severity {
				t.Fatalf("%s severity = %s, want %s", code, finding.Severity, severity)
			}
			return
		}
	}
	t.Fatalf("missing %s in %#v", code, findings)
}

func TestAnalyzeReportsLatestAddedToDigestQualifiedImageReference(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers: [{name: api, image: registry.example:5000/api:v2@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}]
`)
	after := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers: [{name: api, image: registry.example:5000/api:latest@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}]
`)

	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingSeverity(t, findings, "WORKLOAD_IMAGE_LATEST_ADDED", "high")
}

func TestAnalyzeReportsLatestAddedToContainerImageReference(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers: [{name: api, image: registry.example/api:v2}]
`)
	after := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers: [{name: api, image: registry.example/api:latest}]
`)

	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingSeverity(t, findings, "WORKLOAD_IMAGE_LATEST_ADDED", "high")
}

func TestAnalyzeReportsDigestRemovedFromContainerImageReference(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers: [{name: api, image: registry.example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}]
`)
	after := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers: [{name: api, image: registry.example/api:v2}]
`)

	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingSeverity(t, findings, "WORKLOAD_IMAGE_DIGEST_REMOVED", "high")
}

func TestAnalyzeReportsChangedContainerImageReference(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers: [{name: api, image: registry.example/api:v1}]
`)
	after := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers: [{name: api, image: registry.example/api:v2}]
`)

	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingSeverity(t, findings, "WORKLOAD_IMAGE_REFERENCE_CHANGED", "medium")
}
