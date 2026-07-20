package manifest

import "testing"

func TestAnalyzeReportsDefaultIngressBackend(t *testing.T) {
	before := []byte(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: api, namespace: payments}
spec: {}
`)
	after := []byte(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: api, namespace: payments}
spec:
  defaultBackend:
    service:
      name: api
      port: {number: 8080}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "INGRESS_DEFAULT_BACKEND_ADDED")
}

func TestAnalyzeWarnsForUnsupportedKind(t *testing.T) {
	manifest := []byte(`apiVersion: example.io/v1
kind: CustomPolicy
metadata: {name: unknown}
`)
	findings, err := Analyze(manifest, manifest)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "ANALYSIS_UNSUPPORTED_KIND")
}
