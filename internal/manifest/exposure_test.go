package manifest

import "testing"

func TestAnalyzeReportsNewExternalServiceAndRemovedNetworkPolicy(t *testing.T) {
	before := []byte(`
apiVersion: v1
kind: Service
metadata: {name: api, namespace: payments}
spec: {type: ClusterIP}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all, namespace: payments}
spec: {podSelector: {}}
`)
	after := []byte(`
apiVersion: v1
kind: Service
metadata: {name: api, namespace: payments}
spec: {type: LoadBalancer}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "SERVICE_EXTERNAL_EXPOSURE_ADDED")
	assertFinding(t, findings, "NETWORK_POLICY_REMOVED")
}

func TestAnalyzeReportsIngressHostnameAdded(t *testing.T) {
	before := []byte(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: api, namespace: payments}
spec: {rules: []}
`)
	after := []byte(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: api, namespace: payments}
spec:
  rules:
  - host: api.example.com
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "INGRESS_HOST_ADDED")
}
