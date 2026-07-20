package manifest

import "testing"

func TestAnalyzeReportsPrivilegeEscalationAndRootUser(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers:
      - name: api
        image: example/api:v1
        securityContext:
          allowPrivilegeEscalation: false
          runAsUser: 1000
`)
	after := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      containers:
      - name: api
        image: example/api:v2
        securityContext:
          allowPrivilegeEscalation: true
          runAsUser: 0
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "WORKLOAD_PRIVILEGE_ESCALATION_ALLOWED")
	assertFinding(t, findings, "WORKLOAD_ROOT_USER_ADDED")
}
