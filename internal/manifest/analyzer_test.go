package manifest

import "testing"

func TestAnalyzeReportsRBACAndWorkloadEscalation(t *testing.T) {
	before := []byte(`
apiVersion: v1
kind: ServiceAccount
metadata: {name: checkout, namespace: payments}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: checkout, namespace: payments}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: checkout, namespace: payments}
subjects:
- kind: ServiceAccount
  name: checkout
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: checkout}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: payments}
spec:
  template:
    spec:
      serviceAccountName: checkout
      containers: [{name: api, image: example/checkout:v1}]
`)
	after := []byte(`
apiVersion: v1
kind: ServiceAccount
metadata: {name: checkout, namespace: payments}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: checkout, namespace: payments}
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: checkout, namespace: payments}
subjects:
- kind: ServiceAccount
  name: checkout
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: checkout}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: payments}
spec:
  template:
    spec:
      serviceAccountName: checkout
      hostNetwork: true
      containers:
      - name: api
        image: example/checkout:v2
        securityContext:
          privileged: true
`)

	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "RBAC_SECRET_ACCESS_ADDED")
	assertFinding(t, findings, "WORKLOAD_PRIVILEGED_ADDED")
	assertFinding(t, findings, "WORKLOAD_HOST_NETWORK_ADDED")
}

func assertFinding(t *testing.T, findings []Finding, code string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			return
		}
	}
	t.Fatalf("missing %s in %#v", code, findings)
}
