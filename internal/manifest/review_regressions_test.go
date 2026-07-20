package manifest

import "testing"

func TestAnalyzeReportsClusterRoleBoundThroughRoleBinding(t *testing.T) {
	before := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: reader}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: reader, namespace: payments}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader}
subjects: [{kind: ServiceAccount, name: api}]
`)
	after := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: reader}
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: reader, namespace: payments}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader}
subjects: [{kind: ServiceAccount, name: api}]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "RBAC_SECRET_ACCESS_ADDED")
}

func TestAnalyzeExpandsListResources(t *testing.T) {
	before := []byte("")
	after := []byte(`apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Service
  metadata: {name: api, namespace: payments}
  spec: {type: LoadBalancer}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "SERVICE_EXTERNAL_EXPOSURE_ADDED")
}

func TestAnalyzeRejectsDuplicateResourceIdentity(t *testing.T) {
	input := []byte(`apiVersion: v1
kind: Service
metadata: {name: api, namespace: payments}
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: payments}
`)
	_, err := Analyze(input, input)
	if err == nil {
		t.Fatal("Analyze() error = nil")
	}
}

func TestAnalyzeDoesNotFlagImplicitDefaultServiceAccount(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    spec:
      containers: [{name: api, image: example/api:v1}]
`)
	after := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    spec:
      serviceAccountName: default
      containers: [{name: api, image: example/api:v2}]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Code == "WORKLOAD_SERVICE_ACCOUNT_CHANGED" {
			t.Fatalf("findings = %#v", findings)
		}
	}
}
