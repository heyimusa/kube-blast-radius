package manifest

import "testing"

func TestAnalyzeIgnoresUnboundRoleChange(t *testing.T) {
	before := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: orphan, namespace: payments}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
`)
	after := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: orphan, namespace: payments}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Code == "RBAC_SECRET_ACCESS_ADDED" {
			t.Fatalf("unbound Role produced %#v", findings)
		}
	}
}
