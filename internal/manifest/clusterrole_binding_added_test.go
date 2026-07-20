package manifest

import "testing"

func TestAnalyzeReportsNewRoleBindingToClusterRole(t *testing.T) {
	before := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: secret-reader}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
`)
	after := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: secret-reader}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: runtime, namespace: payments}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: secret-reader}
subjects:
- kind: ServiceAccount
  name: runtime
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "RBAC_SECRET_ACCESS_BOUND")
}
