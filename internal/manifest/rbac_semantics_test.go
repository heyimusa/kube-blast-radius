package manifest

import "testing"

func TestAnalyzeReportsResourceNamesWidening(t *testing.T) {
	before := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: api, namespace: payments}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["checkout-config"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: api, namespace: payments}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: api}
subjects: [{kind: ServiceAccount, name: api}]
`)
	after := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: api, namespace: payments}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: api, namespace: payments}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: api}
subjects: [{kind: ServiceAccount, name: api}]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "RBAC_RESOURCE_NAMES_WIDENED")
}

func TestAnalyzeReportsNonResourceURLAddition(t *testing.T) {
	before := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: api}
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: api}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: api}
subjects: [{kind: ServiceAccount, name: api, namespace: payments}]
`)
	after := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: api}
rules:
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: api}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: api}
subjects: [{kind: ServiceAccount, name: api, namespace: payments}]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "RBAC_NON_RESOURCE_URL_ADDED")
}
