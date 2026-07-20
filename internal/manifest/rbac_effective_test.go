package manifest

import "testing"

func TestAnalyzeReportsClusterRoleBoundAcrossNamespaces(t *testing.T) {
	before := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: reader}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: reader}
subjects:
- kind: ServiceAccount
  name: api
  namespace: payments
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader}
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
kind: ClusterRoleBinding
metadata: {name: reader}
subjects:
- kind: ServiceAccount
  name: api
  namespace: payments
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "RBAC_SECRET_ACCESS_ADDED")
}

func TestAnalyzeReportsRBACWildcardAndEscalationVerbs(t *testing.T) {
	before := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: api, namespace: payments}
rules: []
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
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["bind", "escalate", "impersonate"]
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
	assertFinding(t, findings, "RBAC_WILDCARD_ACCESS_ADDED")
	assertFinding(t, findings, "RBAC_ESCALATION_VERB_ADDED")
}
