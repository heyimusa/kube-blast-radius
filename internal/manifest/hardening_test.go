package manifest

import "testing"

func TestAnalyzeReportsServiceAccountAndContainerHardeningRegression(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      serviceAccountName: runtime
      containers:
      - name: api
        image: example/api:v1
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
`)
	after := []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: payments}
spec:
  template:
    spec:
      serviceAccountName: default
      containers:
      - name: api
        image: example/api:v2
        securityContext:
          capabilities:
            add: ["SYS_ADMIN"]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "WORKLOAD_SERVICE_ACCOUNT_CHANGED")
	assertFinding(t, findings, "WORKLOAD_RUN_AS_NON_ROOT_REMOVED")
	assertFinding(t, findings, "WORKLOAD_READ_ONLY_ROOT_FILESYSTEM_REMOVED")
	assertFinding(t, findings, "WORKLOAD_CAPABILITY_ADDED")
}
