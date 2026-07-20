package manifest

import "testing"

func TestAnalyzeReportsInitContainerPrivilege(t *testing.T) {
	before := []byte(`apiVersion: batch/v1
kind: Job
metadata: {name: migrate, namespace: payments}
spec:
  template:
    spec:
      restartPolicy: Never
      initContainers: [{name: init, image: example/init:v1}]
      containers: [{name: migrate, image: example/migrate:v1}]
`)
	after := []byte(`apiVersion: batch/v1
kind: Job
metadata: {name: migrate, namespace: payments}
spec:
  template:
    spec:
      restartPolicy: Never
      initContainers:
      - name: init
        image: example/init:v2
        securityContext: {privileged: true}
      containers: [{name: migrate, image: example/migrate:v2}]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "WORKLOAD_PRIVILEGED_ADDED")
}
