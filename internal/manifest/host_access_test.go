package manifest

import "testing"

func TestAnalyzeReportsHostNamespaceAndHostPathEscalation(t *testing.T) {
	before := []byte(`apiVersion: apps/v1
kind: DaemonSet
metadata: {name: agent, namespace: ops}
spec:
  template:
    spec:
      containers: [{name: agent, image: example/agent:v1}]
`)
	after := []byte(`apiVersion: apps/v1
kind: DaemonSet
metadata: {name: agent, namespace: ops}
spec:
  template:
    spec:
      hostPID: true
      hostIPC: true
      volumes:
      - name: host-root
        hostPath: {path: /}
      containers:
      - name: agent
        image: example/agent:v2
        volumeMounts: [{name: host-root, mountPath: /host}]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "WORKLOAD_HOST_PID_ADDED")
	assertFinding(t, findings, "WORKLOAD_HOST_IPC_ADDED")
	assertFinding(t, findings, "WORKLOAD_HOST_PATH_ADDED")
}
