package manifest

import "testing"

func TestAnalyzeReportsExternalIPAndIngressPathAdded(t *testing.T) {
	before := []byte(`apiVersion: v1
kind: Service
metadata: {name: api, namespace: payments}
spec: {type: ClusterIP}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: api, namespace: payments}
spec:
  rules:
  - host: api.example.com
    http: {paths: []}
`)
	after := []byte(`apiVersion: v1
kind: Service
metadata: {name: api, namespace: payments}
spec:
  type: ClusterIP
  externalIPs: ["203.0.113.10"]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: api, namespace: payments}
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /admin
        pathType: Prefix
        backend:
          service: {name: api, port: {number: 8080}}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "SERVICE_EXTERNAL_IP_ADDED")
	assertFinding(t, findings, "INGRESS_PATH_ADDED")
}
