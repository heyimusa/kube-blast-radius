package manifest

import "testing"

func TestAnalyzeReportsTraefikIngressRouteExposure(t *testing.T) {
	before := []byte(``)
	after := []byte(`apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: {name: checkout, namespace: payments}
spec:
  entryPoints: [websecure]
  routes:
  - match: Host(` + "`checkout.example.com`" + `) && PathPrefix(` + "`/api`" + `)
    kind: Rule
    services:
    - name: checkout
      port: 8080
  tls: {}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "TRAEFIK_INGRESS_ROUTE_HOST_ADDED")
}

func TestAnalyzeReportsTraefikIngressRoutePathAdded(t *testing.T) {
	before := []byte(`apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: {name: checkout, namespace: payments}
spec:
  entryPoints: [websecure]
  routes:
  - match: Host(` + "`checkout.example.com`" + `) && PathPrefix(` + "`/`" + `)
    kind: Rule
    services: [{name: checkout, port: 8080}]
`)
	after := []byte(`apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: {name: checkout, namespace: payments}
spec:
  entryPoints: [websecure]
  routes:
  - match: Host(` + "`checkout.example.com`" + `) && PathPrefix(` + "`/`" + `)
    kind: Rule
    services: [{name: checkout, port: 8080}]
  - match: Host(` + "`checkout.example.com`" + `) && PathPrefix(` + "`/admin`" + `)
    kind: Rule
    services: [{name: checkout, port: 8080}]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "TRAEFIK_INGRESS_ROUTE_MATCH_ADDED")
}
