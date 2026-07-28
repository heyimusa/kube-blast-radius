package manifest

import "testing"

func TestAnalyzeReportsGatewayHostnameAdded(t *testing.T) {
	before := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: checkout
  namespace: payments
spec:
  hostnames: [checkout.internal.example]
`)
	after := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: checkout
  namespace: payments
spec:
  hostnames: [checkout.internal.example, checkout.example.com]
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "GATEWAY_ROUTE_HOSTNAME_ADDED") {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestAnalyzeReportsGatewayCatchAllRouteAdded(t *testing.T) {
	before := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: checkout
  namespace: payments
spec:
  hostnames: [checkout.example.com]
  rules:
    - matches:
        - path: {type: PathPrefix, value: /checkout}
`)
	after := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: checkout
  namespace: payments
spec:
  hostnames: [checkout.example.com]
  rules:
    - matches:
        - path: {type: PathPrefix, value: /checkout}
    - backendRefs:
        - name: checkout
          port: 8080
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "GATEWAY_ROUTE_CATCH_ALL_ADDED") {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestAnalyzeDoesNotReportNewGatewayListenerWithSameNamespaceScope(t *testing.T) {
	before := []byte("")
	after := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: gateway-system
spec:
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      allowedRoutes:
        namespaces: {from: Same}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(findings, "GATEWAY_ALLOWED_ROUTES_WIDENED") {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestAnalyzeDoesNotAssumeSelectorWidensGatewayAllowedRoutes(t *testing.T) {
	before := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: gateway-system
spec:
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      allowedRoutes:
        namespaces: {from: Same}
`)
	after := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: gateway-system
spec:
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels: {team: payments}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(findings, "GATEWAY_ALLOWED_ROUTES_WIDENED") {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestAnalyzeReportsGatewayAllowedRoutesWidened(t *testing.T) {
	before := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: gateway-system
spec:
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      allowedRoutes:
        namespaces: {from: Same}
`)
	after := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: gateway-system
spec:
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      allowedRoutes:
        namespaces: {from: All}
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "GATEWAY_ALLOWED_ROUTES_WIDENED") {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestAnalyzeReportsAdditionalGatewayBackendInAlreadyReferencedNamespace(t *testing.T) {
	before := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: checkout
  namespace: payments
spec:
  rules:
    - backendRefs:
        - name: audit-reader
          namespace: audit-system
          port: 8080
`)
	after := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: checkout
  namespace: payments
spec:
  rules:
    - backendRefs:
        - name: audit-reader
          namespace: audit-system
          port: 8080
        - name: audit-writer
          namespace: audit-system
          port: 8080
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "GATEWAY_CROSS_NAMESPACE_BACKEND_ADDED") {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestAnalyzeReportsGatewayCrossNamespaceBackendAdded(t *testing.T) {
	before := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: checkout
  namespace: payments
spec:
  rules:
    - backendRefs:
        - name: checkout
          port: 8080
`)
	after := []byte(`apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: checkout
  namespace: payments
spec:
  rules:
    - backendRefs:
        - name: checkout
          namespace: admin
          port: 8080
`)
	findings, err := Analyze(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "GATEWAY_CROSS_NAMESPACE_BACKEND_ADDED") {
		t.Fatalf("findings = %#v", findings)
	}
}

func hasFinding(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
