package report

import (
	"encoding/json"
	"testing"

	"github.com/heyimusa/kube-blast-radius/internal/manifest"
)

func TestSARIFProducesGitHubCompatibleHighResult(t *testing.T) {
	output, err := SARIF([]manifest.Finding{{
		Severity: "high",
		Code:     "GATEWAY_ROUTE_HOSTNAME_ADDED",
		Resource: "HTTPRoute/payments/checkout",
		Message:  "Gateway API route newly exposes hostname checkout.example.com",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatal(err)
	}
	if document["version"] != "2.1.0" {
		t.Fatalf("version = %#v", document["version"])
	}
	runs, _ := document["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %#v", runs)
	}
	run, _ := runs[0].(map[string]any)
	results, _ := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %#v", results)
	}
	result, _ := results[0].(map[string]any)
	if result["ruleId"] != "GATEWAY_ROUTE_HOSTNAME_ADDED" || result["level"] != "error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSARIFUsesEmptyResultsForNoFindings(t *testing.T) {
	output, err := SARIF(nil)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatal(err)
	}
	runs, _ := document["runs"].([]any)
	run, _ := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok || len(results) != 0 {
		t.Fatalf("results = %#v", run["results"])
	}
}
