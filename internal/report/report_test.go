package report

import (
	"strings"
	"testing"

	"github.com/heyimusa/kube-blast-radius/internal/manifest"
)

func TestTextIncludesSeverityAndCode(t *testing.T) {
	got := Text([]manifest.Finding{{Severity: "high", Resource: "Deployment/payments/api", Message: "hostNetwork added", Code: "WORKLOAD_HOST_NETWORK_ADDED"}})
	for _, want := range []string{"HIGH", "Deployment/payments/api", "WORKLOAD_HOST_NETWORK_ADDED"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output = %q, missing %q", got, want)
		}
	}
}

func TestJSONUsesEmptyArrayForNoFindings(t *testing.T) {
	got, err := JSON(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"findings": []`) {
		t.Fatalf("output = %s", got)
	}
}
