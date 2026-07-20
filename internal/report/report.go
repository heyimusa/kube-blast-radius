package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/heyimusa/kube-blast-radius/internal/manifest"
)

func Text(findings []manifest.Finding) string {
	if len(findings) == 0 {
		return "NO HIGH-SEVERITY CHANGE MATCHED ENABLED CHECKS; THIS IS NOT A COMPLETE SECURITY ASSESSMENT\n"
	}
	var builder strings.Builder
	for _, finding := range findings {
		fmt.Fprintf(&builder, "%s  %s: %s (%s)\n", strings.ToUpper(finding.Severity), finding.Resource, finding.Message, finding.Code)
	}
	builder.WriteString("ANALYSIS NOTE: findings cover enabled checks only; this is not a complete security assessment.\n")
	return builder.String()
}

func JSON(findings []manifest.Finding) ([]byte, error) {
	if findings == nil {
		findings = []manifest.Finding{}
	}
	return json.MarshalIndent(struct {
		Findings []manifest.Finding `json:"findings"`
	}{findings}, "", "  ")
}
