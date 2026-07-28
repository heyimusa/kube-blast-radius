package report

import (
	"encoding/json"
	"strings"

	"github.com/heyimusa/kube-blast-radius/internal/manifest"
)

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Properties struct {
		Resource string `json:"resource"`
		Severity string `json:"severity"`
	} `json:"properties"`
}

// SARIF returns SARIF 2.1.0 for CI systems. Findings describe manifest
// identities rather than source locations, so results intentionally omit
// physicalLocations instead of inventing a file or line number.
func SARIF(findings []manifest.Finding) ([]byte, error) {
	if findings == nil {
		findings = []manifest.Finding{}
	}
	document := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "kube-blast-radius"}},
			Results: []sarifResult{},
		}},
	}
	rules := map[string]sarifRule{}
	for _, finding := range findings {
		rule, exists := rules[finding.Code]
		if !exists {
			rule.ID = finding.Code
			rule.ShortDescription.Text = finding.Message
			rules[finding.Code] = rule
		}
		result := sarifResult{RuleID: finding.Code, Level: sarifLevel(finding.Severity)}
		result.Message.Text = finding.Message
		result.Properties.Resource = finding.Resource
		result.Properties.Severity = finding.Severity
		document.Runs[0].Results = append(document.Runs[0].Results, result)
	}
	for _, code := range sortedRuleIDs(rules) {
		document.Runs[0].Tool.Driver.Rules = append(document.Runs[0].Tool.Driver.Rules, rules[code])
	}
	return json.MarshalIndent(document, "", "  ")
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sortedRuleIDs(rules map[string]sarifRule) []string {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	for left := 0; left < len(ids); left++ {
		for right := left + 1; right < len(ids); right++ {
			if ids[right] < ids[left] {
				ids[left], ids[right] = ids[right], ids[left]
			}
		}
	}
	return ids
}
