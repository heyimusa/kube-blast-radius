package manifest

func podSpec(workload object) map[string]any {
	switch kind(workload) {
	case "Job":
		return nested(workload, "spec", "template", "spec")
	case "CronJob":
		return nested(workload, "spec", "jobTemplate", "spec", "template", "spec")
	case "Pod":
		return nested(workload, "spec")
	default:
		return nested(workload, "spec", "template", "spec")
	}
}

func podBool(workload object, field string) bool {
	value, _ := podSpec(workload)[field].(bool)
	return value
}

func podContainerField(workload object, field string) []map[string]any {
	items, _ := podSpec(workload)[field].([]any)
	var out []map[string]any
	for _, raw := range items {
		if c, ok := asMap(raw); ok {
			out = append(out, c)
		}
	}
	return out
}

func podContainers(workload object) []map[string]any {
	var out []map[string]any
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		out = append(out, podContainerField(workload, field)...)
	}
	return out
}
