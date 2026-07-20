package manifest

func displayDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func effectiveServiceAccount(value object) string {
	if name, _ := podSpec(value)["serviceAccountName"].(string); name != "" {
		return name
	}
	return "default"
}

func containerNames(workload object) []string {
	var names []string
	for _, c := range podContainers(workload) {
		if name, _ := c["name"].(string); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func containerByName(workload object, wanted string) map[string]any {
	for _, c := range podContainers(workload) {
		if c["name"] == wanted {
			return c
		}
	}
	return map[string]any{}
}

func boolAtMap(value map[string]any, keys ...string) bool {
	var current any = value
	for _, key := range keys {
		m, ok := asMap(current)
		if !ok {
			return false
		}
		current = m[key]
	}
	result, _ := current.(bool)
	return result
}

func runAsRoot(container map[string]any) bool {
	sec, _ := asMap(container["securityContext"])
	uid, ok := sec["runAsUser"].(int)
	return ok && uid == 0
}

func addedCapabilities(old, next map[string]any) bool {
	oldSet := capabilitySet(old)
	newSet := capabilitySet(next)
	for capability := range newSet {
		if !oldSet[capability] {
			return true
		}
	}
	return false
}

func capabilitySet(container map[string]any) map[string]bool {
	out := map[string]bool{}
	sec, _ := asMap(container["securityContext"])
	caps, _ := asMap(sec["capabilities"])
	items, _ := caps["add"].([]any)
	for _, item := range items {
		if name, ok := item.(string); ok {
			out[name] = true
		}
	}
	return out
}
