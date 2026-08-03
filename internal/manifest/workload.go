package manifest

import "strings"

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

func containerKeys(workload object) []string {
	var keys []string
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, c := range podContainerField(workload, field) {
			if name, _ := c["name"].(string); name != "" {
				keys = append(keys, field+"/"+name)
			}
		}
	}
	return keys
}

func containerByKey(workload object, wanted string) map[string]any {
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		prefix := field + "/"
		if !strings.HasPrefix(wanted, prefix) {
			continue
		}
		name := strings.TrimPrefix(wanted, prefix)
		for _, c := range podContainerField(workload, field) {
			if c["name"] == name {
				return c
			}
		}
	}
	return map[string]any{}
}

func containerName(key string) string {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
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

func imageReference(container map[string]any) string {
	image, _ := container["image"].(string)
	return image
}

func hasDigestReference(image string) bool {
	return strings.Contains(image, "@sha256:")
}

func hasLatestTag(image string) bool {
	name := strings.SplitN(image, "@", 2)[0]
	return strings.HasSuffix(name, ":latest")
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
