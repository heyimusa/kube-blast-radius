package manifest

import "fmt"

func diffService(old, next object) []Finding {
	oldType := nestedString(old, "spec", "type")
	newType := nestedString(next, "spec", "type")
	var out []Finding
	if newType == "LoadBalancer" || newType == "NodePort" {
		if oldType != newType {
			out = append(out, Finding{Severity: "high", Code: "SERVICE_EXTERNAL_EXPOSURE_ADDED", Resource: key(next), Message: fmt.Sprintf("service type changes from %s to %s", displayType(oldType), newType)})
		}
	}
	if addedStrings(stringSet(nested(old, "spec")["externalIPs"]), stringSet(nested(next, "spec")["externalIPs"])) {
		out = append(out, Finding{Severity: "high", Code: "SERVICE_EXTERNAL_IP_ADDED", Resource: key(next), Message: "service newly adds externalIPs"})
	}
	return out
}

func diffIngress(old, next object) []Finding {
	before := ingressHosts(old)
	var out []Finding
	for host := range ingressHosts(next) {
		if !before[host] {
			out = append(out, Finding{Severity: "high", Code: "INGRESS_HOST_ADDED", Resource: key(next), Message: fmt.Sprintf("ingress newly exposes host %s", host)})
		}
	}
	if hasDefaultBackend(next) && !hasDefaultBackend(old) {
		out = append(out, Finding{Severity: "high", Code: "INGRESS_DEFAULT_BACKEND_ADDED", Resource: key(next), Message: "ingress newly adds a catch-all default backend"})
	}
	for route := range ingressPaths(next) {
		if !ingressPaths(old)[route] {
			out = append(out, Finding{Severity: "medium", Code: "INGRESS_PATH_ADDED", Resource: key(next), Message: fmt.Sprintf("ingress newly adds route %s", route)})
		}
	}
	return out
}

func ingressHosts(value object) map[string]bool {
	out := map[string]bool{}
	spec := nested(value, "spec")
	rules, _ := spec["rules"].([]any)
	for _, raw := range rules {
		rule, _ := asMap(raw)
		if host, _ := rule["host"].(string); host != "" {
			out[host] = true
		}
	}
	return out
}

func ingressPaths(value object) map[string]bool {
	out := map[string]bool{}
	rules, _ := nested(value, "spec")["rules"].([]any)
	for _, raw := range rules {
		rule, _ := asMap(raw)
		http, _ := asMap(rule["http"])
		paths, _ := http["paths"].([]any)
		for _, pathRaw := range paths {
			path, _ := asMap(pathRaw)
			host, _ := rule["host"].(string)
			route, _ := path["path"].(string)
			out[host+"|"+route] = true
		}
	}
	return out
}
func addedStrings(before, after map[string]bool) bool {
	for value := range after {
		if !before[value] {
			return true
		}
	}
	return false
}

func hasDefaultBackend(value object) bool {
	_, ok := nested(value, "spec")["defaultBackend"]
	return ok
}

func displayType(value string) string {
	if value == "" {
		return "ClusterIP"
	}
	return value
}
