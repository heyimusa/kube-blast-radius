package manifest

import "sort"

func diffIngressRoute(old, next object) []Finding {
	oldMatches := ingressRouteMatches(old)
	newMatches := ingressRouteMatches(next)
	var added []string
	for match := range newMatches {
		if !oldMatches[match] {
			added = append(added, match)
		}
	}
	if len(added) == 0 {
		return nil
	}
	sort.Strings(added)
	code, severity := "TRAEFIK_INGRESS_ROUTE_MATCH_ADDED", "medium"
	if len(oldMatches) == 0 {
		code, severity = "TRAEFIK_INGRESS_ROUTE_HOST_ADDED", "high"
	}
	return []Finding{{Severity: severity, Code: code, Resource: key(next), Message: "Traefik IngressRoute newly adds rule " + added[0]}}
}

func ingressRouteMatches(value object) map[string]bool {
	out := map[string]bool{}
	routes, _ := nested(value, "spec")["routes"].([]any)
	for _, raw := range routes {
		route, _ := asMap(raw)
		if match, ok := route["match"].(string); ok && match != "" {
			out[match] = true
		}
	}
	return out
}
