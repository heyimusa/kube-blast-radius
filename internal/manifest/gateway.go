package manifest

import "fmt"

func diffGateway(old, next object) []Finding {
	before := gatewayAllowedRouteScopes(old)
	after := gatewayAllowedRouteScopes(next)
	var out []Finding
	for listener, scope := range after {
		previousScope, existed := before[listener]
		if !existed {
			continue
		}
		if scopeRank(scope) > scopeRank(previousScope) {
			out = append(out, Finding{
				Severity: "high",
				Code:     "GATEWAY_ALLOWED_ROUTES_WIDENED",
				Resource: key(next),
				Message:  fmt.Sprintf("Gateway listener %s widens allowed route namespaces from %s to %s", listener, displayScope(previousScope), scope),
			})
		}
	}
	return out
}

func diffGatewayRoute(old, next object) []Finding {
	beforeHosts := gatewayRouteHostnames(old)
	afterHosts := gatewayRouteHostnames(next)
	var out []Finding
	for host := range afterHosts {
		if !beforeHosts[host] {
			out = append(out, Finding{Severity: "high", Code: "GATEWAY_ROUTE_HOSTNAME_ADDED", Resource: key(next), Message: fmt.Sprintf("Gateway API route newly exposes hostname %s", host)})
		}
	}
	if gatewayRouteHasCatchAll(next) && !gatewayRouteHasCatchAll(old) {
		out = append(out, Finding{Severity: "high", Code: "GATEWAY_ROUTE_CATCH_ALL_ADDED", Resource: key(next), Message: "Gateway API route newly adds a rule without matches"})
	}
	beforeBackends := gatewayCrossNamespaceBackends(old)
	for backend := range gatewayCrossNamespaceBackends(next) {
		if !beforeBackends[backend] {
			out = append(out, Finding{Severity: "high", Code: "GATEWAY_CROSS_NAMESPACE_BACKEND_ADDED", Resource: key(next), Message: fmt.Sprintf("Gateway API route newly references cross-namespace backend %s", backend)})
		}
	}
	return uniqueFindings(out)
}

func gatewayAllowedRouteScopes(value object) map[string]string {
	out := map[string]string{}
	listeners, _ := nested(value, "spec")["listeners"].([]any)
	for index, raw := range listeners {
		listener, _ := asMap(raw)
		name, _ := listener["name"].(string)
		if name == "" {
			name = fmt.Sprintf("listener-%d", index)
		}
		from := nestedMap(listener, "allowedRoutes", "namespaces")["from"]
		scope, _ := from.(string)
		out[name] = scope
	}
	return out
}

func scopeRank(scope string) int {
	switch scope {
	case "All":
		return 2
	case "Same":
		return 1
	default:
		// Selector depends on namespace labels outside a route-only diff.
		// Do not claim it is wider or narrower without evaluating that state.
		return 0
	}
}

func displayScope(scope string) string {
	if scope == "" {
		return "implementation default"
	}
	return scope
}

func gatewayRouteHostnames(value object) map[string]bool {
	return stringSet(nested(value, "spec")["hostnames"])
}

func gatewayRouteHasCatchAll(value object) bool {
	rules, _ := nested(value, "spec")["rules"].([]any)
	for _, raw := range rules {
		rule, _ := asMap(raw)
		matches, present := rule["matches"]
		if !present {
			return true
		}
		items, ok := matches.([]any)
		if !ok || len(items) == 0 {
			return true
		}
	}
	return false
}

func gatewayCrossNamespaceBackends(value object) map[string]bool {
	out := map[string]bool{}
	routeNamespace := namespace(value)
	rules, _ := nested(value, "spec")["rules"].([]any)
	for _, raw := range rules {
		rule, _ := asMap(raw)
		refs, _ := rule["backendRefs"].([]any)
		for _, refRaw := range refs {
			ref, _ := asMap(refRaw)
			backendNamespace, _ := ref["namespace"].(string)
			backendName, _ := ref["name"].(string)
			if backendNamespace != "" && backendNamespace != routeNamespace && backendName != "" {
				group, _ := ref["group"].(string)
				kind, _ := ref["kind"].(string)
				if group == "" {
					group = "core"
				}
				if kind == "" {
					kind = "Service"
				}
				out[group+"/"+kind+"/"+backendNamespace+"/"+backendName] = true
			}
		}
	}
	return out
}

func nestedMap(value map[string]any, keys ...string) map[string]any {
	current := value
	for _, key := range keys {
		next, ok := asMap(current[key])
		if !ok {
			return map[string]any{}
		}
		current = next
	}
	return current
}
