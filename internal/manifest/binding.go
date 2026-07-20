package manifest

func diffNewBindings(before map[string]object, after []object) []Finding {
	roles, err := index(after)
	if err != nil {
		return []Finding{{Severity: "high", Code: "ANALYSIS_INCOMPLETE", Resource: "manifest", Message: err.Error()}}
	}
	var out []Finding
	for _, binding := range after {
		if kind(binding) != "RoleBinding" && kind(binding) != "ClusterRoleBinding" {
			continue
		}
		if _, existed := before[key(binding)]; existed {
			continue
		}
		roleKey := nestedString(binding, "roleRef", "kind") + "/" + namespaceForBinding(binding) + "/" + nestedString(binding, "roleRef", "name")
		if nestedString(binding, "roleRef", "kind") == "ClusterRole" {
			roleKey = "ClusterRole//" + nestedString(binding, "roleRef", "name")
		}
		role, exists := roles[roleKey]
		if !exists || !roleGrantsSecrets(role) {
			continue
		}
		out = append(out, Finding{Severity: "high", Code: "RBAC_SECRET_ACCESS_BOUND", Resource: key(binding), Message: "new binding grants a subject access to secrets"})
	}
	return out
}

func namespaceForBinding(binding object) string {
	if kind(binding) == "ClusterRoleBinding" {
		return ""
	}
	return namespace(binding)
}
func roleGrantsSecrets(role object) bool {
	for _, rule := range rules(role) {
		if rule.hasResource("secrets") || rule.hasResource("*") {
			return true
		}
	}
	return false
}
