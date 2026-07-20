package manifest

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"
)

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
}

type object map[string]any

func Analyze(before, after []byte) ([]Finding, error) {
	oldObjects, err := parseAll(before)
	if err != nil {
		return nil, err
	}
	newObjects, err := parseAll(after)
	if err != nil {
		return nil, err
	}
	oldByKey, err := index(oldObjects)
	if err != nil {
		return nil, err
	}
	newByKey, err := index(newObjects)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for key, next := range newByKey {
		previous := oldByKey[key]
		switch kind(next) {
		case "Role", "ClusterRole":
			findings = append(findings, diffRole(previous, next, newObjects)...)
		case "RoleBinding", "ClusterRoleBinding", "ServiceAccount":
			// Bindings are analyzed as effective-permission events separately.
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod":
			findings = append(findings, diffWorkload(previous, next)...)
		case "Service":
			findings = append(findings, diffService(previous, next)...)
		case "Ingress":
			findings = append(findings, diffIngress(previous, next)...)
		case "IngressRoute":
			findings = append(findings, diffIngressRoute(previous, next)...)
		default:
			findings = append(findings, Finding{"info", "ANALYSIS_UNSUPPORTED_KIND", key, "resource kind is present but not covered by enabled security checks"})
		}
	}
	findings = append(findings, diffNewBindings(oldByKey, newObjects)...)
	for key, previous := range oldByKey {
		if _, stillPresent := newByKey[key]; !stillPresent && kind(previous) == "NetworkPolicy" {
			findings = append(findings, Finding{"high", "NETWORK_POLICY_REMOVED", key, "network policy is removed"})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].Code < findings[j].Code
	})
	return findings, nil
}

func severityRank(value string) int {
	switch value {
	case "high":
		return 3
	case "medium":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func parseAll(input []byte) ([]object, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var objects []object
	for {
		var value object
		err := decoder.Decode(&value)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse manifest: %w", err)
		}
		if kind(value) == "List" {
			items, ok := value["items"].([]any)
			if !ok {
				return nil, fmt.Errorf("List object has no items array")
			}
			for _, item := range items {
				child, ok := asMap(item)
				if !ok {
					return nil, fmt.Errorf("List contains a non-object item")
				}
				objects = append(objects, object(child))
			}
		} else if len(value) > 0 {
			objects = append(objects, value)
		}
	}
	return objects, nil
}

func index(objects []object) (map[string]object, error) {
	out := map[string]object{}
	for _, value := range objects {
		identity := key(value)
		if kind(value) == "" || name(value) == "" {
			return nil, fmt.Errorf("manifest object missing kind or metadata.name")
		}
		if _, exists := out[identity]; exists {
			return nil, fmt.Errorf("duplicate manifest identity %s", identity)
		}
		out[identity] = value
	}
	return out, nil
}
func key(v object) string       { return kind(v) + "/" + namespace(v) + "/" + name(v) }
func kind(v object) string      { return stringAt(v, "kind") }
func namespace(v object) string { return nestedString(v, "metadata", "namespace") }
func name(v object) string      { return nestedString(v, "metadata", "name") }
func stringAt(v object, k string) string {
	if x, ok := v[k].(string); ok {
		return x
	}
	return ""
}
func nestedString(v object, keys ...string) string {
	var current any = v
	for _, k := range keys {
		m, ok := asMap(current)
		if !ok {
			return ""
		}
		current = m[k]
	}
	x, _ := current.(string)
	return x
}

func asMap(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case object:
		return map[string]any(typed), true
	case map[string]any:
		return typed, true
	default:
		return nil, false
	}
}

func diffRole(old, next object, all []object) []Finding {
	if !roleIsBound(next, all) {
		return nil
	}
	oldRules := rules(old)
	newRules := rules(next)
	var out []Finding
	for _, rule := range newRules {
		if oldRuleContains(oldRules, rule) {
			continue
		}
		if rule.hasResource("secrets") {
			out = append(out, Finding{"high", "RBAC_SECRET_ACCESS_ADDED", key(next), "RBAC rule newly grants access to secrets"})
		}
		if rule.hasResource("*") || rule.hasVerb("*") {
			out = append(out, Finding{"high", "RBAC_WILDCARD_ACCESS_ADDED", key(next), "RBAC rule newly grants wildcard resource or verb access"})
		}
		if rule.hasVerb("bind") || rule.hasVerb("escalate") || rule.hasVerb("impersonate") {
			out = append(out, Finding{"high", "RBAC_ESCALATION_VERB_ADDED", key(next), "RBAC rule newly grants bind, escalate, or impersonate"})
		}
		if rule.resourceNamesWidened(oldRules) {
			out = append(out, Finding{"high", "RBAC_RESOURCE_NAMES_WIDENED", key(next), "RBAC rule removes or broadens resourceNames restrictions"})
		}
		if rule.nonResourceURLsAdded(oldRules) {
			out = append(out, Finding{"medium", "RBAC_NON_RESOURCE_URL_ADDED", key(next), "RBAC rule newly grants non-resource URL access"})
		}
	}
	return uniqueFindings(out)
}
func roleIsBound(role object, all []object) bool {
	roleKind, roleName, roleNamespace := kind(role), name(role), namespace(role)
	for _, candidate := range all {
		if kind(candidate) != "RoleBinding" && kind(candidate) != "ClusterRoleBinding" {
			continue
		}
		if nestedString(candidate, "roleRef", "kind") == roleKind && nestedString(candidate, "roleRef", "name") == roleName {
			if roleKind == "ClusterRole" || kind(candidate) == "ClusterRoleBinding" || namespace(candidate) == roleNamespace {
				return true
			}
		}
	}
	return false
}

type rule struct {
	Resources       map[string]bool
	Verbs           map[string]bool
	Names           map[string]bool
	NonResourceURLs map[string]bool
}

func rules(v object) []rule {
	var out []rule
	rawRules, _ := v["rules"].([]any)
	for _, raw := range rawRules {
		value, _ := asMap(raw)
		out = append(out, rule{Resources: stringSet(value["resources"]), Verbs: stringSet(value["verbs"]), Names: stringSet(value["resourceNames"]), NonResourceURLs: stringSet(value["nonResourceURLs"])})
	}
	return out
}
func stringSet(value any) map[string]bool {
	out := map[string]bool{}
	items, _ := value.([]any)
	for _, item := range items {
		if text, ok := item.(string); ok {
			out[text] = true
		}
	}
	return out
}
func (r rule) hasResource(value string) bool { return r.Resources[value] }
func (r rule) hasVerb(value string) bool     { return r.Verbs[value] }
func (r rule) resourceNamesWidened(old []rule) bool {
	if len(r.Names) > 0 {
		return false
	}
	for _, previous := range old {
		if setContains(previous.Resources, r.Resources) && setContains(previous.Verbs, r.Verbs) && len(previous.Names) > 0 {
			return true
		}
	}
	return false
}
func (r rule) nonResourceURLsAdded(old []rule) bool {
	for _, previous := range old {
		if setContains(previous.Verbs, r.Verbs) && !setContains(previous.NonResourceURLs, r.NonResourceURLs) {
			return true
		}
	}
	return len(r.NonResourceURLs) > 0
}

func oldRuleContains(old []rule, next rule) bool {
	for _, previous := range old {
		if !setContains(previous.Resources, next.Resources) || !setContains(previous.Verbs, next.Verbs) {
			continue
		}
		if len(next.Names) == 0 && len(previous.Names) > 0 {
			continue
		}
		if len(next.NonResourceURLs) > 0 && !setContains(previous.NonResourceURLs, next.NonResourceURLs) {
			continue
		}
		return true
	}
	return false
}
func setContains(superset, subset map[string]bool) bool {
	for value := range subset {
		if !superset[value] && !superset["*"] {
			return false
		}
	}
	return true
}
func uniqueFindings(input []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, finding := range input {
		if !seen[finding.Code] {
			seen[finding.Code] = true
			out = append(out, finding)
		}
	}
	return out
}

func contains(s, wanted string) bool {
	for i := 0; i+len(wanted) <= len(s); i++ {
		if s[i:i+len(wanted)] == wanted {
			return true
		}
	}
	return false
}

func diffWorkload(old, next object) []Finding {
	var out []Finding
	resource := key(next)
	if podBool(next, "hostNetwork") && !podBool(old, "hostNetwork") {
		out = append(out, Finding{"high", "WORKLOAD_HOST_NETWORK_ADDED", resource, "workload newly enables hostNetwork"})
	}
	if podBool(next, "hostPID") && !podBool(old, "hostPID") {
		out = append(out, Finding{"high", "WORKLOAD_HOST_PID_ADDED", resource, "workload newly enables hostPID"})
	}
	if podBool(next, "hostIPC") && !podBool(old, "hostIPC") {
		out = append(out, Finding{"high", "WORKLOAD_HOST_IPC_ADDED", resource, "workload newly enables hostIPC"})
	}
	if hasHostPath(next) && !hasHostPath(old) {
		out = append(out, Finding{"high", "WORKLOAD_HOST_PATH_ADDED", resource, "workload newly mounts a hostPath volume"})
	}
	if privileged(next) && !privileged(old) {
		out = append(out, Finding{"high", "WORKLOAD_PRIVILEGED_ADDED", resource, "workload newly adds a privileged container"})
	}
	oldSA, newSA := effectiveServiceAccount(old), effectiveServiceAccount(next)
	if oldSA != newSA {
		out = append(out, Finding{"high", "WORKLOAD_SERVICE_ACCOUNT_CHANGED", resource, fmt.Sprintf("service account changes from %s to %s", oldSA, newSA)})
	}
	for _, name := range containerNames(next) {
		oldContainer := containerByName(old, name)
		newContainer := containerByName(next, name)
		if boolAtMap(oldContainer, "securityContext", "runAsNonRoot") && !boolAtMap(newContainer, "securityContext", "runAsNonRoot") {
			out = append(out, Finding{"high", "WORKLOAD_RUN_AS_NON_ROOT_REMOVED", resource, fmt.Sprintf("container %s no longer requires non-root execution", name)})
		}
		if boolAtMap(oldContainer, "securityContext", "readOnlyRootFilesystem") && !boolAtMap(newContainer, "securityContext", "readOnlyRootFilesystem") {
			out = append(out, Finding{"high", "WORKLOAD_READ_ONLY_ROOT_FILESYSTEM_REMOVED", resource, fmt.Sprintf("container %s no longer uses a read-only root filesystem", name)})
		}
		if addedCapabilities(oldContainer, newContainer) {
			out = append(out, Finding{"high", "WORKLOAD_CAPABILITY_ADDED", resource, fmt.Sprintf("container %s adds Linux capabilities", name)})
		}
		if !boolAtMap(oldContainer, "securityContext", "allowPrivilegeEscalation") && boolAtMap(newContainer, "securityContext", "allowPrivilegeEscalation") {
			out = append(out, Finding{"high", "WORKLOAD_PRIVILEGE_ESCALATION_ALLOWED", resource, fmt.Sprintf("container %s newly allows privilege escalation", name)})
		}
		if runAsRoot(newContainer) && !runAsRoot(oldContainer) {
			out = append(out, Finding{"high", "WORKLOAD_ROOT_USER_ADDED", resource, fmt.Sprintf("container %s newly runs as UID 0", name)})
		}
	}
	return out
}
func boolAt(v object, keys ...string) bool {
	var current any = v
	for _, k := range keys {
		m, ok := asMap(current)
		if !ok {
			return false
		}
		current = m[k]
	}
	x, _ := current.(bool)
	return x
}
func privileged(v object) bool {
	for _, c := range podContainers(v) {
		sec, _ := asMap(c["securityContext"])
		if p, _ := sec["privileged"].(bool); p {
			return true
		}
	}
	return false
}
func hasHostPath(workload object) bool {
	volumes, _ := podSpec(workload)["volumes"].([]any)
	for _, raw := range volumes {
		volume, _ := asMap(raw)
		if _, ok := asMap(volume["hostPath"]); ok {
			return true
		}
	}
	return false
}
func nested(v object, keys ...string) map[string]any {
	var current any = v
	for _, k := range keys {
		m, ok := asMap(current)
		if !ok {
			return map[string]any{}
		}
		current = m[k]
	}
	m, _ := asMap(current)
	return m
}
