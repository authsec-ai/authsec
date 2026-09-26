package collectorcontract

import "strings"

// ObjectKinds is the P0 native object vocabulary.
func ObjectKinds() []string {
	return []string{
		"linux.systemd_workload",
		"linux.process_group",
		"linux.local_account",
		"linux.local_group",
		"linux.file",
		"network.endpoint",
		"secret.reference",
		"k8s.workload",
		"k8s.pod",
		"k8s.service_account",
		"k8s.role",
		"k8s.cluster_role",
		"k8s.role_binding",
		"k8s.cluster_role_binding",
		"k8s.service",
		"k8s.endpoint_slice",
		"k8s.pvc",
		"k8s.pv",
		"k8s.network_policy",
		"k8s.namespace",
		"k8s.node",
	}
}

// ObservationKinds is the P0 fact vocabulary.
func ObservationKinds() []string {
	return []string{
		"runtime.process_exec",
		"runtime.process_exit",
		"runtime.file_open",
		"runtime.file_io",
		"runtime.network_connect",
		"runtime.dns",
		"runtime.privilege_change",
		"runtime.credential_reference",
		"collector.health",
	}
}

// KnownObjectKind reports membership in ObjectKinds.
func KnownObjectKind(kind string) bool { return contains(ObjectKinds(), kind) }

// KnownObservationKind reports membership in ObservationKinds.
func KnownObservationKind(kind string) bool { return contains(ObservationKinds(), kind) }

// IsPrivilegedKind is an assertion, approval, or ownership record.
// Sensors are not allowed to author these. The check is by kind name so a
// new privileged kind cannot slip through as an unknown 422.
func IsPrivilegedKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	for _, word := range []string{"assertion", "approval", "ownership"} {
		if k == word || strings.HasPrefix(k, word+".") || strings.HasPrefix(k, word+"_") ||
			strings.Contains(k, "."+word) || strings.Contains(k, "_"+word) {
			return true
		}
	}
	return false
}

// NamespacedKind is a Kubernetes kind that must name an approved namespace.
func NamespacedKind(kind string) bool {
	switch kind {
	case "k8s.workload", "k8s.pod", "k8s.service_account", "k8s.role", "k8s.role_binding",
		"k8s.service", "k8s.endpoint_slice", "k8s.pvc", "k8s.network_policy":
		return true
	default:
		return false
	}
}

// ClusterScopedKind is a Kubernetes kind allowed only when the namespace
// allowlist contains "*".
func ClusterScopedKind(kind string) bool {
	switch kind {
	case "k8s.cluster_role", "k8s.cluster_role_binding", "k8s.namespace", "k8s.node", "k8s.pv":
		return true
	default:
		return false
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
