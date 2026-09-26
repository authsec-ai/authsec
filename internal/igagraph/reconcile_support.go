package igagraph

import "time"

// MayEndSnapshotSupport reports whether an authoritative snapshot of this
// object class may end support, and which node class that is. A failed or
// partial snapshot, or a class this package does not own, ends nothing.
func MayEndSnapshotSupport(authoritative bool, objectClass string) (class string, ok bool) {
	if !authoritative {
		return "", false
	}
	class = SnapshotNodeClass(objectClass)
	return class, class != ""
}

// SnapshotNodeClass maps a collector snapshot class onto a support column.
// An empty result means absence must not run.
func SnapshotNodeClass(objectClass string) string {
	switch objectClass {
	case "linux.systemd_workload", "linux.process_group", "k8s.workload", "k8s.pod":
		return "workload"
	case "linux.local_account", "linux.local_group", "k8s.service_account",
		"user", "group", "computer",
		"msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount":
		return "identity"
	case "linux.file", "network.endpoint", "secret.reference",
		"k8s.service", "k8s.pvc", "k8s.pv":
		return "resource"
	case "k8s.role", "k8s.cluster_role", "k8s.network_policy",
		"linux.posix_acl", "linux.systemd", "linux.lsm", "linux.nftables":
		return "policy"
	default:
		return ""
	}
}

// RuntimePartition is the support partition runtime evidence uses.
// Snapshot absence never selects it, and runtime aging never selects a
// snapshot partition.
const RuntimePartition = "collector/object"

// RuntimeUnobserved is true when a runtime support row has not been confirmed
// inside the TTL. A zero TTL disables aging.
func RuntimeUnobserved(lastConfirmed, now time.Time, ttl time.Duration) bool {
	if ttl <= 0 || lastConfirmed.IsZero() {
		return false
	}
	return now.Sub(lastConfirmed) > ttl
}

// CollectorProviders are the providers whose canonical nodes this package
// retires when no live support remains. AWS reconciliation is unchanged.
func CollectorProvider(provider string) bool {
	switch provider {
	case "linux", "kubernetes", "ad":
		return true
	default:
		return false
	}
}

// MayRetireNode is true only when the node is one of those providers, some
// source has supported it, and none still does.
func MayRetireNode(provider string, anySupport, liveSupport int) bool {
	return CollectorProvider(provider) && anySupport > 0 && liveSupport == 0
}
