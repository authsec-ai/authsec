package k8sgraph

import (
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Reading keys back.
//
// THE INVERSE OF Key AND Partition.Key, IN THE SAME PACKAGE. A reader that
// needs to know which cluster, namespace or binding a row belongs to must not
// split a key with its own idea of the format: a second spelling of a key is
// the duplication bug, and a second PARSER of one is the same bug read the
// other way -- it keeps working until the format changes, then answers with
// the wrong namespace. So the format is read back here, beside the code that
// writes it, and round-trip tested against it.

// The object types Key is called with.
const (
	keyServiceAccount     = "serviceaccount"
	keyUser               = "user"
	keyGroup              = "group"
	keyRole               = "role"
	keyClusterRole        = "clusterrole"
	keyRoleBinding        = "rolebinding"
	keyClusterRoleBinding = "clusterrolebinding"
	keyWorkload           = "workload"
)

// ObjectKey is what a Kubernetes source key names: the cluster, the object type
// the key was formatted for, and -- where the key states them -- the namespace
// and name.
type ObjectKey struct {
	Cluster string
	// Type is the key's object type: serviceaccount, user, group, role,
	// clusterrole, rolebinding, clusterrolebinding or workload.
	Type string
	// Namespace is "" for a cluster-scoped object. A workload's fingerprint key
	// states no namespace: its provider_attrs carry it.
	Namespace string
	// Name is the object's name; a fingerprint-keyed workload's fingerprint.
	Name string
}

// ClusterScoped reports whether the object the key names is cluster-scoped.
func (k ObjectKey) ClusterScoped() bool { return k.Namespace == "" }

// ParseKey reads a source key written by Key and its callers (RoleKey,
// BindingKey, ServiceAccountKey, SubjectKey, StatementKey, WorkloadKey,
// LegacyWorkloadKey, and an assignment's BindingKey + Sep + SubjectKey).
// Trailing segments -- a statement's rule hash, an assignment's subject -- are
// ignored: they name something inside or beside the object, not the object.
// ok is false for anything that is not a Kubernetes key of a known type.
func ParseKey(key string) (ObjectKey, bool) {
	parts := strings.Split(key, Sep)
	if len(parts) < 4 || parts[0] != models.ProviderK8s || parts[1] == "" {
		return ObjectKey{}, false
	}
	out := ObjectKey{Cluster: parts[1], Type: parts[2]}
	rest := parts[3:]
	switch out.Type {
	case keyServiceAccount, keyRole, keyRoleBinding:
		if len(rest) < 2 || rest[0] == "" || rest[1] == "" {
			return ObjectKey{}, false
		}
		out.Namespace, out.Name = rest[0], rest[1]
	case keyUser, keyGroup, keyClusterRole, keyClusterRoleBinding:
		if rest[0] == "" {
			return ObjectKey{}, false
		}
		out.Name = rest[0]
	case keyWorkload:
		// WorkloadKey is k8s␟cluster␟workload␟<fingerprint>; LegacyWorkloadKey
		// is k8s␟cluster␟workload␟<namespace>␟<name>.
		if len(rest) >= 2 {
			out.Namespace, out.Name = rest[0], rest[1]
		} else {
			out.Name = rest[0]
		}
	default:
		return ObjectKey{}, false
	}
	return out, true
}

// ParsePartitionKey reads a key written by Partition.Key back into the
// Partition it names. ok is false for a key this package does not write --
// the bare namespace an unattributed snapshot stamps (partitionKeyFor with no
// sweep), the empty key, or a key naming a class or target Partitions never
// emits (the legacy executes_as target): no sweep reconciles such a row, so it
// must not be read as covered by one.
//
// The cluster is the middle of the key and is read as everything between the
// source and the last three fields, so a cluster name holding the separator
// still parses; a namespace, target and class never hold it.
func ParsePartitionKey(key string) (Partition, bool) {
	parts := strings.Split(key, "|")
	if len(parts) < 5 {
		return Partition{}, false
	}
	n := len(parts)
	src, err := uuid.Parse(parts[0])
	if err != nil {
		return Partition{}, false
	}
	p := Partition{
		SourceID:  src,
		Cluster:   strings.Join(parts[1:n-3], "|"),
		Namespace: parts[n-3],
		Target:    parts[n-2],
		Class:     parts[n-1],
	}
	if p.Cluster == "" || p.Namespace == "" {
		return Partition{}, false
	}
	if p.Namespace == "-cluster-" {
		p.Namespace = ""
	}
	switch p.Target {
	case "node":
		p.Target = ""
		switch p.Class {
		case ClassIdentity, ClassPolicy, ClassEntitlement, ClassWorkload:
		default:
			return Partition{}, false
		}
	case TargetAssignment, TargetAccessEdge, TargetExecutesAs:
		if p.Class != "" {
			return Partition{}, false
		}
	default:
		return Partition{}, false
	}
	if p.Key() != key {
		return Partition{}, false // not a key this package wrote
	}
	return p, true
}
