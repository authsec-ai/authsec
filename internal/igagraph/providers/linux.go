package providers

import (
	"net"
	"strings"

	igraph "github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

func normalizeLinux(in Input) (*Plan, error) {
	p := &Plan{}
	byRef := map[string]Object{}
	for _, o := range in.Objects {
		byRef[o.Ref] = o
		if err := linuxObject(p, in.EstateID, o); err != nil {
			skipObject(p, o, err)
		}
	}
	for _, ob := range in.Observations {
		if ob.Preview || !strings.HasPrefix(ob.Kind, "runtime.") {
			continue
		}
		if err := linuxObservation(p, in.EstateID, ob, byRef); err != nil {
			p.Skipped = append(p.Skipped, Skipped{Kind: ob.Kind, Ref: ob.SubjectRef, Reason: err.Error()})
		}
	}
	return p, nil
}

func linuxObject(p *Plan, estate string, o Object) error {
	switch o.Kind {
	case "linux.systemd_workload":
		unit := str(o.Native, "unit")
		key, err := igraph.SystemdWorkloadKey(estate, unit)
		if err != nil {
			return err
		}
		p.Workloads = append(p.Workloads, Workload{
			SourceKey: key, Continuity: models.ContinuityRecognitionOnly,
			Provider: models.ProviderLinux, RuntimeKind: "systemd", Name: unit,
			Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
		if user := str(o.Native, "user"); user != "" {
			p.Unresolved = append(p.Unresolved, "linux-user-name:"+user)
		}
		if doc := nested(o.Attrs, "systemd"); doc != nil {
			if err := linuxConstraint(p, estate, key, "linux_systemd", models.RightsSystemd, "systemd", unit, doc); err != nil {
				return err
			}
		}
		if doc := nested(o.Attrs, "lsm"); doc != nil {
			if err := linuxConstraint(p, estate, key, "linux_lsm", models.RightsLSM, "lsm", unit, doc); err != nil {
				return err
			}
		}
		if doc := nested(o.Attrs, "nftables"); doc != nil {
			if err := linuxConstraint(p, estate, key, "linux_nftables", models.RightsNftables, "nftables", unit, doc); err != nil {
				return err
			}
		}
	case "linux.process_group":
		key, err := igraph.UnmanagedProcessGroupKey(estate, str(o.Native, "boot_id"), str(o.Native, "root_pid"), str(o.Native, "start_ticks"))
		if err != nil {
			return err
		}
		p.Workloads = append(p.Workloads, Workload{
			SourceKey: key, Continuity: models.ContinuityRecognitionOnly,
			Provider: models.ProviderLinux, RuntimeKind: "process_group",
			Name: str(o.Native, "root_pid"), Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
	case "linux.local_account":
		ns := str(o.Native, "user_namespace")
		if ns == "" {
			ns = "host"
		}
		key, err := igraph.LocalIdentityKey(estate, ns, str(o.Native, "uid"))
		if err != nil {
			return err
		}
		name := str(o.Attrs, "name")
		p.Identities = append(p.Identities, Identity{
			SourceKey: key, Continuity: models.ContinuityRecognitionOnly,
			Provider: models.ProviderLinux, Kind: models.AccountKindLocalUser,
			Name: name, State: models.AccountStateEnabled, Backing: "host",
			Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
	case "linux.local_group":
		ns := str(o.Native, "user_namespace")
		if ns == "" {
			ns = "host"
		}
		key, err := igraph.LocalIdentityKey(estate, ns, "gid:"+str(o.Native, "gid"))
		if err != nil {
			return err
		}
		p.Identities = append(p.Identities, Identity{
			SourceKey: key, Continuity: models.ContinuityRecognitionOnly,
			Provider: models.ProviderLinux, Kind: models.AccountKindLocalGroup,
			Name: str(o.Attrs, "name"), State: models.AccountStateEnabled, Backing: "host",
			Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
	case "linux.file":
		ns := str(o.Native, "mount_namespace")
		if ns == "" {
			ns = "host"
		}
		key, err := igraph.FileResourceKey(estate, ns, str(o.Native, "path"))
		if err != nil {
			return err
		}
		p.Resources = append(p.Resources, Resource{
			SourceKey: key, Provider: models.ProviderLinux, Kind: "file",
			Name: str(o.Native, "path"), ReferenceStatus: models.ReferenceStatusReferenced,
			NativeKind: "file", Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
		if acl := nested(o.Attrs, "posix_acl"); acl != nil {
			pol, err := igraph.FileResourceKey(estate, ns, str(o.Native, "path")+"#acl")
			if err != nil {
				return err
			}
			p.Policies = append(p.Policies, Policy{
				SourceKey: pol, Continuity: models.ContinuityRecognitionOnly,
				Provider: models.ProviderLinux, Kind: models.PolicyKindPOSIXACL,
				Name: str(o.Native, "path"), RightsSchema: models.RightsPOSIXACL,
				Document: mustJSON(acl),
			})
		}
	case "network.endpoint":
		private := endpointPrivate(o.Native)
		key, err := igraph.NetworkEndpointKey(str(o.Native, "address_family"), str(o.Native, "address"), str(o.Native, "port"), str(o.Native, "protocol"), estate, private)
		if err != nil {
			return err
		}
		p.Resources = append(p.Resources, Resource{
			SourceKey: key, Provider: models.ProviderLinux, Kind: "endpoint",
			Name:            str(o.Native, "address") + ":" + str(o.Native, "port"),
			ReferenceStatus: models.ReferenceStatusReferenced, NativeKind: "endpoint",
			Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
	case "secret.reference":
		ns := str(o.Native, "namespace")
		if ns == "" {
			ns = "host"
		}
		key, err := igraph.SecretRefKey(first(str(o.Native, "provider"), "linux"), estate, ns, str(o.Native, "name"), str(o.Native, "key"))
		if err != nil {
			return err
		}
		p.Resources = append(p.Resources, Resource{
			SourceKey: key, Provider: models.ProviderLinux, Kind: "secret_reference",
			Name: str(o.Native, "name"), ReferenceStatus: models.ReferenceStatusReferenced,
			NativeKind: "secret_reference", Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
	}
	return nil
}

func linuxConstraint(p *Plan, estate, workloadKey, kind, schema, bind, name string, doc map[string]any) error {
	_ = estate
	pol := workloadKey + igraph.Sep + "policy" + igraph.Sep + bind
	p.Policies = append(p.Policies, Policy{
		SourceKey: pol, Continuity: models.ContinuityRecognitionOnly,
		Provider: models.ProviderLinux, Kind: kind, Name: name,
		RightsSchema: schema, Document: mustJSON(doc),
	})
	p.PolicyBindings = append(p.PolicyBindings, PolicyBinding{
		SourceKey: pol + igraph.Sep + "bind", WorkloadKey: workloadKey, PolicyKey: pol, Kind: bind,
	})
	return nil
}

func linuxObservation(p *Plan, estate string, ob Observation, byRef map[string]Object) error {
	rt := ob.Runtime
	key, err := igraph.ProcessRuntimeKey(estate, str(rt, "boot_id"), str(rt, "pid_namespace"), str(rt, "pid"), str(rt, "start_ticks"))
	if err != nil {
		return err
	}
	subject := byRef[ob.SubjectRef]
	wkey := workloadKey(p, subject.Ref)
	if wkey == "" {
		wkey, err = igraph.UnmanagedProcessGroupKey(estate, str(rt, "boot_id"), str(rt, "pid"), str(rt, "start_ticks"))
		if err != nil {
			return err
		}
		p.Workloads = append(p.Workloads, Workload{
			SourceKey: wkey, Continuity: models.ContinuityRecognitionOnly,
			Provider: models.ProviderLinux, RuntimeKind: "process_group", Name: str(rt, "pid"),
			Attrs: jsonOrEmpty(nil), Ref: ob.SubjectRef,
		})
	}
	p.Runtimes = append(p.Runtimes, Runtime{
		SourceKey: key, WorkloadKey: wkey, Kind: "process",
		Incarnation: str(rt, "boot_id"), ObservedAt: ob.ObservedAt, Observation: ob.ID,
	})
	if idKey := identityKey(p, byRef[ob.IdentityRef].Ref); idKey != "" {
		p.Bindings = append(p.Bindings, Binding{
			RuntimeKey: key, IdentityKey: idKey, Kind: "uid", Observation: ob.ID, From: ob.ObservedAt,
		})
	} else if uid := str(rt, "uid"); uid != "" {
		ns := str(rt, "user_namespace")
		if ns == "" {
			ns = "host"
		}
		idKey, err = igraph.LocalIdentityKey(estate, ns, uid)
		if err != nil {
			return err
		}
		p.Identities = append(p.Identities, Identity{
			SourceKey: idKey, Continuity: models.ContinuityRecognitionOnly,
			Provider: models.ProviderLinux, Kind: models.AccountKindLocalUser,
			Name: uid, State: models.AccountStateEnabled, Backing: "host", Attrs: jsonOrEmpty(nil),
		})
		p.Bindings = append(p.Bindings, Binding{
			RuntimeKey: key, IdentityKey: idKey, Kind: "uid", Observation: ob.ID, From: ob.ObservedAt,
		})
	}
	if res := resourceKey(p, byRef[ob.ResourceRef].Ref); res != "" {
		p.Observed = append(p.Observed, Observed{
			WorkloadKey: wkey, RuntimeKey: key, ResourceKey: res, Observation: ob.ID,
			Action: ob.Kind, Outcome: outcome(ob.Outcome), Attribution: ob.Attribution, ObservedAt: ob.ObservedAt,
		})
	}
	return nil
}

func workloadKey(p *Plan, ref string) string {
	if ref == "" {
		return ""
	}
	for _, w := range p.Workloads {
		if w.Ref == ref {
			return w.SourceKey
		}
	}
	return ""
}

func identityKey(p *Plan, ref string) string {
	if ref == "" {
		return ""
	}
	for _, id := range p.Identities {
		if id.Ref == ref {
			return id.SourceKey
		}
	}
	return ""
}

func resourceKey(p *Plan, ref string) string {
	for _, r := range p.Resources {
		if r.Ref == ref {
			return r.SourceKey
		}
	}
	return ""
}

func endpointPrivate(native map[string]any) bool {
	if str(native, "private") == "true" {
		return true
	}
	ip := net.ParseIP(str(native, "address"))
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func jsonOrEmpty(v any) []byte {
	if v == nil {
		return []byte(`{}`)
	}
	return mustJSON(v)
}
