package services

import (
	"context"
	"encoding/json"
	"log"
	"net/netip"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

/* azure_signin_origin.go answers WHERE an identity signs in from. Entra's
   sign-in log gives only an IP address; for an identity that signs in with a
   client secret, that address is the one clue to where the secret is used.

   Each subscription pass records the subscription's public IP addresses and
   prefixes, and what each is attached to (a VM through its network
   interface, a load balancer, a NAT gateway). After every discovery run,
   each sign-in address on a cloud_usage row is placed:

     your_azure     one of the connected subscriptions' public addresses
     azure          an Azure address that is not one of yours (Microsoft's
                    published service tags: the service and region)
     private        a private or link-local address
     outside_azure  none of the above, when the service tags were read
     unknown        not yours, and the service tags could not be read

   Facts only: where an address belongs, as Azure publishes it. */

// azurePublicIPQuery lists a subscription's public addresses and prefixes,
// and what each address is attached to.
const azurePublicIPQuery = `Resources
| where type in~ ('microsoft.network/publicipaddresses', 'microsoft.network/publicipprefixes')
| project id, name, type, ip = tostring(properties.ipAddress), prefix = tostring(properties.ipPrefix),
    attachedTo = tostring(properties.ipConfiguration.id), natGateway = tostring(properties.natGateway.id)
| order by id asc`

// azureNICPublicIPQuery maps each public address on a network interface to
// the VM using that interface.
const azureNICPublicIPQuery = `Resources
| where type =~ 'microsoft.network/networkinterfaces'
| mv-expand ipc = properties.ipConfigurations
| project nic = id, vm = tostring(properties.virtualMachine.id), pip = tostring(ipc.properties.publicIPAddress.id)
| where isnotempty(pip)
| order by nic asc`

// azureServiceTagLocation addresses the service tag call; any region returns
// the whole list.
const azureServiceTagLocation = "westus"

type azurePublicIPRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	IP         string `json:"ip"`
	Prefix     string `json:"prefix"`
	AttachedTo string `json:"attachedTo"`
	NATGateway string `json:"natGateway"`
}

type azureNICRow struct {
	NIC string `json:"nic"`
	VM  string `json:"vm"`
	PIP string `json:"pip"`
}

// azurePublicAddress is one public address or prefix of a subscription, as
// recorded on its connector (attrs.public_ips).
type azurePublicAddress struct {
	IP         string `json:"ip,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
	ResourceID string `json:"resource_id"`
	Name       string `json:"name"`
	// AttachedTo is the resource using the address: a VM, a load balancer,
	// a NAT gateway (whose subnets egress through it), ...
	AttachedTo   string `json:"attached_to,omitempty"`
	AttachedKind string `json:"attached_kind,omitempty"`
}

// armResourceOf trims an ARM id to its top resource
// (".../providers/<namespace>/<type>/<name>"), dropping child segments such
// as a NIC's ipConfigurations.
func armResourceOf(id string) string {
	seg := strings.Split(strings.Trim(strings.ToLower(id), "/"), "/")
	if len(seg) < 8 {
		return strings.ToLower(id)
	}
	return "/" + strings.Join(seg[:8], "/")
}

// armTypeOf is "<namespace>/<type>" of an ARM resource id.
func armTypeOf(id string) string {
	seg := strings.Split(strings.Trim(strings.ToLower(id), "/"), "/")
	if len(seg) < 8 {
		return ""
	}
	return seg[5] + "/" + seg[6]
}

// collectPublicIPs records the subscription's public addresses and prefixes
// on its connector.
func (s *AzureOnboardingService) collectPublicIPs(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, counters map[string]int) models.SurfaceCoverage {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "Microsoft.ResourceGraph/resources (public IP addresses and prefixes)"}
	rows, err := azureQueryAll[azurePublicIPRow](ctx, s, armToken, subscriptionID, azurePublicIPQuery)
	if err != nil {
		logAzureError("public ip addresses", err)
		return surfaceFailure(surface, err, len(rows))
	}
	nics, err := azureQueryAll[azureNICRow](ctx, s, armToken, subscriptionID, azureNICPublicIPQuery)
	if err != nil {
		logAzureError("network interfaces", err)
		return surfaceFailure(surface, err, 0)
	}
	vmOfPIP := map[string]string{}
	for _, n := range nics {
		if n.VM != "" {
			vmOfPIP[strings.ToLower(n.PIP)] = strings.ToLower(n.VM)
		}
	}
	out := make([]azurePublicAddress, 0, len(rows))
	for _, r := range rows {
		a := azurePublicAddress{ResourceID: strings.ToLower(r.ID), Name: r.Name}
		switch {
		case strings.EqualFold(r.Type, "microsoft.network/publicipprefixes"):
			if r.Prefix == "" {
				continue
			}
			a.Prefix = r.Prefix
		case r.IP == "":
			// Allocated dynamically and not in use: no address yet.
			continue
		default:
			a.IP = r.IP
		}
		switch {
		case vmOfPIP[a.ResourceID] != "":
			a.AttachedTo = vmOfPIP[a.ResourceID]
		case r.AttachedTo != "":
			a.AttachedTo = armResourceOf(r.AttachedTo)
		case r.NATGateway != "":
			a.AttachedTo = strings.ToLower(r.NATGateway)
		}
		a.AttachedKind = armTypeOf(a.AttachedTo)
		out = append(out, a)
	}
	if err := s.inventory.MergeAttrs(workspaceID, connectorID, generation, map[string]interface{}{"public_ips": out}); err != nil {
		log.Printf("[azure] scan: could not record public addresses for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not record the public addresses it read"
		return surface
	}
	surface.Count = len(out)
	counters["public_ips"] = len(out)
	return surface
}

/* -------------------------------- attribution -------------------------------- */

// azureIPOrigin is where one sign-in address belongs.
type azureIPOrigin struct {
	IP    string `json:"ip"`
	Where string `json:"where"`
	// Your Azure: the subscription and the resource the address is on.
	Subscription string `json:"subscription,omitempty"`
	Resource     string `json:"resource,omitempty"`
	ResourceKind string `json:"resource_kind,omitempty"`
	PublicIP     string `json:"public_ip_resource,omitempty"`
	// Azure (not yours): the service tag, its service and region.
	ServiceTag string `json:"service_tag,omitempty"`
	Service    string `json:"service,omitempty"`
	Region     string `json:"region,omitempty"`
}

// Where values.
const (
	ipOriginYourAzure = "your_azure"
	ipOriginAzure     = "azure"
	ipOriginPrivate   = "private"
	ipOriginOutside   = "outside_azure"
	ipOriginUnknown   = "unknown"
)

type azureOwnAddress struct {
	prefix       netip.Prefix
	subscription string
	addr         azurePublicAddress
}

type azureTagPrefix struct {
	prefix netip.Prefix
	tag    *azure.ServiceTag
}

// azureIPPlacer places addresses against the workspace's own public
// addresses and Microsoft's service tags.
type azureIPPlacer struct {
	own      []azureOwnAddress
	tags     []azureTagPrefix
	tagsRead bool
}

func (p *azureIPPlacer) place(raw string) azureIPOrigin {
	o := azureIPOrigin{IP: raw, Where: ipOriginUnknown}
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return o
	}
	ip = ip.Unmap()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		o.Where = ipOriginPrivate
		return o
	}
	for _, a := range p.own {
		if a.prefix.Contains(ip) {
			o.Where, o.Subscription, o.PublicIP = ipOriginYourAzure, a.subscription, a.addr.ResourceID
			o.Resource, o.ResourceKind = a.addr.AttachedTo, a.addr.AttachedKind
			if o.Resource == "" {
				o.Resource, o.ResourceKind = a.addr.ResourceID, "microsoft.network/publicipaddresses"
			}
			return o
		}
	}
	// The most specific service tag that holds the address; at equal length,
	// a named service over the catch-all AzureCloud.
	var best *azureTagPrefix
	for i := range p.tags {
		t := &p.tags[i]
		if !t.prefix.Contains(ip) {
			continue
		}
		if best == nil || t.prefix.Bits() > best.prefix.Bits() ||
			(t.prefix.Bits() == best.prefix.Bits() && isAzureCloudTag(best.tag) && !isAzureCloudTag(t.tag)) {
			best = t
		}
	}
	switch {
	case best != nil:
		o.Where, o.ServiceTag, o.Service, o.Region = ipOriginAzure, best.tag.Name, best.tag.Service, best.tag.Region
	case p.tagsRead:
		o.Where = ipOriginOutside
	}
	return o
}

// isAzureCloudTag reports whether a tag is the catch-all for all of Azure
// ("AzureCloud", "AzureCloud.eastus").
func isAzureCloudTag(t *azure.ServiceTag) bool {
	return t.Name == "AzureCloud" || strings.HasPrefix(t.Name, "AzureCloud.")
}

// attributeSignInIPs places every sign-in address recorded under the tenant
// connector, after a discovery run: the tenant pass read the sign-ins, the
// subscription passes the subscriptions' addresses.
func (s *AzureOnboardingService) attributeSignInIPs(ctx context.Context, workspaceID, tenantConnectorID uuid.UUID, tenantID string) (map[string]int, error) {
	placer := &azureIPPlacer{}
	var subs []models.CloudConnector
	if err := s.db.Where("workspace_id = ? AND provider = ? AND scope_kind = ? AND status = ? AND lower(parent_scope_id) = ?",
		workspaceID, models.CloudProviderAzure, models.CloudScopeSubscription, models.CloudConnectorActive, strings.ToLower(tenantID)).
		Order("scope_id").Find(&subs).Error; err != nil {
		return nil, err
	}
	for _, c := range subs {
		var attrs struct {
			DisplayName string               `json:"display_name"`
			PublicIPs   []azurePublicAddress `json:"public_ips"`
		}
		_ = json.Unmarshal(c.Attrs, &attrs)
		for _, a := range attrs.PublicIPs {
			var pfx netip.Prefix
			var err error
			if a.Prefix != "" {
				pfx, err = netip.ParsePrefix(a.Prefix)
			} else {
				var ip netip.Addr
				if ip, err = netip.ParseAddr(a.IP); err == nil {
					pfx = netip.PrefixFrom(ip, ip.BitLen())
				}
			}
			if err == nil {
				placer.own = append(placer.own, azureOwnAddress{prefix: pfx.Masked(), subscription: firstNonEmpty(attrs.DisplayName, c.ScopeID), addr: a})
			}
		}
	}
	// Microsoft's ranges, through any subscription of the tenant.
	if len(subs) > 0 {
		discoveryCfg, cfgErr := s.resolveDiscoveryConfig(workspaceID, tenantID)
		if cfgErr != nil {
			logAzureError("azure service tags: credentials", cfgErr)
		} else if armToken, err := s.api.AppToken(ctx, discoveryCfg, tenantID, azure.ScopeARMApp); err == nil {
			if tags, err := s.api.ListServiceTags(ctx, armToken, subs[0].ScopeID, azureServiceTagLocation); err == nil {
				placer.tagsRead = true
				for i := range tags {
					for _, p := range tags[i].Prefixes {
						placer.tags = append(placer.tags, azureTagPrefix{prefix: p, tag: &tags[i]})
					}
				}
			} else {
				logAzureError("azure service tags", err)
			}
		} else {
			logAzureError("arm app token for service tags", err)
		}
	}

	var usage []struct {
		ID    uuid.UUID
		Attrs []byte
	}
	if err := s.db.Model(&models.CloudUsage{}).Select("id, attrs").
		Where("workspace_id = ? AND connector_id = ? AND source = ?", workspaceID, tenantConnectorID, models.UsageSourceEntraSignIn).
		Scan(&usage).Error; err != nil {
		return nil, err
	}
	counts := map[string]int{}
	cache := map[string]azureIPOrigin{}
	for _, u := range usage {
		var attrs struct {
			IPs []string `json:"ip_addresses"`
		}
		_ = json.Unmarshal(u.Attrs, &attrs)
		if len(attrs.IPs) == 0 {
			continue
		}
		origins := make([]azureIPOrigin, 0, len(attrs.IPs))
		for _, ip := range attrs.IPs {
			o, ok := cache[ip]
			if !ok {
				o = placer.place(ip)
				cache[ip] = o
				counts[o.Where]++
			}
			origins = append(origins, o)
		}
		sort.Slice(origins, func(i, j int) bool { return origins[i].IP < origins[j].IP })
		raw, err := json.Marshal(origins)
		if err != nil {
			continue
		}
		if err := s.db.Exec(`UPDATE cloud_usage SET attrs = attrs || jsonb_build_object('ip_origins', ?::jsonb) WHERE id = ?`,
			string(raw), u.ID).Error; err != nil {
			return counts, err
		}
	}
	return counts, nil
}

// logAttributeSignInIPs runs attribution after a run and logs the outcome.
func (s *AzureOnboardingService) logAttributeSignInIPs(ctx context.Context, workspaceID, tenantConnectorID uuid.UUID, tenantID string) {
	counts, err := s.attributeSignInIPs(ctx, workspaceID, tenantConnectorID, tenantID)
	if err != nil {
		log.Printf("[azure] sign-in origins for tenant %s failed: %v", tenantID, err)
		return
	}
	log.Printf("[azure] sign-in origins for tenant %s: %d addresses yours in Azure, %d Azure (not yours), %d outside Azure, %d private, %d unknown",
		tenantID, counts[ipOriginYourAzure], counts[ipOriginAzure], counts[ipOriginOutside], counts[ipOriginPrivate], counts[ipOriginUnknown])
}
