package azure

import (
	"context"
	"net/netip"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"
)

// ServiceTag is one of Microsoft's published Azure IP range sets ("service
// tags"): the address prefixes one Azure service, or all of Azure, uses in a
// region. Read through armnetwork (the official Resource Manager SDK) under
// Reader; the same list Microsoft publishes for firewalls.
type ServiceTag struct {
	Name     string
	Service  string
	Region   string
	Prefixes []netip.Prefix
}

// ListServiceTags returns every Azure service tag. location only addresses
// the call (any Azure region answers with the whole public-cloud list).
func (c *Client) ListServiceTags(ctx context.Context, armToken, subscriptionID, location string) ([]ServiceTag, error) {
	cl, err := armnetwork.NewServiceTagsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	resp, err := cl.List(ctx, location, nil)
	if err != nil {
		return nil, armError(err)
	}
	out := make([]ServiceTag, 0, len(resp.Values))
	for _, v := range resp.Values {
		if v == nil || v.Properties == nil {
			continue
		}
		t := ServiceTag{Name: str(v.Name), Service: str(v.Properties.SystemService), Region: str(v.Properties.Region)}
		for _, p := range v.Properties.AddressPrefixes {
			if p == nil {
				continue
			}
			if pfx, err := netip.ParsePrefix(strings.TrimSpace(*p)); err == nil {
				t.Prefixes = append(t.Prefixes, pfx.Masked())
			}
		}
		if len(t.Prefixes) > 0 {
			out = append(out, t)
		}
	}
	return out, nil
}
