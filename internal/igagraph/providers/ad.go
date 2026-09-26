package providers

import (
	"encoding/json"
	"strings"

	igraph "github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

type adObject struct {
	AccountKind       string   `json:"account_kind"`
	LDAPClass         string   `json:"ldap_class"`
	ObjectGUID        string   `json:"object_guid"`
	ObjectSID         string   `json:"object_sid"`
	DistinguishedName string   `json:"distinguished_name"`
	SAMAccountName    string   `json:"sam_account_name"`
	DisplayName       string   `json:"display_name"`
	Member            []string `json:"member"`
	ForestID          string   `json:"forest_id"`
	AccountFlags      struct {
		AccountDisabled bool `json:"account_disabled"`
	} `json:"account_flags"`
}

func normalizeAD(in Input) (*Plan, error) {
	p := &Plan{}
	type row struct {
		obj adObject
		key string
	}
	var rows []row
	for _, o := range in.Objects {
		obj, err := decodeAD(o)
		if err != nil {
			return nil, err
		}
		if obj.ObjectGUID == "" {
			continue
		}
		forest := obj.ForestID
		if forest == "" {
			var ferr error
			forest, ferr = forestFromRecognition(o.Recognition, obj.ObjectGUID)
			if ferr != nil {
				return nil, ferr
			}
		}
		key, err := igraph.ADIdentityKey(forest, obj.ObjectGUID)
		if err != nil {
			return nil, err
		}
		kind := obj.AccountKind
		if kind == "" {
			kind = kindFromClass(obj.LDAPClass, o.Kind)
		}
		if kind == "" {
			continue
		}
		state := models.AccountStateEnabled
		if obj.AccountFlags.AccountDisabled {
			state = models.AccountStateDisabled
		}
		name := obj.DisplayName
		if name == "" {
			name = obj.SAMAccountName
		}
		attrs := map[string]any{
			"object_sid": obj.ObjectSID, "distinguished_name": obj.DistinguishedName,
			"sam_account_name": obj.SAMAccountName,
		}
		p.Identities = append(p.Identities, Identity{
			SourceKey: key, ImmutableKey: strings.ToLower(obj.ObjectGUID),
			Continuity: models.ContinuityImmutable, Provider: models.ProviderAD,
			Kind: kind, Name: name, State: state, Backing: "ad",
			Attrs: mustJSON(attrs), DN: obj.DistinguishedName,
		})
		rows = append(rows, row{obj: obj, key: key})
	}
	byDN := map[string]string{}
	for _, id := range p.Identities {
		if id.DN != "" {
			byDN[strings.ToLower(id.DN)] = id.SourceKey
		}
	}
	for _, row := range rows {
		for _, member := range row.obj.Member {
			src, ok := byDN[strings.ToLower(member)]
			if !ok {
				p.Unresolved = append(p.Unresolved, "ad-member:"+member)
				continue
			}
			rkey, err := relationKey("ad", "member_of", src, row.key)
			if err != nil {
				return nil, err
			}
			p.Relationships = append(p.Relationships, Relationship{
				SourceKey: rkey, Type: models.RelTypeMemberOf, Basis: models.BasisDeclared,
				FromIdentity: src, ToIdentity: row.key,
			})
		}
	}
	return p, nil
}

func decodeAD(o Object) (adObject, error) {
	var obj adObject
	raw := o.Raw
	if len(raw) == 0 {
		raw = mustJSON(o.Native)
	}
	if len(raw) == 0 {
		return obj, nil
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return obj, err
	}
	return obj, nil
}

func forestFromRecognition(key, guid string) (string, error) {
	parts := strings.Split(key, igraph.Sep)
	if len(parts) != 3 || parts[0] != "ad" {
		return "", errADKey
	}
	forest, err := igraph.UnescapeSegment(parts[1])
	if err != nil {
		return "", err
	}
	got, err := igraph.ADIdentityKey(forest, guid)
	if err != nil {
		return "", err
	}
	if got != key {
		return "", errADKey
	}
	return forest, nil
}

var errADKey = adKeyError{}

type adKeyError struct{}

func (adKeyError) Error() string { return "ad identity key does not match the objectGUID" }

func kindFromClass(class, objectType string) string {
	c := strings.ToLower(class)
	if c == "" {
		c = strings.ToLower(objectType)
	}
	switch c {
	case "user", "ad_user":
		return models.AccountKindADUser
	case "group", "ad_group":
		return models.AccountKindADGroup
	case "computer", "ad_computer":
		return models.AccountKindADComputer
	case "msds-managedserviceaccount", "msds-groupmanagedserviceaccount", "ad_managed_service_account":
		return models.AccountKindADManagedSA
	default:
		return ""
	}
}
