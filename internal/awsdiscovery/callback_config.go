package awsdiscovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// CallbackConfig is the deployment's automatic-onboarding setup: where the
// template is published, which regional SNS topic each supported deployment
// region reports back through, the central queue those topics feed, and which
// opt-in regions this deployment can scan.
//
// Why a topic per region: a custom resource's ServiceToken must be in the same
// region as the stack. One global topic would work for stacks in exactly one
// region. The IAM role itself is global, so only the region the stack is
// deployed in needs a topic; the regions a connector scans need none.
type CallbackConfig struct {
	// Topics maps a deployment region to AuthSec's SNS topic in that region.
	Topics map[string]string
	// QueueURL is the central SQS queue every regional topic delivers to.
	QueueURL string
	// TemplateBaseURL is where versioned templates are published, for example
	// https://bucket.s3.us-east-1.amazonaws.com. See TemplateURLFor.
	TemplateBaseURL string
	// TemplateURLOverrides, when set for a region, replaces the base URL for
	// stacks in that region. Exists for the case where the Quick Create console
	// turns out to need a template bucket in the stack's own region.
	TemplateURLOverrides map[string]string
	// OptInScanRegions are the opt-in regions AuthSec's OWN account has
	// enabled. Scanning a region assumes the customer role through that region's
	// STS endpoint with AuthSec's credentials, so an opt-in region disabled on
	// AuthSec's side fails every time regardless of the customer.
	OptInScanRegions map[string]struct{}
}

// ErrCallbackConfig means the automatic-onboarding configuration is invalid.
var ErrCallbackConfig = errors.New("invalid AWS automatic onboarding configuration")

// ParseCallbackConfig validates the raw deployment settings. Empty input is a
// valid, disabled configuration; anything present must be right, because a
// wrong topic ARN or template URL is discovered only by a customer whose stack
// fails.
func ParseCallbackConfig(topicsJSON, queueURL, templateBaseURL, overridesJSON, optInCSV string) (CallbackConfig, error) {
	cfg := CallbackConfig{
		Topics:               map[string]string{},
		TemplateURLOverrides: map[string]string{},
		OptInScanRegions:     map[string]struct{}{},
		QueueURL:             strings.TrimSpace(queueURL),
		TemplateBaseURL:      strings.TrimRight(strings.TrimSpace(templateBaseURL), "/"),
	}

	if s := strings.TrimSpace(topicsJSON); s != "" {
		if err := json.Unmarshal([]byte(s), &cfg.Topics); err != nil {
			return CallbackConfig{}, fmt.Errorf("%w: topics are not a JSON object of region to ARN: %v", ErrCallbackConfig, err)
		}
	}
	for region, arn := range cfg.Topics {
		if err := ValidateRegion(region); err != nil {
			return CallbackConfig{}, fmt.Errorf("%w: %v", ErrCallbackConfig, err)
		}
		if PartitionForRegion(region) != PartitionAWS {
			return CallbackConfig{}, fmt.Errorf("%w: %s is not a commercial region", ErrCallbackConfig, region)
		}
		if IsOptInRegion(region) {
			// An opt-in topic region needs a regionalised SNS principal in the
			// queue policy and the region enabled on AuthSec's side. Not in
			// phase one.
			return CallbackConfig{}, fmt.Errorf("%w: %s is an opt-in region and cannot host a callback topic",
				ErrCallbackConfig, region)
		}
		partition, topicRegion, err := ParseTopicARN(arn)
		if err != nil {
			return CallbackConfig{}, fmt.Errorf("%w: %v", ErrCallbackConfig, err)
		}
		if partition != PartitionAWS || topicRegion != region {
			return CallbackConfig{}, fmt.Errorf("%w: topic %s is not in %s", ErrCallbackConfig, arn, region)
		}
	}

	if s := strings.TrimSpace(overridesJSON); s != "" {
		if err := json.Unmarshal([]byte(s), &cfg.TemplateURLOverrides); err != nil {
			return CallbackConfig{}, fmt.Errorf("%w: template overrides are not a JSON object: %v", ErrCallbackConfig, err)
		}
	}
	for region, u := range cfg.TemplateURLOverrides {
		if err := validateTemplateURL(u); err != nil {
			return CallbackConfig{}, fmt.Errorf("%w: override for %s: %v", ErrCallbackConfig, region, err)
		}
	}
	if cfg.TemplateBaseURL != "" {
		if err := validateTemplateURL(cfg.TemplateBaseURL); err != nil {
			return CallbackConfig{}, fmt.Errorf("%w: template base URL: %v", ErrCallbackConfig, err)
		}
	}

	if cfg.QueueURL != "" {
		if _, err := QueueRegion(cfg.QueueURL); err != nil {
			return CallbackConfig{}, fmt.Errorf("%w: %v", ErrCallbackConfig, err)
		}
	}

	for _, r := range strings.Split(optInCSV, ",") {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "" {
			continue
		}
		if !IsOptInRegion(r) {
			return CallbackConfig{}, fmt.Errorf("%w: %s is not an opt-in region", ErrCallbackConfig, r)
		}
		cfg.OptInScanRegions[r] = struct{}{}
	}
	return cfg, nil
}

// validateTemplateURL requires an https S3 URL: Quick Create accepts nothing
// else as templateURL.
func validateTemplateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q is not an https URL", raw)
	}
	host := strings.ToLower(u.Hostname())
	if !strings.HasSuffix(host, ".amazonaws.com") || !strings.Contains(host, "s3") {
		return fmt.Errorf("%q is not an S3 URL; Quick Create only accepts templates stored in S3", raw)
	}
	return nil
}

// QueueRegion extracts the region from an SQS queue URL
// (https://sqs.{region}.amazonaws.com/{account}/{name}).
func QueueRegion(queueURL string) (string, error) {
	u, err := url.Parse(queueURL)
	if err != nil || u.Scheme != "https" {
		return "", fmt.Errorf("%q is not an https SQS queue URL", queueURL)
	}
	parts := strings.Split(u.Hostname(), ".")
	if len(parts) != 4 || parts[0] != "sqs" || parts[2] != "amazonaws" || parts[3] != "com" {
		return "", fmt.Errorf("%q is not an SQS queue URL of the form https://sqs.<region>.amazonaws.com/…", queueURL)
	}
	if err := ValidateRegion(parts[1]); err != nil {
		return "", err
	}
	return parts[1], nil
}

// Enabled reports whether automatic onboarding can be offered at all.
func (c CallbackConfig) Enabled() bool {
	return len(c.Topics) > 0 && c.QueueURL != "" && c.TemplateBaseURL != ""
}

// SupportedDeploymentRegions lists the regions a stack may be created in,
// sorted.
func (c CallbackConfig) SupportedDeploymentRegions() []string {
	out := make([]string, 0, len(c.Topics))
	for r := range c.Topics {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// TopicFor returns the callback topic for a deployment region.
func (c CallbackConfig) TopicFor(region string) (string, bool) {
	t, ok := c.Topics[region]
	return t, ok
}

// IsOurTopic reports whether an SNS topic ARN is one of this deployment's
// callback topics. Exact match: a message that arrived through any other
// topic did not come from a stack AuthSec launched.
func (c CallbackConfig) IsOurTopic(arn string) bool {
	for _, t := range c.Topics {
		if t == arn {
			return true
		}
	}
	return false
}

// TemplateURLFor returns the published template URL for stacks in region.
// The key is versioned and immutable, so a stack created from an older link
// keeps resolving to exactly the template it was created from.
func (c CallbackConfig) TemplateURLFor(region string) string {
	if u, ok := c.TemplateURLOverrides[region]; ok {
		return u
	}
	return c.TemplateBaseURL + "/aws/" + TemplateVersion + "/authsec-aws-discovery-role.yaml"
}

// ScanRegionSupported reports whether a commercial region may be scanned by
// this deployment: every default-enabled region, and the opt-in regions this
// deployment has enabled on its own side.
func (c CallbackConfig) ScanRegionSupported(region string) bool {
	if !IsOptInRegion(region) {
		return true
	}
	_, ok := c.OptInScanRegions[region]
	return ok
}

// OptInScanRegionList returns OptInScanRegions sorted, for the console.
func (c CallbackConfig) OptInScanRegionList() []string {
	out := make([]string, 0, len(c.OptInScanRegions))
	for r := range c.OptInScanRegions {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
