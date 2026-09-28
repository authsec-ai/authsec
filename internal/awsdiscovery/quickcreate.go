package awsdiscovery

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Quick Create: the one-click alternative to downloading the template.
//
// A Quick Create link opens the CloudFormation console on the "Create stack"
// review page with the template and every parameter already filled in, so the
// customer only ticks the IAM acknowledgement and clicks Create. The format is
// AWS's documented one:
//
//	https://{region}.console.aws.amazon.com/cloudformation/home?region={region}
//	  #/stacks/create/review?templateURL=…&stackName=…&param_{Name}=…
//
// Two AWS behaviours shape this file:
//
//   - CloudFormation IGNORES a param_ value for any NoEcho parameter. A link
//     that tried to pre-fill one would silently leave it blank, so building a
//     link that names a NoEcho parameter is refused here, against the embedded
//     template, instead of being discovered by a customer.
//   - Users can overwrite every pre-filled value in the console. Nothing a
//     link sets is trusted later; the callback is verified on its own merits.

// Partitions AuthSec distinguishes. Only the commercial partition supports
// automatic onboarding; see PartitionForRegion.
const (
	PartitionAWS    = "aws"
	PartitionGovUS  = "aws-us-gov"
	PartitionChina  = "aws-cn"
	quickCreatePath = "/cloudformation/home"
)

// ErrQuickCreateUnsupported means a Quick Create link cannot be built for the
// request: a non-commercial partition, or a parameter the link must not carry.
var ErrQuickCreateUnsupported = errors.New("quick create link not supported for this request")

// stackNamePattern is CloudFormation's own rule for a stack name.
var stackNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,127}$`)

// PartitionForRegion returns the partition a region belongs to.
//
// GovCloud and China are separate partitions with their own consoles, IAM and
// STS: a commercial AuthSec principal cannot assume a role there, so callers
// use this to keep those regions out of the automatic flow.
func PartitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return PartitionGovUS
	case strings.HasPrefix(region, "cn-"):
		return PartitionChina
	default:
		return PartitionAWS
	}
}

// optInRegions are the commercial regions that must be enabled in an account
// before anything, STS included, works there. Taken from AWS's STS regions
// table ("You must enable the Region to use it"). Every other commercial
// region is enabled by default.
//
// A static list on purpose: this decides whether a region may host AuthSec's
// callback topic (never, in phase one) and whether it needs to be in the
// deployment's opt-in allow-list to be scanned. A region AWS launches later
// defaults to "not opt-in" here, which the allow-list check then catches the
// first time a scan of it fails, rather than silently.
var optInRegions = map[string]struct{}{
	"af-south-1":     {},
	"ap-east-1":      {},
	"ap-south-2":     {},
	"ap-southeast-3": {},
	"ap-southeast-4": {},
	"ap-southeast-5": {},
	"ap-southeast-7": {},
	"ca-west-1":      {},
	"eu-central-2":   {},
	"eu-south-1":     {},
	"eu-south-2":     {},
	"il-central-1":   {},
	"me-central-1":   {},
	"me-south-1":     {},
	"mx-central-1":   {},
}

// IsOptInRegion reports whether a commercial region is opt-in.
func IsOptInRegion(region string) bool {
	_, ok := optInRegions[region]
	return ok
}

// QuickCreateURL builds a Quick Create link for the embedded template.
//
// params are template parameter names without the param_ prefix. Every name
// must be declared by the embedded template, and none may be NoEcho: an
// undeclared name is almost certainly a typo that CloudFormation would ignore
// without a word, and a NoEcho one is ignored by design.
func QuickCreateURL(region, templateURL, stackName string, params map[string]string) (string, error) {
	if err := ValidateRegion(region); err != nil {
		return "", err
	}
	if p := PartitionForRegion(region); p != PartitionAWS {
		return "", fmt.Errorf("%w: region %s is in partition %s", ErrQuickCreateUnsupported, region, p)
	}
	if !strings.HasPrefix(templateURL, "https://") {
		return "", fmt.Errorf("%w: template URL must be https", ErrQuickCreateUnsupported)
	}
	if !stackNamePattern.MatchString(stackName) {
		return "", fmt.Errorf("%q is not a valid CloudFormation stack name", stackName)
	}

	declared, noEcho := templateParameters()
	q := url.Values{}
	q.Set("templateURL", templateURL)
	q.Set("stackName", stackName)
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := declared[name]; !ok {
			return "", fmt.Errorf("%w: the template declares no parameter %q", ErrQuickCreateUnsupported, name)
		}
		if _, ok := noEcho[name]; ok {
			return "", fmt.Errorf("%w: parameter %q is NoEcho, and Quick Create ignores NoEcho values",
				ErrQuickCreateUnsupported, name)
		}
		q.Set("param_"+name, params[name])
	}

	return fmt.Sprintf("https://%s.console.aws.amazon.com%s?region=%s#/stacks/create/review?%s",
		region, quickCreatePath, region, q.Encode()), nil
}

var (
	templateParamsOnce     sync.Once
	templateDeclaredParams map[string]struct{}
	templateNoEchoParams   map[string]struct{}
)

// templateParameters reads the parameter names, and which of them are NoEcho,
// out of the embedded template.
//
// A line scan rather than a YAML parse. The template uses CloudFormation's
// short-form tags (!Ref, !Sub, !GetAtt), which a plain YAML decoder rejects
// unless each tag is registered, and this only needs two facts from one
// top-level section of a file this package owns. The shape it relies on — a
// top-level `Parameters:` key, two-space parameter names, four-space
// properties — is asserted by the template test, so an edit that breaks it
// fails the build rather than this function.
func templateParameters() (declared, noEcho map[string]struct{}) {
	templateParamsOnce.Do(func() {
		templateDeclaredParams, templateNoEchoParams = scanTemplateParameters(CloudFormationTemplate)
	})
	return templateDeclaredParams, templateNoEchoParams
}

func scanTemplateParameters(template string) (declared, noEcho map[string]struct{}) {
	declared = map[string]struct{}{}
	noEcho = map[string]struct{}{}
	inParams := false
	current := ""
	sc := bufio.NewScanner(strings.NewReader(template))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			inParams = trimmed == "Parameters:"
			current = ""
		case !inParams:
			continue
		case indent == 2 && strings.HasSuffix(trimmed, ":"):
			current = strings.TrimSuffix(trimmed, ":")
			declared[current] = struct{}{}
		case indent == 4 && current != "":
			if key, val, ok := strings.Cut(trimmed, ":"); ok && key == "NoEcho" {
				if v := strings.Trim(strings.TrimSpace(val), `'"`); strings.EqualFold(v, "true") {
					noEcho[current] = struct{}{}
				}
			}
		}
	}
	return declared, noEcho
}
