package awsdiscovery

// The permission baseline, in a form the console and a customer's security
// reviewer can both read.
//
// This list and the inline policy in authsec-aws-discovery-role.yaml describe
// the same grant and MUST move together. They are in the same package and
// should be edited in the same change; a mismatch shows up as a scan surface
// reporting AccessDenied against a stack the console said was sufficient.

// BaselineManagedPolicy is the AWS-managed read-only policy the role carries.
// It grants metadata reads across the account and does not grant reading secret
// values, SSM parameter values or decryption keys.
//
// The partition is a placeholder: the template substitutes ${AWS::Partition} so
// the stack also works in GovCloud and China.
const BaselineManagedPolicy = "arn:${AWS::Partition}:iam::aws:policy/SecurityAudit"

// Permission is one additional read granted beyond the baseline.
type Permission struct {
	// Actions is the IAM action list for this group.
	Actions []string `json:"actions"`
	// Surface is the discovery surface it serves.
	Surface string `json:"surface"`
	// Why explains what AuthSec does with it, in a sentence a customer's
	// reviewer can evaluate without reading our code.
	Why string `json:"why"`
	// Redundant marks a grant that MAY already be covered by the baseline, and
	// so may be removable.
	//
	// It is about necessity, not validity. Every action in this file is a real
	// IAM action: cfn-lint's W3037 check validates the template's service
	// prefixes and action names against AWS's own IAM spec, and
	// TestTemplateAndPermissionListAgree keeps this list and the template in
	// step. Resolving redundancy is the part that needs the live SecurityAudit
	// document read from an account.
	//
	// Surfaced rather than hidden: an over-grant a customer cannot see is worse
	// than one they can question.
	Redundant bool `json:"possibly_redundant_with_baseline,omitempty"`
}

// AdditionalPermissions returns the reads granted on top of the baseline.
func AdditionalPermissions() []Permission {
	return []Permission{
		{
			Surface: "onboarding",
			Actions: []string{"sts:GetCallerIdentity"},
			Why: "Proves the cross-account role can be assumed and reports which " +
				"account it lands in. The only call made during onboarding.",
		},
		{
			Surface: "iam",
			Actions: []string{
				"iam:GetAccountAuthorizationDetails",
				"iam:GenerateCredentialReport",
				"iam:GetCredentialReport",
				"iam:GenerateServiceLastAccessedDetails",
				"iam:GetServiceLastAccessedDetails",
				"iam:ListOpenIDConnectProviders",
			},
			Why: "Reads every role, user, attached and inline policy in one " +
				"paginated call instead of thousands of per-identity calls, and " +
				"reads last-used data without paying for CloudTrail volume. The " +
				"Generate* calls produce read-only reports; they create no " +
				"resource and change no state. ListOpenIDConnectProviders lists " +
				"the account's OIDC providers as join targets for IRSA and the " +
				"EKS identity edge.",
			Redundant: true,
		},
		{
			Surface: "bedrock-agents",
			Actions: []string{"bedrock:ListAgents", "bedrock:GetAgent"},
			Why: "Discovers AWS-native managed agents and the execution role each " +
				"one runs as. Agent instructions and prompt text are never read.",
			Redundant: true,
		},
		{
			Surface: "bedrock-agentcore",
			Actions: []string{
				"bedrock-agentcore:ListAgentRuntimes",
				"bedrock-agentcore:GetAgentRuntime",
				"bedrock-agentcore:ListWorkloadIdentities",
				"bedrock-agentcore:ListOauth2CredentialProviders",
				"bedrock-agentcore:ListApiKeyCredentialProviders",
				"bedrock-agentcore:ListGateways",
				"bedrock-agentcore:ListGatewayTargets",
			},
			Why: "Discovers AgentCore runtimes, the workload identities they run " +
				"as, and what they can reach. List-only on credential providers: " +
				"names and ARNs, never a value.",
			Redundant: true,
		},
		{
			Surface: "eks",
			Actions: []string{
				"eks:ListClusters",
				"eks:DescribeCluster",
				"eks:ListPodIdentityAssociations",
				"eks:DescribePodIdentityAssociation",
			},
			Why: "Records which IAM role a Kubernetes service account may assume, " +
				"and the cluster OIDC issuer that tells two clusters apart. Pods " +
				"and workloads are not read here.",
			Redundant: true,
		},
		{
			Surface: "cloudtrail",
			Actions: []string{
				"cloudtrail:LookupEvents",
				"cloudtrail:DescribeTrails",
				"cloudtrail:GetTrailStatus",
			},
			Why: "Reads per-identity API history for liveness and agent " +
				"classification.",
		},
	}
}

// HardDenies are the actions the role is explicitly denied, whatever any Allow
// says. The baseline does not grant them today; the Deny is what keeps that
// true if the baseline widens or a later release adds a permission carelessly.
func HardDenies() []Permission {
	return []Permission{
		{
			Surface: "secret-values",
			Actions: []string{
				"secretsmanager:GetSecretValue",
				"secretsmanager:BatchGetSecretValue",
				"ssm:GetParameter", "ssm:GetParameters",
				"ssm:GetParametersByPath", "ssm:GetParameterHistory",
			},
			Why: "AuthSec records the existence, age and last use of a secret. It " +
				"never reads one.",
		},
		{
			Surface: "decryption",
			Actions: []string{
				"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey",
				"kms:GenerateDataKeyWithoutPlaintext",
				"kms:ReEncryptFrom", "kms:ReEncryptTo",
			},
			Why: "Nothing discovery reads is encrypted at the application layer, " +
				"so the ability to decrypt has no legitimate use here.",
		},
		{
			Surface: "role-chaining",
			Actions: []string{
				"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity",
				"sts:AssumeRoleWithSAML",
			},
			Why: "The discovery session is a leaf. It may be assumed by AuthSec, " +
				"but it may never assume anything further and pivot deeper into " +
				"the account.",
		},
	}
}
