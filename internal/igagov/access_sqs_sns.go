package igagov

import (
	"regexp"
	"strings"
)

// SQS queues and SNS topics in access policies (step 8). A block covers
// receiving, sending and deleting, and every way to hand them to someone
// else (the resource policy, a message move, tags). An allow on a queue
// grants the plain message actions of each level; an allow on a topic
// covers publishing only (a subscription can carry its messages anywhere).
// Action tables were checked against the AWS service reference for sqs and
// sns (servicereference.us-east-1.amazonaws.com, 2026-10-24).

// SQS and SNS access-policy names.
const (
	AccessTypeSQSQueue = "sqs_queue"
	AccessTypeSNSTopic = "sns_topic"
	AccessSidQueue     = "AuthSecAccessQueue"
	AccessSidTopic     = "AuthSecAccessTopic"
)

var (
	sqsRead = []string{"sqs:ReceiveMessage", "sqs:ChangeMessageVisibility", "sqs:StartMessageMoveTask", "sqs:AddPermission", "sqs:SetQueueAttributes",
		"sqs:TagQueue", "sqs:UntagQueue"}
	sqsWrite = []string{"sqs:SendMessage", "sqs:ChangeMessageVisibility", "sqs:SetQueueAttributes", "sqs:AddPermission", "sqs:RemovePermission",
		"sqs:StartMessageMoveTask", "sqs:CancelMessageMoveTask", "sqs:TagQueue", "sqs:UntagQueue"}
	sqsDelete = []string{"sqs:DeleteMessage", "sqs:PurgeQueue", "sqs:DeleteQueue"}
	// What an allow grants per level.
	sqsAllowRead   = []string{"sqs:ReceiveMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"}
	sqsAllowWrite  = []string{"sqs:SendMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"}
	sqsAllowDelete = []string{"sqs:DeleteMessage", "sqs:GetQueueUrl"}

	snsRead = []string{"sns:Subscribe", "sns:ConfirmSubscription", "sns:AddPermission", "sns:SetTopicAttributes", "sns:SetSubscriptionAttributes",
		"sns:TagResource", "sns:UntagResource"}
	snsWrite = []string{"sns:Publish", "sns:SetTopicAttributes", "sns:SetSubscriptionAttributes", "sns:PutDataProtectionPolicy", "sns:AddPermission",
		"sns:RemovePermission", "sns:TagResource", "sns:UntagResource"}
	snsDelete     = []string{"sns:DeleteTopic", "sns:Unsubscribe"}
	snsAllowWrite = []string{"sns:Publish", "sns:GetTopicAttributes"}
)

var (
	reSQSARN = regexp.MustCompile(`^arn:(aws[a-z-]*):sqs:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):([A-Za-z0-9_-]{1,75}(?:\.fifo)?)$`)
	reSNSARN = regexp.MustCompile(`^arn:(aws[a-z-]*):sns:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):([A-Za-z0-9_-]{1,251}(?:\.fifo)?)$`)
)

// MessagingTarget is one SQS queue or SNS topic.
type MessagingTarget struct {
	Kind, Partition, Region, Account, Resource string
}

// ParseSQSQueueARN reads a queue ARN.
func ParseSQSQueueARN(arn string) (MessagingTarget, bool) {
	m := reSQSARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return MessagingTarget{}, false
	}
	return MessagingTarget{Kind: AccessTypeSQSQueue, Partition: m[1], Region: m[2], Account: m[3], Resource: m[4]}, true
}

// ParseSNSTopicARN reads a topic ARN (a subscription ARN names more).
func ParseSNSTopicARN(arn string) (MessagingTarget, bool) {
	m := reSNSARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return MessagingTarget{}, false
	}
	return MessagingTarget{Kind: AccessTypeSNSTopic, Partition: m[1], Region: m[2], Account: m[3], Resource: m[4]}, true
}

func (t MessagingTarget) sqs() bool { return t.Kind == AccessTypeSQSQueue }

// MessagingTarget is an AWSAccessTarget.
func (t MessagingTarget) Type() string { return t.Kind }
func (t MessagingTarget) Service() string {
	if t.sqs() {
		return "sqs"
	}
	return "sns"
}
func (t MessagingTarget) Noun() string {
	if t.sqs() {
		return "queue"
	}
	return "topic"
}
func (t MessagingTarget) ARN() string {
	return "arn:" + t.Partition + ":" + t.Service() + ":" + t.Region + ":" + t.Account + ":" + t.Resource
}
func (t MessagingTarget) Name() string         { return t.Resource }
func (t MessagingTarget) ARNAccount() string   { return t.Account }
func (t MessagingTarget) ARNRegion() string    { return t.Region }
func (t MessagingTarget) ARNPartition() string { return t.Partition }
func (t MessagingTarget) Where() string {
	what := "SQS queue "
	if !t.sqs() {
		what = "SNS topic "
	}
	return what + t.Resource + " (" + t.Region + ", account " + t.Account + ")"
}

// Statements is the queue's or topic's document.
func (t MessagingTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	sid := AccessSidQueue
	if !t.sqs() {
		sid = AccessSidTopic
	}
	var acts []string
	switch {
	case effect == AccessEffectAllow && t.sqs():
		if accessHas(access, AccessAll) {
			return nil, &AccessFieldError{Field: "access", Message: "Choose read, write or delete for an allow."}
		}
		for l, a := range map[string][]string{AccessRead: sqsAllowRead, AccessWrite: sqsAllowWrite, AccessDelete: sqsAllowDelete} {
			if accessHas(access, l) {
				acts = append(acts, a...)
			}
		}
	case effect == AccessEffectAllow:
		if accessHas(access, AccessRead, AccessDelete, AccessAll) {
			return nil, &AccessFieldError{Field: "access", Message: "An allow on a topic covers publishing (write) only: a subscription can carry its messages anywhere."}
		}
		acts = snsAllowWrite
	case t.sqs():
		acts = levelActions(access, "sqs:*", sqsRead, sqsWrite, sqsDelete)
	default:
		acts = levelActions(access, "sns:*", snsRead, snsWrite, snsDelete)
	}
	if len(acts) == 0 {
		return nil, nil
	}
	return []AccessStatement{{Sid: sid, Actions: sortedUnique(acts), Resources: []string{t.ARN()}}}, nil
}

// Notes is the preview's warnings for a queue or topic.
func (t MessagingTarget) Notes(effect string, access []string) []AccessNote {
	var out []AccessNote
	add := func(code, msg string) { out = append(out, AccessNote{Code: code, Message: msg}) }
	if effect == AccessEffectBlock && accessHas(access, AccessRead, AccessAll) {
		add("handoff_blocked", "Changing the "+t.Noun()+"'s policy and attributes and tagging it are refused too: each can hand its messages to someone else.")
		if !t.sqs() {
			add("subscriptions_not_covered", "Subscriptions that already exist keep receiving messages: the block stops new ones.")
		}
	}
	if effect == AccessEffectAllow {
		add("kms_not_granted", "If the "+t.Noun()+" is encrypted with a customer managed KMS key, the role also needs that key, which this allow does not grant.")
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t MessagingTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users, groups and the " + t.Noun() + "'s policy are unchanged."
}
