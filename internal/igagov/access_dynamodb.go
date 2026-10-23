package igagov

import (
	"regexp"
	"strings"
)

// DynamoDB tables in access policies. A block is a Deny on the table and
// everything under it (indexes, streams, backups, exports); an allow grants
// item access only, on the table and its indexes. The action table was
// checked against the AWS Service Authorization Reference for DynamoDB
// (list_dynamodb.html, 2026-10-23); see the notes for what IAM cannot stop.
//
// Unverified against a live account, so chosen to fail safe:
//   - whether a PartiQL statement with RETURNING sets dynamodb:ReturnValues:
//     a read block denies every PartiQL write outright, and an allow without
//     read grants none;
//   - ReturnValuesOnConditionCheckFailure has no condition key at all: a
//     write whose condition fails returns the stored item, so write access
//     can read (a preview note says so; nothing in IAM can close it).

// DynamoDB access-policy names.
const (
	AccessTypeDynamoDBTable   = "dynamodb_table"
	AccessSidTable            = "AuthSecAccessTable"
	AccessSidReturnValues     = "AuthSecAccessReturnValues"
	AccessSidReplica          = "AuthSecAccessReplica"
	AccessSidRead             = "AuthSecAccessRead"
	AccessSidItems            = "AuthSecAccessItems"
	KeyDynamoReturnValues     = "dynamodb:ReturnValues"
	CondStringEquals          = "StringEquals"
	CondStringEqualsIfExists  = "StringEqualsIfExists"
	dynamoAll                 = "dynamodb:*"
	dynamoCreateTableReplica  = "dynamodb:CreateTableReplica"
	dynamoBatchWriteItem      = "dynamodb:BatchWriteItem"
	dynamoDescribeTable       = "dynamodb:DescribeTable"
	dynamoReturnValuesNoneVal = "NONE"
)

// The item actions per access level (block and allow).
var (
	dynamoRead   = []string{"dynamodb:BatchGetItem", "dynamodb:ConditionCheckItem", "dynamodb:GetItem", "dynamodb:PartiQLSelect", "dynamodb:Query", "dynamodb:Scan", "dynamodb:SearchVectors"}
	dynamoWrite  = []string{"dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate"}
	dynamoDelete = []string{"dynamodb:DeleteItem", "dynamodb:PartiQLDelete"}
	// dynamoPartiQLWrites are refused by a read block and never granted by
	// an allow without read: they may return the stored item.
	dynamoPartiQLWrites = []string{"dynamodb:PartiQLDelete", "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate"}
	// dynamoReadCopies are the other ways a block of read must close: the
	// stream, an export to S3, a restore or AWS Backup copy into a table the
	// role reads, Kinesis streaming, a cross-account replica.
	dynamoReadCopies = []string{"dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator",
		"dynamodb:ExportTableToPointInTime", "dynamodb:RestoreTableToPointInTime", "dynamodb:RestoreTableFromBackup",
		"dynamodb:StartAwsBackupJob", "dynamodb:EnableKinesisStreamingDestination", "dynamodb:UpdateKinesisStreamingDestination",
		"dynamodb:AssociateTableReplica"}
	// dynamoReturningWrites are the writes a read block denies only when they
	// ask for the stored item back (AuthSecAccessReturnValues).
	dynamoReturningWrites  = []string{"dynamodb:DeleteItem", "dynamodb:PutItem", "dynamodb:UpdateItem"}
	dynamoReturnValuesSome = []string{"ALL_NEW", "ALL_OLD", "UPDATED_NEW", "UPDATED_OLD"}
)

// DynamoTableTarget is one DynamoDB table.
type DynamoTableTarget struct {
	Partition string
	Region    string
	Account   string
	Table     string
}

// A table ARN, or any ARN under one (index, stream, backup, export): the
// name must be literal. A global-table ARN names no region and is refused.
var reDynamoTableARN = regexp.MustCompile(`^arn:(aws[a-z-]*):dynamodb:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):table/([A-Za-z0-9_.-]{3,255})(?:/.*)?$`)

// ParseDynamoDBTableARN reads the table an ARN names (or lies under).
func ParseDynamoDBTableARN(arn string) (DynamoTableTarget, bool) {
	m := reDynamoTableARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return DynamoTableTarget{}, false
	}
	return DynamoTableTarget{Partition: m[1], Region: m[2], Account: m[3], Table: m[4]}, true
}

// TableARN is arn:<p>:dynamodb:<region>:<account>:table/<name>.
func (t DynamoTableTarget) TableARN() string {
	return "arn:" + t.Partition + ":dynamodb:" + t.Region + ":" + t.Account + ":table/" + t.Table
}

// SubARN is everything under the table (indexes, streams, backups, exports).
func (t DynamoTableTarget) SubARN() string { return t.TableARN() + "/*" }

// IndexARN is the table's indexes.
func (t DynamoTableTarget) IndexARN() string { return t.TableARN() + "/index/*" }

// ReplicaARN is the table of this name in any region of the account:
// CreateTableReplica is checked on the new replica's ARN, not on the table.
func (t DynamoTableTarget) ReplicaARN() string {
	return "arn:" + t.Partition + ":dynamodb:*:" + t.Account + ":table/" + t.Table
}

// DynamoTableTarget is an AWSAccessTarget.
func (t DynamoTableTarget) Type() string         { return AccessTypeDynamoDBTable }
func (t DynamoTableTarget) Service() string      { return "dynamodb" }
func (t DynamoTableTarget) Noun() string         { return "table" }
func (t DynamoTableTarget) ARN() string          { return t.TableARN() }
func (t DynamoTableTarget) Name() string         { return t.Table }
func (t DynamoTableTarget) ARNAccount() string   { return t.Account }
func (t DynamoTableTarget) ARNRegion() string    { return t.Region }
func (t DynamoTableTarget) ARNPartition() string { return t.Partition }
func (t DynamoTableTarget) Where() string {
	return "DynamoDB table " + t.Table + " (" + t.Region + ", account " + t.Account + ")"
}

// dynamoBatchWrite: AWS checks batch puts and batch deletes as one action. A
// block of write or of delete refuses it; an allow grants it only with both.
func dynamoBatchWrite(effect string, access []string) bool {
	if effect == AccessEffectBlock {
		return accessHas(access, AccessWrite, AccessDelete)
	}
	return accessHas(access, AccessWrite) && accessHas(access, AccessDelete)
}

// Statements is the table's document (see the file comment).
func (t DynamoTableTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	read, write, del := accessHas(access, AccessRead), accessHas(access, AccessWrite), accessHas(access, AccessDelete)
	if effect == AccessEffectBlock {
		if accessHas(access, AccessAll) {
			return []AccessStatement{
				{Sid: AccessSidTable, Actions: []string{dynamoAll}, Resources: []string{t.TableARN(), t.SubARN()}},
				{Sid: AccessSidReplica, Actions: []string{dynamoCreateTableReplica}, Resources: []string{t.ReplicaARN()}},
			}, nil
		}
		var acts []string
		if read {
			acts = append(acts, dynamoRead...)
			acts = append(acts, dynamoReadCopies...)
			acts = append(acts, dynamoPartiQLWrites...)
		}
		if write {
			acts = append(acts, dynamoWrite...)
			acts = append(acts, "dynamodb:AssociateTableReplica")
		}
		if del {
			acts = append(acts, dynamoDelete...)
			acts = append(acts, "dynamodb:DeleteTable", "dynamodb:UpdateTimeToLive")
		}
		if dynamoBatchWrite(effect, access) {
			acts = append(acts, dynamoBatchWriteItem)
		}
		acts = sortedUnique(acts)
		stmts := []AccessStatement{{Sid: AccessSidTable, Actions: acts, Resources: []string{t.TableARN(), t.SubARN()}}}
		if read {
			denied := map[string]bool{}
			for _, a := range acts {
				denied[a] = true
			}
			var rv []string
			for _, a := range dynamoReturningWrites {
				if !denied[a] {
					rv = append(rv, a)
				}
			}
			if len(rv) > 0 {
				stmts = append(stmts, AccessStatement{Sid: AccessSidReturnValues, Actions: rv, Resources: []string{t.TableARN()},
					Cond: map[string]any{CondStringEquals: map[string]any{KeyDynamoReturnValues: dynamoReturnValuesSome}}})
			}
		}
		if read || write {
			stmts = append(stmts, AccessStatement{Sid: AccessSidReplica, Actions: []string{dynamoCreateTableReplica}, Resources: []string{t.ReplicaARN()}})
		}
		return stmts, nil
	}

	var stmts []AccessStatement
	if read {
		acts := append(append([]string{}, dynamoRead...), dynamoDescribeTable)
		stmts = append(stmts, AccessStatement{Sid: AccessSidRead, Actions: acts, Resources: []string{t.TableARN(), t.IndexARN()}})
	}
	var items []string
	if write {
		items = append(items, dynamoWrite...)
	}
	if del {
		items = append(items, dynamoDelete...)
	}
	if dynamoBatchWrite(effect, access) {
		items = append(items, dynamoBatchWriteItem)
	}
	if len(items) > 0 {
		var cond map[string]any
		if !read {
			partiql := map[string]bool{}
			for _, a := range dynamoPartiQLWrites {
				partiql[a] = true
			}
			kept := items[:0:0]
			for _, a := range items {
				if !partiql[a] {
					kept = append(kept, a)
				}
			}
			items = kept
			cond = map[string]any{CondStringEqualsIfExists: map[string]any{KeyDynamoReturnValues: dynamoReturnValuesNoneVal}}
		}
		stmts = append(stmts, AccessStatement{Sid: AccessSidItems, Actions: items, Resources: []string{t.TableARN()}, Cond: cond})
	}
	if len(stmts) == 0 {
		return nil, nil
	}
	return stmts, nil
}

// Notes is the preview's warnings for a table, in a fixed order.
func (t DynamoTableTarget) Notes(effect string, access []string) []AccessNote {
	all := accessHas(access, AccessAll)
	read, write, del := accessHas(access, AccessRead), accessHas(access, AccessWrite), accessHas(access, AccessDelete)
	var out []AccessNote
	add := func(code, msg string) { out = append(out, AccessNote{Code: code, Message: msg}) }
	if effect == AccessEffectBlock {
		if read && !all {
			if !(write && del) {
				add("return_values_blocked", "Writes that ask for the stored item back are refused too.")
				add("partiql_writes_blocked", "PartiQL statements that insert, update or delete items are refused too: they can return the stored item.")
			}
		}
		if !all && write != del {
			add("batch_write_shared", "Batch writes are refused too: AWS checks batch puts and batch deletes as one permission (BatchWriteItem).")
		}
		if del && !all {
			add("delete_table_blocked", "Deleting the table and changing its time to live are refused too: both remove items.")
		}
		if del && !write && !all {
			add("overwrite_not_covered", "Put and update can still replace or clear an item's contents.")
		}
		if read && !all && !(write && del) {
			add("condition_failure_values_not_covered", "A write whose condition check fails returns the stored item; AWS has no permission or condition that stops this, so these roles' write access can still read items.")
		}
		if read || all {
			add("copies_not_covered", "Copies outside this table are not covered: global-table replicas in other regions, DAX clusters, AWS Backup recovery points, exports already written, and stream or Kinesis consumers already set up.")
		}
		if (write || del) && !read && !all {
			add("replicas_not_covered", "Global-table replicas in other regions are separate tables; a write there reaches this table and is not covered.")
		}
		return out
	}
	add("allow_items_only", "Only item access (and DescribeTable when read is chosen) is allowed: table settings, streams, backups and exports are not.")
	if write != del {
		add("batch_write_needs_both", "Batch writes are allowed only when write and delete are both chosen.")
	}
	if (write || del) && !read {
		add("return_values_limited", "Writes cannot ask for the stored item back, and PartiQL statements are not allowed, because read was not chosen. A write whose condition check fails can still return the item.")
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t DynamoTableTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users, groups and the table's resource policy are unchanged."
}
