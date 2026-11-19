package gcp

import "strings"

/* assettypes.go maps a Cloud Asset assetType (what searchAllIamPolicies returns
   beside every policy) to the kind a cloud_resource row is stored under.

   Org, folder and project policies create no cloud_resource row: a grant at one
   of those levels is account_wide and names no resource. They are classified
   here only so the binding can say where it is attached (organization, folder,
   project, or resource). */

// Resource kinds GCP discovery stores. Text in the schema, so a new Google
// service needs a line in the map below, never a migration.
const (
	KindGCSBucket       = "gcs_bucket"
	KindBQDataset       = "bq_dataset"
	KindBQTable         = "bq_table"
	KindSecret          = "secret"
	KindKMSKey          = "kms_key"
	KindKMSKeyRing      = "kms_keyring"
	KindPubSubTopic     = "pubsub_topic"
	KindPubSubSub       = "pubsub_subscription"
	KindRunService      = "run_service"
	KindCloudFunction   = "cloud_function"
	KindArtifactRepo    = "artifact_repo"
	KindSQLInstance     = "sql_instance"
	KindSpannerInstance = "spanner_instance"
	KindServiceAccount  = "service_account"
	KindProject         = "project"
	KindFolder          = "folder"
	KindOrganization    = "organization"
	KindUnknownGCPAsset = "gcp_resource"
)

var assetKinds = map[string]string{
	"storage.googleapis.com/Bucket":                    KindGCSBucket,
	"bigquery.googleapis.com/Dataset":                  KindBQDataset,
	"bigquery.googleapis.com/Table":                    KindBQTable,
	"secretmanager.googleapis.com/Secret":              KindSecret,
	"cloudkms.googleapis.com/CryptoKey":                KindKMSKey,
	"cloudkms.googleapis.com/KeyRing":                  KindKMSKeyRing,
	"pubsub.googleapis.com/Topic":                      KindPubSubTopic,
	"pubsub.googleapis.com/Subscription":               KindPubSubSub,
	"run.googleapis.com/Service":                       KindRunService,
	"cloudfunctions.googleapis.com/CloudFunction":      KindCloudFunction,
	"cloudfunctions.googleapis.com/Function":           KindCloudFunction,
	"artifactregistry.googleapis.com/Repository":       KindArtifactRepo,
	"sqladmin.googleapis.com/Instance":                 KindSQLInstance,
	"spanner.googleapis.com/Instance":                  KindSpannerInstance,
	"iam.googleapis.com/ServiceAccount":                KindServiceAccount,
	"cloudresourcemanager.googleapis.com/Project":      KindProject,
	"cloudresourcemanager.googleapis.com/Folder":       KindFolder,
	"cloudresourcemanager.googleapis.com/Organization": KindOrganization,
}

// AssetKind returns the stored kind for an asset type. An asset type the map does
// not know is stored under KindUnknownGCPAsset: a grant on a service we have not
// mapped is still a grant, and dropping it would read as no access.
func AssetKind(assetType string) string {
	if k, ok := assetKinds[assetType]; ok {
		return k
	}
	return KindUnknownGCPAsset
}

// IsScopeKind reports whether kind is one of the three hierarchy levels, whose
// policies are account_wide and create no cloud_resource row.
func IsScopeKind(kind string) bool {
	return kind == KindProject || kind == KindFolder || kind == KindOrganization
}

// ResourceSensitivity is the starting heuristic for a resource by kind, the GCP
// analogue of the AWS service-keyed rule: secrets and keys are high, data stores
// medium, the rest low. A reviewer may raise it; a re-scan never lowers it.
func ResourceSensitivity(kind string) string {
	switch kind {
	case KindSecret, KindKMSKey, KindKMSKeyRing:
		return "high"
	case KindGCSBucket, KindBQDataset, KindBQTable, KindSQLInstance, KindSpannerInstance, KindServiceAccount:
		return "med"
	default:
		return "low"
	}
}

// ResourceDisplayName is the last path segment of a full Cloud Asset name.
func ResourceDisplayName(fullName string) string {
	if i := strings.LastIndex(fullName, "/"); i >= 0 && i < len(fullName)-1 {
		return fullName[i+1:]
	}
	return fullName
}
